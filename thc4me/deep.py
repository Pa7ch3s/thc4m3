#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from math import log2
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# rich is optional
try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table
except Exception:  # noqa: BLE001
    Console = None  # type: ignore[misc]

console = Console() if Console else None

SCHEMA_VERSION_DEFAULT = 1


# ---------- utils ----------
def cprint(msg: str, style: Optional[str] = None, end: str = "\n") -> None:
    if console:
        console.print(msg, style=style, end=end)
    else:
        print(msg, end=end)


def shlex_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def run(cmd: str, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(  # noqa: S603
            ["bash", "-lc", cmd],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(
            args=e.cmd, returncode=124, stdout=b"", stderr=f"timeout after {timeout}s".encode()
        )
    except Exception as e:  # noqa: BLE001
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=b"", stderr=str(e).encode())


# ---------- entropy ----------
def file_entropy(
    path: Path, timeout: Optional[float], sample_bytes: int = 8_000_000, chunk: int = 1_048_576
) -> Dict[str, Any]:
    start = time.time()
    freq = [0] * 256
    total = 0
    to_flag = False
    try:
        with path.open("rb") as f:
            remaining = sample_bytes
            while remaining > 0:
                if timeout and (time.time() - start) > timeout:
                    to_flag = True
                    break
                data = f.read(min(chunk, remaining))
                if not data:
                    break
                for b in data:
                    freq[b] += 1
                total += len(data)
                remaining -= len(data)
    except Exception as e:  # noqa: BLE001
        return {"value": None, "bytes_read": total, "sampled": False, "timeout": to_flag, "error": str(e)}
    if total == 0:
        return {"value": None, "bytes_read": 0, "sampled": False, "timeout": to_flag}
    H = 0.0
    for c in freq:
        if c:
            p = c / total
            H -= p * log2(p)
    try:
        sampled_flag = total < path.stat().st_size
    except Exception:  # noqa: BLE001
        sampled_flag = True
    return {"value": H, "bytes_read": total, "sampled": sampled_flag, "timeout": to_flag}


# ---------- DMG helpers ----------
def _parse_hdiutil_plist(plist_bytes: bytes) -> List[str]:
    try:
        obj = plistlib.loads(plist_bytes)
    except Exception:  # noqa: BLE001
        return []
    mounts: List[str] = []
    if isinstance(obj, dict):
        ents = obj.get("system-entities")
        if isinstance(ents, list):
            for ent in ents:
                if isinstance(ent, dict):
                    mp = ent.get("mount-point")
                    if isinstance(mp, str) and mp.startswith("/Volumes/"):
                        mounts.append(mp)
    return mounts


def attach_dmg(path: Path, mountpoint: Optional[Path], attach_timeout: Optional[int]) -> Tuple[bool, List[str], str]:
    mp_arg = f"-mountpoint {shlex_quote(str(mountpoint))}" if mountpoint else "-mountRandom /Volumes"
    cmd = f"printf 'Y\\n' | hdiutil attach -plist -readonly -nobrowse -noverify -noautoopen {mp_arg} {shlex_quote(str(path))}"
    p = run(cmd, timeout=attach_timeout)
    out_bytes = p.stdout or b""
    mounts = _parse_hdiutil_plist(out_bytes)
    ok = bool(mounts)
    out_txt = out_bytes.decode(errors="ignore") + (p.stderr.decode(errors="ignore") if p.stderr else "")
    return ok, mounts, out_txt.strip()


def detach_mounts(mounts: List[str], per_unmount_timeout: int = 10) -> None:
    for m in mounts:
        try:
            run(f"hdiutil detach {shlex_quote(m)} >/dev/null 2>&1", timeout=per_unmount_timeout)
        except Exception:  # noqa: BLE001
            pass


# ---------- codesign / spctl ----------
def codesign_info(path: Path, timeout: Optional[float]) -> Dict[str, Any]:
    p = run(f"codesign -dvvv {shlex_quote(str(path))} 2>&1 || true", timeout=timeout)
    out = (p.stdout or b"").decode(errors="ignore") + (p.stderr or b"").decode(errors="ignore")
    ok = ("Authority=" in out) or ("Signature=" in out) or ("signed" in out.lower())
    return {"ok": ok, "details": out.strip()}


def spctl_assess_file(path: Path, timeout: Optional[float]) -> Dict[str, Any]:
    p = run(f"spctl --assess --type execute -vv {shlex_quote(str(path))} 2>&1 || true", timeout=timeout)
    out = ((p.stdout or b"") + (p.stderr or b"")).decode(errors="ignore")
    return {"ok": "accepted" in out.lower(), "details": out.strip()}


def spctl_assess_pkg(path: Path, timeout: Optional[float]) -> Dict[str, Any]:
    p = run(f"spctl --assess --type install -vv {shlex_quote(str(path))} 2>&1 || true", timeout=timeout)
    out = ((p.stdout or b"") + (p.stderr or b"")).decode(errors="ignore")
    return {"ok": "accepted" in out.lower(), "details": out.strip()}


# ---------- .app scanning ----------
def read_info_plist(app_path: Path, timeout: Optional[float]) -> Tuple[Optional[Dict[str, Any]], str]:
    plist = app_path / "Contents" / "Info.plist"
    if not plist.exists():
        return None, ""
    p = run(f"plutil -convert json -o - {shlex_quote(str(plist))} 2>/dev/null || true", timeout=timeout)
    try:
        txt = (p.stdout or b"").decode(errors="ignore")
        if not txt.strip():
            return None, txt
        return json.loads(txt), txt
    except Exception:  # noqa: BLE001
        return None, (p.stdout or b"").decode(errors="ignore")


def _find_exec_from_info(app_path: Path, info: Optional[Dict[str, Any]]) -> Optional[Path]:
    try:
        if info and "CFBundleExecutable" in info:
            cand = app_path / "Contents" / "MacOS" / str(info["CFBundleExecutable"])
            if cand.exists():
                return cand
        macos_dir = app_path / "Contents" / "MacOS"
        execs = sorted([p for p in macos_dir.glob("*") if p.is_file()])
        return execs[0] if execs else None
    except Exception:  # noqa: BLE001
        return None


def sample_zip_entries(zip_path: Path, sample_limit: int = 30) -> List[str]:
    out: List[str] = []
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            for i, name in enumerate(z.namelist()):
                out.append(name)
                if i + 1 >= sample_limit:
                    break
    except Exception:  # noqa: BLE001
        out.append("<zip-error>")
    return out


def scan_app_bundle(app_mount_path: str, args: argparse.Namespace, task_timeout: Optional[float]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    app_path = Path(app_mount_path)
    out["path"] = str(app_path)
    out["bundle_id"] = None
    out["version"] = None

    info, raw = read_info_plist(app_path, timeout=max(2, task_timeout or 2))
    if info:
        out["info"] = info
        out["bundle_id"] = info.get("CFBundleIdentifier")
        out["version"] = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    else:
        out["info_raw"] = raw

    exec_path = _find_exec_from_info(app_path, info)
    out["exec"] = str(exec_path) if exec_path else None

    if exec_path and exec_path.exists():
        out["codesign"] = codesign_info(exec_path, timeout=max(2, task_timeout or 2))
        out["spctl"] = spctl_assess_file(exec_path, timeout=max(2, task_timeout or 2))
    else:
        out["codesign"] = None
        out["spctl"] = None

    if args.entropy and exec_path and exec_path.exists():
        ent_budget = max(1, int((task_timeout or 10) * 0.6))
        out["entropy"] = file_entropy(exec_path, ent_budget, sample_bytes=args.entropy_sample)
    else:
        out["entropy"] = None

    embedded: List[Dict[str, Any]] = []
    if args.unpack_embedded or args.java_check:
        base = app_path / "Contents"
        for root, _, files in os.walk(str(base)):
            for fn in files:
                if fn.lower().endswith((".jar", ".zip")):
                    full = Path(root) / fn
                    sample = sample_zip_entries(full, sample_limit=args.truncate_samples or 30)
                    embedded.append({"path": str(full), "sample": sample})
    out["embedded_archives"] = embedded

    if args.java_check and embedded:
        suspicious = []
        kws = [
            "Runtime.getRuntime",
            "ProcessBuilder",
            "Socket",
            "HttpURLConnection",
            "URLConnection",
            "openConnection",
            "URL",
        ]
        for e in embedded:
            joined = "\n".join(e.get("sample", [])).lower()
            for kw in kws:
                if kw.lower() in joined:
                    suspicious.append({"archive": e["path"], "keyword": kw})
                    break
        out["java_artifact_indicators"] = suspicious

    return out


# ---------- PKG scanning ----------
def _expand_pkg_to_tmp(pkg_path: Path, timeout: Optional[int]) -> Optional[Path]:
    target = Path(tempfile.mktemp(prefix="pkgx_"))
    p = run(f"pkgutil --expand {shlex_quote(str(pkg_path))} {shlex_quote(str(target))}", timeout=timeout)
    if p.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        return None
    return target


def _pkg_file_sample(pkg_path: Path, limit: int, timeout: Optional[int]) -> List[str]:
    p = run(f"pkgutil --payload-files {shlex_quote(str(pkg_path))} 2>/dev/null | head -n {limit}", timeout=timeout)
    lines = (p.stdout or b"").decode(errors="ignore").splitlines()
    if lines:
        return lines[:limit]
    d = _expand_pkg_to_tmp(pkg_path, timeout)
    if not d:
        return []
    sample: List[str] = []
    try:
        for root, _, files in os.walk(d):
            for fn in files:
                rel = os.path.relpath(os.path.join(root, fn), d)
                sample.append(rel)
                if len(sample) >= limit:
                    raise StopIteration
    except StopIteration:
        pass
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return sample


def _read_pkg_metadata(expanded_dir: Path) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    versions: List[str] = []

    dist = expanded_dir / "Distribution"
    if dist.exists():
        try:
            txt = dist.read_text(errors="ignore")
            versions += re.findall(r'version="([^"]+)"', txt)
        except Exception:  # noqa: BLE001
            pass

    pkg_infos = list(expanded_dir.glob("**/PackageInfo"))
    candidates: List[Tuple[str, str]] = []
    for pi in pkg_infos:
        try:
            txt = pi.read_text(errors="ignore")
            mid = re.search(r'identifier="([^"]+)"', txt)
            mver = re.search(r'version="([^"]+)"', txt)
            ident = mid.group(1) if mid else ""
            ver = mver.group(1) if mver else ""
            if ver:
                versions.append(ver)
            if ident:
                candidates.append((ident, ver))
        except Exception:  # noqa: BLE001
            continue

    preferred = None
    for ident, _ in candidates:
        if "." in ident:
            preferred = ident
            break
    meta["identifier"] = preferred or (candidates[0][0] if candidates else None)

    def _ver_key(v: str) -> Tuple[int, int, int, int]:
        nums = [int(x) for x in re.findall(r"\d+", v)]
        nums = (nums + [0, 0, 0, 0])[:4]
        return tuple(nums)  # type: ignore[return-value]

    meta["version"] = max(versions, key=_ver_key) if versions else None
    if pkg_infos:
        meta["packageinfo_files"] = [str(p) for p in pkg_infos]
    return meta


def _pkg_meta_best(pkg_path: Path, timeout: int = 90) -> Tuple[Optional[str], Optional[str]]:
    tmp = Path(tempfile.mktemp(prefix="pkgx_best_"))
    try:
        _ = run(f"pkgutil --expand {shlex_quote(str(pkg_path))} {shlex_quote(str(tmp))}", timeout=timeout)
        pis = list(tmp.glob("**/PackageInfo"))
        ident, versions = None, []
        for pi in pis:
            t = pi.read_text(errors="ignore")
            mid = re.search(r'identifier="([^"]+)"', t)
            mver = re.search(r'version="([^"]+)"', t)
            if mid and not ident:
                ident = mid.group(1)
            if mver:
                versions.append(mver.group(1))

        def vkey(v: str) -> Tuple[int, int, int, int]:
            nums = [int(x) for x in re.findall(r"\d+", v)]
            nums = (nums + [0, 0, 0, 0])[:4]
            return tuple(nums)  # type: ignore[return-value]

        ver = sorted(versions, key=vkey)[-1] if versions else None
        return ident, ver
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scan_pkg_file(pkg_path: Path, args: argparse.Namespace, task_timeout: Optional[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": str(pkg_path)}
    out["codesign"] = codesign_info(pkg_path, timeout=max(2, task_timeout or 2))
    out["spctl"] = spctl_assess_pkg(pkg_path, timeout=max(2, task_timeout or 2))
    meta: Dict[str, Any] = {}
    expanded = _expand_pkg_to_tmp(pkg_path, timeout=max(90, (task_timeout or 10)))
    if expanded:
        try:
            meta = _read_pkg_metadata(expanded) or {}
        finally:
            shutil.rmtree(expanded, ignore_errors=True)
    if not meta.get("identifier") or not meta.get("version"):
        iid2, ver2 = _pkg_meta_best(pkg_path, timeout=max(90, (task_timeout or 10)))
        if iid2 and not meta.get("identifier"):
            meta["identifier"] = iid2
        if ver2 and not meta.get("version"):
            meta["version"] = ver2
    out["identifier"] = meta.get("identifier")
    out["version"] = meta.get("version")
    out["files_sample"] = _pkg_file_sample(pkg_path, limit=args.pkg_sample, timeout=task_timeout)
    return out


# ---------- DMG scan ----------
@dataclass
class ScanResult:
    path: str
    mime: str
    dmg: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def scan_dmg(path: Path, args: argparse.Namespace, task_timeout: Optional[int]) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "path": str(path),
        "mime": "application/x-apple-diskimage",
        "dmg": {"ok": False, "mounts": [], "apps": [], "pkgs": []},
        "error": None,
    }
    ok, mounts, raw = attach_dmg(
        path, mountpoint=Path(args.mountpoint) if args.mountpoint else None, attach_timeout=args.attach_timeout
    )
    res["dmg"]["raw_attach"] = raw
    if not ok:
        res["dmg"]["ok"] = False
        res["error"] = "attach-failed"
        return res
    res["dmg"]["ok"] = True
    res["dmg"]["mounts"] = mounts

    found_apps: List[str] = []
    found_pkgs: List[str] = []
    for m in mounts:
        mpath = Path(m)
        try:
            for entry in mpath.iterdir():
                if entry.suffix == ".app" and entry.is_dir():
                    found_apps.append(str(entry))
                elif entry.suffix == ".pkg" and entry.is_file():
                    found_pkgs.append(str(entry))
        except Exception:  # noqa: BLE001
            continue
    if not found_apps:
        for m in mounts:
            for entry in (Path(m)).glob("**/*.app"):
                found_apps.append(str(entry))
                if len(found_apps) > 50:
                    break
            if len(found_apps) > 50:
                break

    per_task = max(2, int(task_timeout or args.per_task_timeout or 10))
    apps_out = [scan_app_bundle(app, args, per_task) for app in found_apps]
    pkgs_out = [scan_pkg_file(Path(pkg), args, per_task) for pkg in found_pkgs]
    res["dmg"]["apps"] = apps_out
    res["dmg"]["pkgs"] = pkgs_out

    if not args.keep_mounted:
        try:
            detach_mounts(mounts)
        except Exception:  # noqa: BLE001
            pass
    else:
        res["dmg"]["kept_mounted"] = True
    return res


# ---------- Windows and mobile ----------
def _read_pe_headers(path: Path) -> Dict[str, Any]:
    import struct

    out: Dict[str, Any] = {"is_pe": False}
    p = Path(path)
    if not p.exists():
        return out
    try:
        with p.open("rb") as f:
            mz = f.read(64)
            if mz[:2] != b"MZ":
                return out
            f.seek(0x3C)
            e_lfanew = struct.unpack("<I", f.read(4))[0]
            f.seek(e_lfanew)
            if f.read(4) != b"PE\0\0":
                return out
            coff = f.read(20)
            if len(coff) < 20:
                return out
            machine, sections, timestamp, _a, _b, opt_size, chars = struct.unpack("<HHIIIHH", coff)
            opt = f.read(opt_size or 0)
        out.update(
            {
                "is_pe": True,
                "machine": hex(machine),
                "sections": sections,
                "timestamp": timestamp,
                "characteristics": hex(chars),
                "pe32_plus": (len(opt) >= 2 and opt[:2] == b"\x0b\x02"),
            }
        )
        # heuristic: security directory size non-zero -> likely authenticode present
        if len(opt) >= 144:
            sec_size = int.from_bytes(opt[144 - 4 : 144], "little")
            out["has_authenticode"] = bool(sec_size)
        return out
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
        return out


def scan_exe_file(path: Path, args: argparse.Namespace, task_timeout: Optional[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": str(path), "type": "exe"}
    out["pe"] = _read_pe_headers(path)
    ent_budget = max(1, int((task_timeout or 10) * 0.6))
    out["entropy"] = file_entropy(Path(path), ent_budget, sample_bytes=args.entropy_sample)
    return out


def _is_cfb(path: Path) -> bool:
    try:
        with Path(path).open("rb") as f:
            return f.read(8) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    except Exception:  # noqa: BLE001
        return False


def scan_msi_file(path: Path, args: argparse.Namespace, task_timeout: Optional[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": str(path), "type": "msi", "is_msi": _is_cfb(path)}
    ent_budget = max(1, int((task_timeout or 10) * 0.6))
    out["entropy"] = file_entropy(Path(path), ent_budget, sample_bytes=args.entropy_sample)
    return out


def scan_bat_file(path: Path, args: argparse.Namespace, task_timeout: Optional[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": str(path), "type": "bat"}
    try:
        txt = Path(path).read_text(errors="ignore")
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
        return out
    head = "\n".join(txt.splitlines()[:80])
    sigs = [
        "powershell",
        "rundll32",
        "reg add",
        "schtasks",
        "bitsadmin",
        "curl ",
        "certutil",
        "base64",
        "vssadmin",
        "wevtutil",
        "wmic",
        "mshta",
        "[System.Convert]::FromBase64String",
    ]
    out["head"] = head
    low = head.lower()
    out["indicators"] = [s for s in sigs if s.lower() in low]
    return out


def scan_apk_file(path: Path, args: argparse.Namespace, task_timeout: Optional[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": str(path), "type": "apk"}
    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            out["has_manifest"] = "AndroidManifest.xml" in names
            out["dex_count"] = sum(1 for n in names if n.endswith(".dex"))
            out["entries_sample"] = names[: min(len(names), args.truncate_samples or 30)]
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    ent_budget = max(1, int((task_timeout or 10) * 0.6))
    out["entropy"] = file_entropy(path, ent_budget, sample_bytes=args.entropy_sample)
    return out


def scan_ipa_file(path: Path, args: argparse.Namespace, task_timeout: Optional[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": str(path), "type": "ipa"}
    try:
        with zipfile.ZipFile(path, "r") as z:
            plist_name = None
            for n in z.namelist():
                if n.startswith("Payload/") and n.endswith(".app/Info.plist"):
                    plist_name = n
                    break
            if plist_name:
                data = z.read(plist_name)
                info = plistlib.loads(data)
                out["bundle_id"] = info.get("CFBundleIdentifier")
                out["version"] = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            out["has_mobileprovision"] = any(n.endswith(".mobileprovision") for n in z.namelist())
            out["entries_sample"] = z.namelist()[: min(len(z.namelist()), args.truncate_samples or 30)]
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


# ---------- CLI ----------
def _expand_paths(patterns: List[str]) -> List[Path]:
    import glob
    import os

    out: List[Path] = []
    for pat in patterns:
        pat = os.path.expanduser(os.path.expandvars(pat))
        if any(c in pat for c in "*?[]"):
            for m in sorted(glob.glob(pat, recursive=True)):
                if os.path.exists(m):
                    out.append(Path(m).resolve())
        else:
            p = Path(pat)
            if p.exists():
                out.append(p.resolve())
    uniq, seen = [], set()
    for p in out:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def make_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="thc4me-deep",
        description="Deep scanner for DMG/app bundles/pkgs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("paths", nargs="+", help="files or globs to scan")
    ap.add_argument("--deep", action="store_true", help="enable deeper static analysis")
    ap.add_argument("--forensics", action="store_true", help="add basic forensic checks")
    ap.add_argument("--entropy", action="store_true", help="compute entropy on binaries")
    ap.add_argument("--entropy-sample", type=int, default=8_000_000, help="bytes to sample for entropy")
    ap.add_argument("--unpack-embedded", action="store_true", help="sample embedded archives (zip/jar)")
    ap.add_argument("--java-check", action="store_true", help="scan jar entries for suspicious java APIs")
    ap.add_argument("--per-task-timeout", type=int, default=10, help="seconds per-path task timeout")
    ap.add_argument("--attach-timeout", type=int, default=30, help="seconds for hdiutil attach")
    ap.add_argument("--jobs", type=int, default=1, help="parallel jobs")
    ap.add_argument("--out", type=str, default=None, help="write JSON output to file")
    ap.add_argument("--mountpoint", type=str, default=None, help="fixed mountpoint for hdiutil -mountpoint")
    ap.add_argument("--truncate-samples", type=int, default=30, help="truncate samples per embedded archive")
    ap.add_argument("--pkg-sample", type=int, default=40, help="max files to list from pkg payload")
    ap.add_argument("--progress-bars", action="store_true", help="show progress bars")
    ap.add_argument(
        "--schema-version", type=int, default=SCHEMA_VERSION_DEFAULT, help="schema version embedded per item"
    )
    ap.add_argument("--keep-mounted", action="store_true", help="do not detach hdiutil mounts after scanning")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    ap = make_argparser()
    args = ap.parse_args(argv)

    paths = _expand_paths(args.paths)
    if not paths:
        cprint("No paths to scan.", style="bold red")
        return 2

    results: List[Dict[str, Any]] = []
    job_count = max(1, args.jobs)

    progress = None
    if args.progress_bars and console:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        progress.start()
        task_global = progress.add_task("Total", total=len(paths))

    def dispatch(pth: Path) -> Dict[str, Any]:
        sfx = pth.suffix.lower()
        if sfx == ".dmg":
            return scan_dmg(pth, args, args.per_task_timeout)
        if sfx == ".pkg":
            return {"pkg": scan_pkg_file(pth, args, args.per_task_timeout)}
        if sfx == ".app":
            return {"app": scan_app_bundle(str(pth), args, args.per_task_timeout)}
        if sfx == ".exe":
            return {"exe": scan_exe_file(pth, args, args.per_task_timeout)}
        if sfx == ".msi":
            return {"msi": scan_msi_file(pth, args, args.per_task_timeout)}
        if sfx in (".bat", ".cmd"):
            return {"bat": scan_bat_file(pth, args, args.per_task_timeout)}
        if sfx == ".apk":
            return {"apk": scan_apk_file(pth, args, args.per_task_timeout)}
        if sfx == ".ipa":
            return {"ipa": scan_ipa_file(pth, args, args.per_task_timeout)}
        return {"path": str(pth), "error": f"unsupported type: {sfx or '<none>'}"}

    try:
        with ThreadPoolExecutor(max_workers=job_count) as ex:
            futures = {ex.submit(dispatch, p): p for p in paths}
            for fut in as_completed(futures):
                pth = futures[fut]
                try:
                    r = fut.result()
                except Exception as e:  # noqa: BLE001
                    r = {"path": str(pth), "error": str(e)}
                if isinstance(r, dict):
                    r["schema_version"] = args.schema_version
                results.append(r)
                if progress:
                    progress.update(task_global, advance=1)
    finally:
        if progress:
            progress.stop()

    if console:
        tbl = Table(title="Scan Summary")
        tbl.add_column("path", overflow="fold")
        tbl.add_column("mounted")
        tbl.add_column("apps")
        for r in results:
            if "pkg" in r:
                tbl.add_row(r.get("pkg", {}).get("path", "<pkg>"), "n/a", "n/a")
            elif "app" in r:
                tbl.add_row(r.get("app", {}).get("path", "<app>"), "n/a", "1")
            elif "dmg" in r:
                mount_count = len(r.get("dmg", {}).get("mounts", []))
                apps_n = len(r.get("dmg", {}).get("apps", []))
                tbl.add_row(r.get("path", "<err>"), str(mount_count), str(apps_n))
            else:
                tbl.add_row(r.get("path", "<err>"), "n/a", "n/a")
        console.print(tbl)

    if args.out:
        try:
            with open(args.out, "w") as fh:
                json.dump(results, fh, indent=2)
            cprint(f"Wrote results to {args.out}", style="green")
        except Exception as e:  # noqa: BLE001
            cprint(f"Failed to write {args.out}: {e}", style="red")
            return 1
    else:
        print(json.dumps(results, indent=2))
    return 0


def cli() -> int:
    return main()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        cprint("Interrupted. Attempting to clean up mounts.", style="yellow")
        try:
            out = run("hdiutil info | awk '/disk[0-9]s[0-9]/ {print $1}' || true", timeout=3)
            txt = (out.stdout or b"").decode(errors="ignore")
            for line in txt.splitlines():
                if line.strip():
                    run(f"hdiutil detach {line.strip()} >/dev/null 2>&1", timeout=3)
        except Exception:  # noqa: BLE001
            pass
        raise
