#!/usr/bin/env python3
import os, sys, json, plistlib, subprocess, tempfile, shutil, xml.etree.ElementTree as ET

def _run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {"ok": p.returncode == 0, "code": p.returncode, "out": p.stdout, "err": p.stderr}

def _filetype(p):
    r = _run(["/usr/bin/file","-b","--mime-type",p])
    if not r["ok"]:
        return "application/octet-stream"
    return r["out"].splitlines()[0].strip()

def is_macho(p):
    try:
        with open(p,"rb") as f:
            m = int.from_bytes(f.read(4),"big")
        return m in (0xFEEDFACE,0xFEEDFACF,0xCEFAEDFE,0xCFFAEDFE,0xCAFEBABE,0xCAFEBABF)
    except Exception:
        return False

def macho_info(p):
    libs = []
    r = _run(["/usr/bin/otool","-L",p])
    if r["ok"]:
        for line in r["out"].splitlines()[1:]:
            line = line.strip()
            if line:
                libs.append(line.split(" (compatibility",1)[0])
    archs = []
    r2 = _run(["/usr/bin/lipo","-info",p])
    if r2["ok"]:
        txt = r2["out"]
        if "are:" in txt:
            archs = txt.split("are:",1)[1].strip().split()
        elif "architecture:" in txt:
            archs = [txt.split("architecture:",1)[1].strip()]
    return {"libs": libs, "archs": archs}

def verify_codesign(p):
    r = _run(["/usr/bin/codesign","-dv","--verbose=4",p])
    info = {"ok": r["ok"], "details": (r["err"] or r["out"])}
    out = info["details"]
    keys = ("Identifier","TeamIdentifier","Authority","Format","CodeDirectory v","Sealed Resources version","Timestamp","Runtime Version")
    for line in out.splitlines():
        s = line.strip()
        for k in keys:
            if s.startswith(k + ":"):
                info[k] = s.split(":",1)[1].strip()
    return info

def spctl_assess(p):
    r = _run(["/usr/sbin/spctl","--assess","--type","exec","-vv",p])
    return {"ok": r["ok"], "code": r["code"], "out": r["out"].strip(), "err": r["err"].strip()}

def _is_app_dir(path):
    return os.path.isdir(path) and os.path.exists(os.path.join(path,"Contents","Info.plist"))

def scan_app_bundle(app):
    info_plist = os.path.join(app,"Contents","Info.plist")
    info = {}
    if os.path.exists(info_plist):
        with open(info_plist,"rb") as f:
            info = plistlib.load(f)
    exe = None
    if info.get("CFBundleExecutable"):
        exe = os.path.join(app,"Contents","MacOS",info["CFBundleExecutable"])
    res = {"info": info}
    if exe and os.path.exists(exe):
        res["exec"] = exe
        if is_macho(exe):
            res["macho"] = macho_info(exe)
            res["codesign"] = verify_codesign(exe)
            res["spctl"] = spctl_assess(exe)
    return res

def scan_pkg(pkg):
    out = {"signature": _run(["/usr/sbin/pkgutil","--check-signature",pkg])["out"].strip()}
    tmp = tempfile.mkdtemp(prefix="thc4me_pkg_")
    try:
        r = _run(["/usr/sbin/pkgutil","--expand",pkg,os.path.join(tmp,"exp")])
        if not r["ok"]:
            out["expand_error"] = r["err"].strip() or r["out"].strip()
            return out
        ids = []
        for root,_,files in os.walk(os.path.join(tmp,"exp")):
            for fn in files:
                if fn == "PackageInfo":
                    pth = os.path.join(root,fn)
                    try:
                        txt = open(pth,"r",encoding="utf-8",errors="ignore").read()
                        try:
                            el = ET.fromstring(txt)
                            ident = el.attrib.get("identifier")
                            ver = el.attrib.get("version")
                            if ident:
                                ids.append({"id": ident, "version": ver})
                        except Exception:
                            pass
                    except Exception:
                        pass
        if ids:
            out["packages"] = ids
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def scan_dmg(dmg):
    r = _run(["/usr/bin/hdiutil","attach","-nobrowse","-readonly","-plist",dmg])
    if not r["ok"]:
        return {"ok": False, "error": r["err"].strip() or r["out"].strip()}
    mounts, devs, listing = [], [], []
    try:
        plist = plistlib.loads(r["out"].encode())
        ents = plist.get("system-entities",[])
        mounts = [e.get("mount-point") for e in ents if e.get("mount-point")]
        devs = [e.get("dev-entry") for e in ents if e.get("dev-entry")]
        for m in mounts:
            try:
                entries = os.listdir(m)
                top = []
                for name in sorted(entries)[:100]:
                    full = os.path.join(m,name)
                    item = {"name": name, "type": ("dir" if os.path.isdir(full) else "file")}
                    if _is_app_dir(full):
                        info = os.path.join(full,"Contents","Info.plist")
                        try:
                            with open(info,"rb") as f:
                                meta = plistlib.load(f)
                            item["app"] = {"id": meta.get("CFBundleIdentifier"), "ver": meta.get("CFBundleShortVersionString")}
                        except Exception:
                            pass
                    top.append(item)
                listing.append({"mount": m, "entries": top})
            except Exception as e:
                listing.append({"mount": m, "error": str(e)})
        result = {"ok": True, "mounts": mounts, "listing": listing, "devices": devs}
    except Exception:
        result = {"ok": True, "raw": r["out"]}
    finally:
        for d in devs:
            _run(["/usr/bin/hdiutil","detach",d])
    return result

def _scan_one(p):
    p = os.path.realpath(p)
    if not os.path.exists(p):
        return {"path": p, "error": "not found"}
    mime = _filetype(p) if os.path.isfile(p) else ("inode/directory" if os.path.isdir(p) else "unknown")
    out = {"path": p, "mime": mime, "size": (os.path.getsize(p) if os.path.isfile(p) else None)}
    if (p.endswith(".app") or _is_app_dir(p)) and os.path.isdir(p):
        out["bundle"] = scan_app_bundle(p); return out
    if p.endswith(".pkg"):
        out["pkg"] = scan_pkg(p); return out
    if p.endswith(".dmg") or "iso9660" in mime:
        out["dmg"] = scan_dmg(p); return out
    if os.path.isfile(p) and is_macho(p):
        out["macho"] = macho_info(p); out["codesign"] = verify_codesign(p); out["spctl"] = spctl_assess(p)
    return out

def _scan_many(paths):
    items = []
    for p in paths:
        try:
            items.append(_scan_one(p))
        except Exception as e:
            items.append({"path": p, "error": str(e)})
    return items

def cli():
    if sys.platform != "darwin":
        print(json.dumps({"error": "macOS required for deep scan"})); sys.exit(2)
    if len(sys.argv) < 2:
        print("usage: thc4me-deep <path>", file=sys.stderr); sys.exit(2)
    target = sys.argv[1]
    print(json.dumps(_scan_one(target), ensure_ascii=False))

