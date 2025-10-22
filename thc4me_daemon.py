#!/usr/bin/env python3
"""
thc4me_daemon.py - FastAPI scanner daemon for THC4me

POST /scan multipart form field 'file' -> returns JSON:
{ "scan": {...}, "artifacts": [...], "findings": [...] }
"""
import hashlib, json, re, shutil, subprocess, uuid, os, mimetypes
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import tempfile

app = FastAPI(title="THC4me Scanner", version="0.1")

CREDS_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|password|pass|secret|token|auth[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?"
)

def run_cmd(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return p.stdout.decode('utf-8', errors='ignore'), p.stderr.decode('utf-8', errors='ignore'), p.returncode
    except Exception as e:
        return "", str(e), 1

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def guess_file_type(path):
    file_bin = shutil.which("file")
    if file_bin:
        out, err, rc = run_cmd([file_bin, "--brief", "--mime-type", path])
        if out:
            return out.strip()
    mt, _ = mimetypes.guess_type(path)
    return mt or "application/octet-stream"

def extract_strings(path, min_len=4, max_lines=20000):
    strings_bin = shutil.which("strings")
    results = []
    if strings_bin:
        out, err, rc = run_cmd([strings_bin, "-n", str(min_len), path], timeout=30)
        if out:
            for i, line in enumerate(out.splitlines()):
                if i >= max_lines: break
                results.append(line.rstrip())
            return results
    # fallback naive extraction
    try:
        with open(path, 'rb') as f:
            data = f.read()
            printable = []
            cur = []
            for b in data:
                if 32 <= b < 127:
                    cur.append(chr(b))
                else:
                    if len(cur) >= min_len:
                        printable.append(''.join(cur))
                        if len(printable) >= max_lines: break
                    cur = []
            if len(cur) >= min_len and len(printable) < max_lines:
                printable.append(''.join(cur))
            return printable
    except Exception:
        return []

def scan_path(path):
    path = str(path)
    fid = str(uuid.uuid4())
    sha = sha256_of_file(path)
    ftype = guess_file_type(path)
    basename = os.path.basename(path)

    scan_obj = {
        "scan": {"id": fid, "filename": basename, "sha256": sha, "filetype": ftype, "scanned_at": datetime.utcnow().isoformat() + "Z"},
        "artifacts": [],
        "findings": []
    }

    scan_obj["artifacts"].append({
        "type":"metadata","name":"file_info","value":basename,
        "detail":f"mime={ftype}","evidence_path":path
    })

    lower = basename.lower()
    if lower.endswith((".apk",".jar",".ipa",".zip")):
        unzip = shutil.which("unzip")
        if unzip:
            out, err, rc = run_cmd([unzip, "-l", path])
            if out:
                scan_obj["artifacts"].append({"type":"archive_index","name":"unzip_list","value": out[:10000], "detail":"listing of archive contents", "evidence_path": ""})
        aapt = shutil.which("aapt") or shutil.which("aapt2")
        if aapt and lower.endswith(".apk"):
            out, err, rc = run_cmd([aapt, "dump", "xmltree", path, "AndroidManifest.xml"], timeout=20)
            if out:
                scan_obj["artifacts"].append({"type":"manifest","name":"AndroidManifest.xml","value": out[:10000], "detail":"aapt xmltree", "evidence_path": ""})

    # strings
    strs = extract_strings(path, min_len=4, max_lines=20000)
    if strs:
        scan_obj["artifacts"].append({"type":"strings_sample","name":"strings_top500","value": "\n".join(strs[:500]), "detail": f"{len(strs)} total strings", "evidence_path": ""})

    # regex hunts
    findings = []
    seen = set()
    for s in strs[:5000]:
        m = CREDS_RE.search(s)
        if m:
            keyval = m.group(1)
            if keyval in seen: continue
            seen.add(keyval)
            findings.append({
                "code":"TC-HARDCODED-CREDS",
                "title":"Hard-coded credential (Thick Client)",
                "severity":"High",
                "confidence":"Firm",
                "description":f"Possible hard-coded secret near: {keyval}",
                "evidence": s.strip(),
                "offsets": []
            })
            scan_obj["artifacts"].append({"type":"strings_match","name":"hardcoded_credential","value":keyval,"detail":s.strip(),"evidence_path":""})
            if len(findings) >= 25: break

    certs = [s for s in strs if "BEGIN CERTIFICATE" in s or "-----BEGIN CERTIFICATE-----" in s]
    if certs:
        for idx, c in enumerate(certs[:5]):
            scan_obj["artifacts"].append({"type":"certificate","name":f"cert_{idx}","value":c[:2000],"detail":"embedded certificate (truncated)","evidence_path":""})

    scan_obj["artifacts"].append({"type":"hash","name":"sha256","value":sha,"detail":"","evidence_path":path})

    if findings:
        scan_obj["findings"].extend(findings)

    if len(strs) > 20000:
        scan_obj["artifacts"].append({"type":"note","name":"large_string_pool","value":str(len(strs)),"detail":"Large number of printable strings","evidence_path":""})

    return scan_obj

@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    # save to temp
    suffix = Path(file.filename).suffix or ""
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tf:
        tmpname = tf.name
        content = await file.read()
        tf.write(content)
    try:
        # Basic safety: limit file size (e.g., 200MB)
        if os.path.getsize(tmpname) > 200 * 1024 * 1024:
            os.unlink(tmpname)
            raise HTTPException(status_code=413, detail="file too large")
        result = scan_path(tmpname)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.unlink(tmpname)
        except Exception:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("thc4me_daemon:app", host="127.0.0.1", port=8000, workers=1, log_level="info")
