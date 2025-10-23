#!/usr/bin/env python3
import os, sys, json

try:
    from .core import (_filetype, is_macho, macho_info, verify_codesign, spctl_assess, scan_app_bundle, scan_pkg, scan_dmg)
except Exception:
    try:
        from .macho import _filetype, is_macho, macho_info
        from .macos import verify_codesign, spctl_assess, scan_app_bundle, scan_pkg, scan_dmg
    except Exception:
        import thc4me_static_parser as _sp
        _filetype=_sp._filetype; is_macho=_sp.is_macho; macho_info=_sp.macho_info
        verify_codesign=_sp.verify_codesign; spctl_assess=_sp.spctl_assess
        scan_app_bundle=_sp.scan_app_bundle; scan_pkg=_sp.scan_pkg; scan_dmg=_sp.scan_dmg

def _scan_one(p):
    mime=_filetype(p)
    out={"path":p,"mime":mime,"size":os.path.getsize(p)}
    if p.endswith(".app") and os.path.isdir(p): out["bundle"]=scan_app_bundle(p); return out
    if p.endswith(".pkg"): out["pkg"]=scan_pkg(p); return out
    if p.endswith(".dmg") or "iso9660" in mime: out["dmg"]=scan_dmg(p); return out
    if is_macho(p):
        out["macho"]=macho_info(p)
        out["codesign"]=verify_codesign(p)
        out["spctl"]=spctl_assess(p)
    return out

def _scan_many(paths):
    items=[]
    for p in paths:
        try: items.append(_scan_one(p))
        except Exception as e: items.append({"path":p,"error":str(e)})
    return items

def cli():
    if sys.platform!="darwin":
        print(json.dumps({"error":"macOS required for deep scan"})); sys.exit(2)
    if len(sys.argv)<2:
        print("usage: thc4me-deep <path>", file=sys.stderr); sys.exit(2)
    target=sys.argv[1]
    res=_scan_one(target)
    print(json.dumps(res, ensure_ascii=False))
