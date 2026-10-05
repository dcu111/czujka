# -*- coding: utf-8 -*-
"""
Czujka - serwer. Serwuje interfejs i udostepnia API skanowania.

Uruchomienie:
    pip install -r requirements.txt
    uvicorn app:app --port 8000
    # otworz http://localhost:8000

Tryb aktywny (logika/naduzycia) jest domyslnie wylaczony. Wolno go wlaczyc
TYLKO dla wlasnej strony lub za pisemna zgoda wlasciciela:
    export CZUJKA_AUTH_TOKEN=twoj-sekret
    # wywolaj /api/scan?url=...&mode=full&token=twoj-sekret
"""
import os
import pathlib

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, HTMLResponse

import scanner

try:
    import browser_checks
except Exception:
    browser_checks = None
try:
    import logic_checks
except Exception:
    logic_checks = None

app = FastAPI(title="Czujka")
FRONT = pathlib.Path(__file__).parent / "frontend" / "index.html"


@app.get("/", response_class=HTMLResponse)
def index():
    return FRONT.read_text(encoding="utf-8")


@app.get("/api/scan")
def api_scan(url: str = Query(...), mode: str = "passive", token: str = ""):
    try:
        report = scanner.scan(url)
    except Exception as e:
        return JSONResponse({"error": f"{e.__class__.__name__}: {e}"}, status_code=500)

    # modul przegladarki (bledy JS, glitche) - jesli zainstalowany
    if browser_checks is not None:
        try:
            browser_checks.enrich(report)
        except Exception:
            pass

    # tryb aktywny - tylko po autoryzacji
    auth = os.environ.get("CZUJKA_AUTH_TOKEN")
    if mode == "full" and auth and token == auth and logic_checks is not None:
        try:
            report["cats"].append(logic_checks.run(report["url"]))
            report = scanner_recount(report)
            report["mode"] = "pelny (autoryzowany)"
        except Exception:
            pass

    return JSONResponse(report)


def scanner_recount(report):
    crit = warn = ok = 0
    for c in report["cats"]:
        for it in c["picked"]:
            crit += it["sev"] == "crit"
            warn += it["sev"] == "warn"
            ok += it["sev"] == "ok"
    report["crit"], report["warn"], report["ok"] = crit, warn, ok
    report["score"] = max(8, min(100, 100 - 14 * crit - 5 * warn))
    return report
