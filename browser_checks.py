# -*- coding: utf-8 -*-
"""
Modul przegladarki (opcjonalny). Laduje strone w prawdziwym Chromium i lapie to,
czego nie widac z samego HTML: bledy JavaScript, nieudane zadania, rozjezdzajacy
sie uklad na telefonie.

Wlaczenie:
    pip install playwright
    playwright install chromium

Dziala pasywnie (tylko otwiera i oglada strone), wiec jest legalny z kazdego URL.
"""
from scanner import F, RANK


def _run(url):
    from playwright.sync_api import sync_playwright
    errors, failed = [], []
    overflow = False
    with sync_playwright() as p:
        br = p.chromium.launch()
        page = br.new_page(viewport={"width": 375, "height": 800})
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("requestfailed", lambda r: failed.append(r.url))
        page.goto(url, wait_until="networkidle", timeout=20000)
        overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 4")
        br.close()
    return errors, failed, overflow


def enrich(report):
    """Dodaje realne wyniki do kategorii 'bledy'."""
    try:
        errors, failed, overflow = _run(report["url"])
    except Exception:
        return
    cat = next((c for c in report["cats"] if c["id"] == "bledy"), None)
    if cat is None:
        return
    cat["picked"] = [i for i in cat["picked"] if "Modul przegladarki" not in i["where"]]
    cat["method"] = ("Playwright laduje strone w Chromium, lapie bledy JavaScript i nieudane "
                     "zadania oraz sprawdza uklad na telefonie.")
    if errors:
        cat["picked"].append(F("warn", f"{len(errors)} bledow JavaScript w konsoli",
                               where="Konsola przegladarki",
                               found="Przyklad: " + (errors[0][:160] if errors else ""),
                               m="Skrypty zglaszaja bledy, moga psuc dzialanie strony.",
                               f="Przekaz liste bledow osobie, ktora robila strone.", eff="it"))
    if failed:
        cat["picked"].append(F("warn", f"{len(failed)} nieudanych zadan sieciowych",
                               where="Zasoby strony",
                               found="Np. " + ", ".join(failed[:3]),
                               m="Czesc zasobow (zdjecia, skrypty) nie laduje sie poprawnie.",
                               f="Sprawdz, czy adresy brakujacych zasobow sa poprawne.", eff="it"))
    if overflow:
        cat["picked"].append(F("warn", "Uklad rozjezdza sie na telefonie",
                               where="Widok 375 px (telefon)",
                               found="Tresc jest szersza niz ekran, pojawia sie poziomy pasek przewijania.",
                               m="Na telefonie strona wyglada na zepsuta.",
                               f="Popraw style dla widoku mobilnego (max-width, responsywnosc).", eff="it"))
    if not errors and not failed and not overflow:
        cat["picked"].append(F("ok", "Brak bledow i glitchy w przegladarce",
                               where="Chromium, widok telefonu",
                               found="Brak bledow JavaScript, nieudanych zadan i rozjezdzania ukladu.",
                               m="Strona dziala plynnie.", f="Nic nie trzeba robic."))
    cat["picked"].sort(key=lambda i: RANK[i["sev"]], reverse=True)
    cat["worst"] = max([RANK[i["sev"]] for i in cat["picked"]], default=1)
