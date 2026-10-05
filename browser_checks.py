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
    cat["picked"] = [i for i in cat["picked"] if "Moduł przeglądarki" not in i["where"]]
    cat["method"] = ("Playwright ładuje stronę w Chromium, łapie błędy JavaScript i nieudane "
                     "żądania oraz sprawdza układ na telefonie.")
    if errors:
        cat["picked"].append(F("warn", f"{len(errors)} błędów JavaScript w konsoli",
                               where="Konsola przeglądarki",
                               found="Przykład: " + (errors[0][:160] if errors else ""),
                               m="Skrypty zgłaszają błędy, mogą psuć działanie strony.",
                               f="Przekaż listę błędów osobie, która robiła stronę.", eff="it"))
    if failed:
        cat["picked"].append(F("warn", f"{len(failed)} nieudanych żądań sieciowych",
                               where="Zasoby strony",
                               found="Np. " + ", ".join(failed[:3]),
                               m="Część zasobów (zdjęcia, skrypty) nie ładuje się poprawnie.",
                               f="Sprawdź, czy adresy brakujących zasobów są poprawne.", eff="it"))
    if overflow:
        cat["picked"].append(F("warn", "Układ rozjeżdża się na telefonie",
                               where="Widok 375 px (telefon)",
                               found="Treść jest szersza niż ekran, pojawia się poziomy pasek przewijania.",
                               m="Na telefonie strona wygląda na zepsuta.",
                               f="Popraw style dla widoku mobilnego (max-width, responsywność).", eff="it"))
    if not errors and not failed and not overflow:
        cat["picked"].append(F("ok", "Brak błędów i glitchy w przeglądarce",
                               where="Chromium, widok telefonu",
                               found="Brak błędów JavaScript, nieudanych żądań i rozjeżdżania układu.",
                               m="Strona działa płynnie.", f="Nic nie trzeba robić."))
    cat["picked"].sort(key=lambda i: RANK[i["sev"]], reverse=True)
    cat["worst"] = max([RANK[i["sev"]] for i in cat["picked"]], default=1)
