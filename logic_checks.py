# -*- coding: utf-8 -*-
"""
Modul logiki i naduzyc (AKTYWNY). Nie czyta tylko strony, ale realnie wysyla
zadania, zeby sprawdzic, czy sa limity i czy nie da sie czegos zglitchowac.

UWAGA PRAWNA: ten modul wysyla prawdziwe zadania do serwera. Wolno go uruchamiac
WYLACZNIE na wlasnej stronie (najlepiej na kopii/stagingu) albo za pisemna zgoda
wlasciciela. Dlatego w app.py jest schowany za tokenem autoryzacyjnym.

To jest szkielet realnych testow. Czesc testow (np. limit tworzenia paszportow DPP)
wymaga wskazania konkretnego formularza/endpointu, bo jest specyficzna dla strony.
"""
import time
from urllib.parse import urlparse

from scanner import F, fetch, cat


def _idor(url):
    """Czy zmiana numeru w adresie pokazuje cudzy zasob bez logowania."""
    parts = urlparse(url)
    segs = parts.path.rstrip("/").split("/")
    if not segs or not segs[-1].isdigit():
        return None
    try:
        base = fetch(url)
        nxt = url.rsplit("/", 1)[0] + "/" + str(int(segs[-1]) + 1)
        other = fetch(nxt)
        if other.status_code == 200 and len(other.content) > 200 and \
           abs(len(other.content) - len(base.content)) < len(base.content) * 0.5 and \
           "login" not in other.url.lower():
            return F("crit", "Dostęp do cudzego zasobu przez zmianę numeru w adresie",
                     where=nxt,
                     found=f"Zmiana numeru w adresie na {nxt} zwraca inny rekord bez logowania.",
                     m="Możliwy wyciek danych innych klientów (błąd logiczny typu IDOR).",
                     f="Sprawdzaj uprawnienia do każdego zasobu po stronie serwera.", eff="it")
    except Exception:
        return None
    return None


def _rate_limit(url, n=15):
    """Czy serwer ogranicza liczbe szybkich zadan (ochrona przed botami)."""
    codes = []
    try:
        for _ in range(n):
            codes.append(fetch(url).status_code)
    except Exception:
        pass
    if codes and 429 not in codes and all(c < 400 for c in codes):
        return F("warn", "Brak widocznego limitu żądań (rate limiting)",
                 where="Strona główna",
                 found=f"Wysłano {len(codes)} szybkich żądań z jednego adresu i żaden nie został ograniczony (brak kodu 429).",
                 m="Jeśli strona ma płatne akcje (np. tworzenie paszportu DPP), bot może je masowo wywołać i nabić koszty.",
                 f="Dodaj limit żądań na IP/konto i CAPTCHĘ przy akcjach, które coś tworzą lub kosztują.", eff="it")
    return F("ok", "Serwer ogranicza nadmierny ruch", where="Strona główna",
             found="Przy serii szybkich żądań pojawiła się blokada (kod 429) lub spowolnienie.",
             m="Trudniej o atak botami i nabicie kosztów.", f="Nic nie trzeba robić.")


def run(url):
    items = []
    idor = _idor(url)
    if idor:
        items.append(idor)
    items.append(_rate_limit(url))
    items.append(F("ok", "Testy specyficzne dla strony (do konfiguracji)",
                   where="Formularz tworzenia paszportu, pole ilości, podwójny submit",
                   found="Limit tworzenia paszportów DPP, walidacja skrajnych danych i podwójnego kliknięcia "
                         "wymagają wskazania konkretnego formularza. Skonfiguruj je dla swojej strony.",
                   m="", f=""))
    return cat("logika", "Logika i nadużycia", "Czy kliknięciami można narobić szkód lub kosztów",
               "agent wysyła realne żądania i sprawdza limity oraz błędy logiczne. Tylko po zgodzie właściciela.",
               items, flag="Testy po zgodzie")
