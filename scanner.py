# -*- coding: utf-8 -*-
"""
Czujka - silnik skanujacy (pasywny).
Wszystkie testy ponizej czytaja tylko to, co strona sama oddaje przegladarce,
wiec sa legalne na kazdym URL. Testy aktywne (logika, naduzycia) sa w logic_checks.py
i wymagaja zgody wlasciciela.
"""
import socket
import ssl
import time
import random
import string
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

UA = "CzujkaScanner/1.0 (+audyt-strony)"
TIMEOUT = 10
PTS = {"crit": 14, "warn": 5}
RANK = {"crit": 3, "warn": 2, "ok": 1}


def normalize(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def fetch(url, method="GET", allow_redirects=True):
    return requests.request(
        method, url, timeout=TIMEOUT, allow_redirects=allow_redirects,
        headers={"User-Agent": UA, "Accept": "text/html,*/*"}, verify=True,
    )


def F(sev, t, where="", found="", m="", f="", eff=None):
    d = {"sev": sev, "t": t, "where": where, "found": found, "m": m, "f": f}
    if eff:
        d["eff"] = eff
    return d


# ---------------------------------------------------------------- checks

def check_availability(ctx):
    items = []
    try:
        t0 = time.time()
        r = fetch(ctx["url"])
        dt = time.time() - t0
        ctx["main"] = r
        ctx["soup"] = BeautifulSoup(r.text, "lxml")
        ctx["final_url"] = r.url
        if r.status_code >= 500:
            items.append(F("crit", f"Strona zwraca blad serwera ({r.status_code})",
                           where=ctx["url"],
                           found=f"Adres {ctx['url']} zwraca kod {r.status_code} zamiast strony.",
                           m="Strona nie otwiera sie poprawnie.",
                           f="Sprawdz logi serwera, blad jest po stronie serwera.", eff="it"))
        elif r.status_code >= 400:
            items.append(F("crit", f"Strona zwraca blad ({r.status_code})",
                           where=ctx["url"],
                           found=f"Adres {ctx['url']} zwraca kod {r.status_code}.",
                           m="Odwiedzajacy nie zobaczy strony.",
                           f="Sprawdz konfiguracje adresu i serwera.", eff="it"))
        else:
            items.append(F("ok", "Strona odpowiada poprawnie", where=ctx["final_url"],
                           found=f"Kod odpowiedzi {r.status_code}, czas odpowiedzi {dt:.1f} s.",
                           m="Serwer zwraca strone bez bledow.", f="Nic nie trzeba robic."))
            if dt > 2.5:
                items.append(F("warn", f"Wolna odpowiedz serwera ({dt:.1f} s)",
                               where=ctx["final_url"],
                               found=f"Serwer odpowiedzial po {dt:.1f} s (zalecane ponizej 2,5 s).",
                               m="Czesc osob zamyka strone, zanim sie zaladuje.",
                               f="Wlacz pamiec podreczna i sprawdz wydajnosc hostingu.", eff="srednie"))
    except requests.exceptions.SSLError as e:
        items.append(F("crit", "Blad certyfikatu SSL", where=ctx["url"],
                       found=f"Nie udalo sie nawiazac bezpiecznego polaczenia: {e.__class__.__name__}.",
                       m="Przegladarki pokaza ostrzezenie o niebezpiecznej stronie.",
                       f="Sprawdz i odnow certyfikat SSL.", eff="it"))
    except Exception as e:
        items.append(F("crit", "Strona nie odpowiada", where=ctx["url"],
                       found=f"Brak odpowiedzi: {e.__class__.__name__}.",
                       m="Strona jest niedostepna.",
                       f="Sprawdz, czy serwer dziala i czy domena wskazuje na wlasciwy adres.", eff="it"))
    return cat("dostepnosc", "Dostepnosc i dzialanie",
               "Czy strona odpowiada i jak szybko sie laduje",
               "wysylamy zapytanie HTTP i mierzymy kod odpowiedzi oraz czas.", items)


def check_security(ctx):
    items = []
    r = ctx.get("main")
    final = ctx.get("final_url", ctx["url"])
    host = urlparse(final).hostname

    # HTTPS wymuszane?
    try:
        http_url = "http://" + host
        hr = fetch(http_url, allow_redirects=True)
        if hr.url.startswith("https://"):
            items.append(F("ok", "Polaczenie jest szyfrowane (HTTPS)", where="Cala domena",
                           found="Przekierowanie z http na https dziala.",
                           m="Dane miedzy klientem a strona sa zaszyfrowane.", f="Nic nie trzeba robic."))
        else:
            items.append(F("crit", "Strona nie wymusza HTTPS", where="http://" + host,
                           found="Wejscie przez http nie przekierowuje na https.",
                           m="Dane moga byc przesylane bez szyfrowania.",
                           f="Ustaw przekierowanie z http na https i wlacz HSTS.", eff="it"))
    except Exception:
        pass

    # Certyfikat
    try:
        days, issuer = tls_cert_days(host)
        if days is None:
            pass
        elif days < 0:
            items.append(F("crit", "Certyfikat SSL wygasl", where="Domena glowna",
                           found=f"Certyfikat dla {host} wygasl {abs(days)} dni temu (wystawca {issuer}).",
                           m="Przegladarki pokazuja czerwone ostrzezenie i odstraszaja klientow.",
                           f="Natychmiast odnow certyfikat.", eff="sam"))
        elif days < 14:
            items.append(F("crit", f"Certyfikat SSL wygasa za {days} dni", where="Domena glowna",
                           found=f"Certyfikat dla {host} wygasa za {days} dni (wystawca {issuer}).",
                           m="Po wygasnieciu strona bedzie oznaczona jako niebezpieczna.",
                           f="Odnow certyfikat w panelu hostingu, najlepiej automatycznie.", eff="sam"))
        else:
            items.append(F("ok", "Certyfikat SSL jest wazny", where="Domena glowna",
                           found=f"Certyfikat wazny jeszcze {days} dni (wystawca {issuer}).",
                           m="Polaczenie jest zabezpieczone.", f="Nic nie trzeba robic."))
    except Exception:
        pass

    # Naglowki
    if r is not None:
        h = {k.lower(): v for k, v in r.headers.items()}
        if "strict-transport-security" not in h:
            items.append(F("warn", "Brak naglowka bezpieczenstwa HSTS", where="Naglowki odpowiedzi serwera",
                           found="W odpowiedzi brak naglowka Strict-Transport-Security.",
                           m="Strona nie wymusza szyfrowanego polaczenia na poziomie przegladarki.",
                           f="Dodaj naglowek HSTS w konfiguracji serwera.", eff="it"))
        if "content-security-policy" not in h:
            items.append(F("warn", "Brak naglowka Content-Security-Policy", where="Naglowki odpowiedzi serwera",
                           found="Brak naglowka Content-Security-Policy.",
                           m="Brakuje zabezpieczenia utrudniajacego wstrzykniecie zlosliwego skryptu.",
                           f="Dodaj naglowek CSP dopasowany do strony.", eff="it"))
        if "x-frame-options" not in h and "content-security-policy" not in h:
            items.append(F("warn", "Brak ochrony przed osadzeniem w ramce", where="Naglowki odpowiedzi serwera",
                           found="Brak naglowka X-Frame-Options.",
                           m="Strone mozna osadzic w ramce i uzyc do oszustwa (clickjacking).",
                           f="Dodaj naglowek X-Frame-Options: SAMEORIGIN.", eff="it"))
        srv = h.get("server", "") + " " + h.get("x-powered-by", "")
        if any(ch.isdigit() for ch in srv):
            items.append(F("warn", "Serwer ujawnia wersje oprogramowania", where="Naglowki odpowiedzi serwera",
                           found=f"Naglowek ujawnia wersje: {srv.strip()}.",
                           m="Ulatwia to szukanie dziur pasujacych do tej wersji.",
                           f="Ukryj informacje o wersji w konfiguracji serwera.", eff="it"))
        if not any(x in h for x in ("strict-transport-security", "content-security-policy", "x-frame-options")):
            pass

    # Wrazliwe pliki
    items += check_sensitive_paths(ctx)

    if not any(i["sev"] != "ok" for i in items):
        items.append(F("ok", "Nie wykryto typowych problemow bezpieczenstwa", where="Naglowki i sciezki",
                       found="Podstawowe naglowki obecne, nie znaleziono publicznych plikow z danymi.",
                       m="Podstawy bezpieczenstwa sa na miejscu.", f="Nic nie trzeba robic."))
    return cat("bezpieczenstwo", "Bezpieczenstwo", "Czy strona i dane klientow sa chronione",
               "czytamy naglowki odpowiedzi i certyfikat TLS oraz sprawdzamy typowe wrazliwe sciezki.", items)


def check_sensitive_paths(ctx):
    items = []
    base = ctx.get("final_url", ctx["url"])
    # baseline soft-404
    rnd = "/" + "".join(random.choices(string.ascii_lowercase, k=16)) + ".txt"
    try:
        b = fetch(urljoin(base + "/", rnd.lstrip("/")))
        base_status, base_len = b.status_code, len(b.content)
    except Exception:
        base_status, base_len = 404, -1
    probes = {
        "/.env": ("DB_", "APP_KEY", "SECRET", "="),
        "/.git/config": ("[core]", "repositoryformatversion"),
        "/.git/HEAD": ("ref:",),
        "/backup.zip": ("PK",),
        "/wp-config.php.bak": ("DB_PASSWORD", "DB_NAME"),
    }
    for path, sigs in probes.items():
        try:
            rr = fetch(urljoin(base + "/", path.lstrip("/")))
            if rr.status_code == 200 and len(rr.content) != base_len:
                body = rr.content[:4096].decode("utf-8", "ignore")
                if any(s in body for s in sigs):
                    items.append(F("crit", f"Publicznie dostepny wrazliwy plik ({path})",
                                   where=base + path,
                                   found=f"Plik {base}{path} otwiera sie publicznie i wyglada na plik z danymi dostepowymi.",
                                   m="Dane dostepowe moga byc widoczne w internecie dla kazdego.",
                                   f="Natychmiast usun plik z serwera i zmien ujawnione hasla.", eff="it"))
        except Exception:
            continue
    return items


def check_seo(ctx):
    items = []
    soup = ctx.get("soup")
    base = ctx.get("final_url", ctx["url"])
    if soup is None:
        return cat("wydajnosc", "Wydajnosc i widocznosc", "Jak szybko dziala i czy da sie ja znalezc w Google",
                   "parser HTML czyta znaczniki meta, atrybuty alt oraz robots.txt i sitemap.xml.", items)

    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    desc = soup.find("meta", attrs={"name": "description"})
    imgs = soup.find_all("img")
    no_alt = [i for i in imgs if not i.get("alt")]

    if not title:
        items.append(F("warn", "Brak tytulu strony", where="sekcja <head>",
                       found="Brak znacznika <title>.", m="W wynikach Google nie pojawi sie sensowny tytul.",
                       f="Dodaj unikalny tytul strony.", eff="sam"))
    if not desc or not desc.get("content"):
        items.append(F("warn", "Brak opisu meta na stronie glownej", where="sekcja <head>",
                       found="Brak znacznika <meta name='description'>.",
                       m="W wynikach Google pod tytulem nie pojawia sie zachecajacy opis.",
                       f="Dodaj krotki opis meta, do 160 znakow.", eff="sam"))
    if imgs and len(no_alt) > 0:
        items.append(F("warn", "Zdjecia bez opisow alternatywnych", where="Cala strona",
                       found=f"{len(no_alt)} z {len(imgs)} zdjec nie ma atrybutu alt.",
                       m="Wyszukiwarki i osoby niewidome nie wiedza, co jest na zdjeciach.",
                       f="Dodaj opisy alt do zdjec.", eff="sam"))

    # waga HTML
    html_kb = len(ctx["main"].content) / 1024 if ctx.get("main") is not None else 0
    if html_kb > 500:
        items.append(F("warn", f"Ciezki kod strony ({html_kb:.0f} KB)", where="Strona glowna (/)",
                       found=f"Sam dokument HTML wazy {html_kb:.0f} KB (zalecane ponizej 150 KB).",
                       m="Strona laduje sie wolniej.", f="Ogranicz rozmiar kodu i wczytuj zasoby na zadanie.", eff="it"))

    # sitemap / robots
    for path, nm in [("/sitemap.xml", "sitemap"), ("/robots.txt", "robots")]:
        try:
            rr = fetch(urljoin(base + "/", path.lstrip("/")))
            if nm == "sitemap":
                if rr.status_code == 200 and "<urlset" in rr.text[:2000].lower():
                    items.append(F("ok", "Strona ma mape witryny (sitemap)", where=base + path,
                                   found="Mapa witryny obecna.", m="Google latwiej znajduje podstrony.",
                                   f="Nic nie trzeba robic."))
                else:
                    items.append(F("warn", "Brak mapy witryny (sitemap)", where=base + path,
                                   found="Nie znaleziono sitemap.xml.", m="Google trudniej indeksuje strone.",
                                   f="Wygeneruj i wgraj sitemap.xml.", eff="sam"))
        except Exception:
            continue
    return cat("wydajnosc", "Wydajnosc i widocznosc", "Jak szybko dziala i czy da sie ja znalezc w Google",
               "parser HTML czyta znaczniki meta, atrybuty alt oraz robots.txt i sitemap.xml.", items)


def check_links(ctx):
    items = []
    soup = ctx.get("soup")
    base = ctx.get("final_url", ctx["url"])
    host = urlparse(base).hostname
    if soup is None:
        return cat("bledy", "Bledy i glitche", "Czy cos sie psuje lub zle wyswietla",
                   "sprawdzamy odnosniki wewnetrzne. Pelne wykrywanie bledow JavaScript wymaga modulu przegladarki.", items)
    seen, broken = set(), []
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        if urlparse(href).hostname != host:
            continue
        href = href.split("#")[0]
        if href in seen:
            continue
        seen.add(href)
        if len(seen) > 25:
            break
        try:
            rr = fetch(href, method="HEAD", allow_redirects=True)
            if rr.status_code >= 400:
                rr = fetch(href)  # some servers reject HEAD
            if rr.status_code >= 400:
                broken.append((href, rr.status_code))
        except Exception:
            broken.append((href, "brak odpowiedzi"))
    if broken:
        lst = ", ".join(f"{urlparse(u).path or '/'} ({c})" for u, c in broken[:5])
        items.append(F("warn", f"{len(broken)} linkow prowadzi donikad", where="Menu i tresc",
                       found=f"Niedzialajace odnosniki: {lst}.",
                       m="Klient klika i trafia na strone z bledem.",
                       f="Popraw adresy linkow albo je usun.", eff="sam"))
    else:
        items.append(F("ok", "Linki wewnetrzne dzialaja", where=f"Sprawdzono {len(seen)} odnosnikow",
                       found="Zaden sprawdzony link nie zwrocil bledu.",
                       m="Nawigacja po stronie dziala.", f="Nic nie trzeba robic."))
    items.append(F("ok", "Pelne wykrywanie bledow JS", where="Modul przegladarki",
                   found="Blledy konsoli i glitche na zywo wykrywa modul Playwright (browser_checks.py). Wlacz go, aby rozszerzyc ten test.",
                   m="", f=""))
    return cat("bledy", "Bledy i glitche", "Czy cos sie psuje lub zle wyswietla",
               "sprawdzamy odnosniki wewnetrzne. Pelne wykrywanie bledow JavaScript wlacza modul przegladarki.", items)


def check_rodo(ctx):
    items = []
    soup = ctx.get("soup")
    if soup is None:
        return cat("rodo", "Zgodnosc z RODO i prawem", "Czy strona spelnia wymogi prawne",
                   "szukamy skryptow sledzacych, polityki prywatnosci i klauzul przy formularzach.", items, flag="Rzadko sprawdzane")
    html = str(soup).lower()

    trackers = [t for t in ("google-analytics.com", "googletagmanager.com", "gtag(", "fbevents", "connect.facebook.net")
                if t in html]
    if trackers:
        items.append(F("crit", "Skrypt sledzacy laduje sie w kodzie strony", where="sekcja <head>",
                       found=f"Wykryto skrypty sledzace: {', '.join(set(trackers))}. Pasywnie nie da sie potwierdzic, czy czekaja na zgode (to sprawdza modul przegladarki).",
                       m="Jesli laduja sie przed zgoda na cookies, to naruszenie RODO.",
                       f="Upewnij sie, ze skrypty sledzace ruszaja dopiero po zgodzie uzytkownika.", eff="it"))

    has_priv = any(("polityk" in (a.get_text() or "").lower() or "prywatn" in (a.get("href") or "").lower()
                    or "privacy" in (a.get("href") or "").lower()) for a in soup.find_all("a", href=True))
    if has_priv:
        items.append(F("ok", "Jest link do polityki prywatnosci", where="Strona",
                       found="Znaleziono odnosnik do polityki prywatnosci.",
                       m="Dokument jest dostepny dla uzytkownikow.", f="Nic nie trzeba robic."))
    else:
        items.append(F("crit", "Brak polityki prywatnosci", where="Stopka strony",
                       found="Nie znaleziono linku do polityki prywatnosci.",
                       m="Prawo wymaga informowania, jak strona przetwarza dane.",
                       f="Dodaj polityke prywatnosci i link do niej w stopce.", eff="sam"))

    has_cookie = "cookie" in html or "ciasteczk" in html
    forms = soup.find_all("form")
    personal_forms = [fm for fm in forms if fm.find("input", attrs={"type": ["email", "text"]}) or fm.find("textarea")]
    for fm in personal_forms:
        has_consent = bool(fm.find("input", attrs={"type": "checkbox"})) and ("zgod" in fm.get_text().lower())
        if not has_consent:
            items.append(F("warn", "Formularz bez zgody na przetwarzanie danych", where="Formularz na stronie",
                           found="Formularz zbiera dane, ale brak checkboxa zgody i klauzuli informacyjnej.",
                           m="Zbieranie danych bez zgody jest niezgodne z RODO.",
                           f="Dodaj pod formularzem informacje i checkbox zgody.", eff="sam"))
            break
    if not has_cookie:
        items.append(F("warn", "Brak informacji o cookies", where="Strona",
                       found="Nie wykryto banera ani informacji o plikach cookies.",
                       m="Strona powinna informowac o cookies i pytac o zgode.",
                       f="Dodaj baner cookies z opcja zgody i odrzucenia.", eff="srednie"))
    return cat("rodo", "Zgodnosc z RODO i prawem", "Czy strona spelnia wymogi prawne",
               "szukamy skryptow sledzacych, polityki prywatnosci i klauzul przy formularzach.", items, flag="Rzadko sprawdzane")


# ---------------------------------------------------------------- helpers

def tls_cert_days(host):
    ctxs = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with ctxs.wrap_socket(sock, server_hostname=host) as ss:
            cert = ss.getpeercert()
    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (exp - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "nieznany")
    return days, issuer


def cat(cid, name, desc, method, items, flag=None):
    items = sorted(items, key=lambda i: RANK[i["sev"]], reverse=True)
    worst = max([RANK[i["sev"]] for i in items], default=1)
    d = {"id": cid, "name": name, "desc": desc, "method": method, "picked": items, "worst": worst}
    if flag:
        d["flag"] = flag
    return d


def scan(url):
    ctx = {"url": normalize(url)}
    cats = [
        check_availability(ctx),
        check_links(ctx),
        check_security(ctx),
        check_seo(ctx),
        check_rodo(ctx),
    ]
    crit = warn = ok = 0
    for c in cats:
        for it in c["picked"]:
            if it["sev"] == "crit":
                crit += 1
            elif it["sev"] == "warn":
                warn += 1
            else:
                ok += 1
    score = max(8, min(100, 100 - 14 * crit - 5 * warn))
    return {"url": ctx["url"], "cats": cats, "crit": crit, "warn": warn, "ok": ok,
            "score": score, "mode": "pasywny"}
