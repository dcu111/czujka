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
            items.append(F("crit", f"Strona zwraca błąd serwera ({r.status_code})",
                           where=ctx["url"],
                           found=f"Adres {ctx['url']} zwraca kod {r.status_code} zamiast strony.",
                           m="Strona nie otwiera się poprawnie.",
                           f="Sprawdź logi serwera, błąd jest po stronie serwera.", eff="it"))
        elif r.status_code >= 400:
            items.append(F("crit", f"Strona zwraca błąd ({r.status_code})",
                           where=ctx["url"],
                           found=f"Adres {ctx['url']} zwraca kod {r.status_code}.",
                           m="Odwiedzający nie zobaczy strony.",
                           f="Sprawdź konfigurację adresu i serwera.", eff="it"))
        else:
            items.append(F("ok", "Strona odpowiada poprawnie", where=ctx["final_url"],
                           found=f"Kod odpowiedzi {r.status_code}, czas odpowiedzi {dt:.1f} s.",
                           m="Serwer zwraca stronę bez błędów.", f="Nic nie trzeba robić."))
            if dt > 2.5:
                items.append(F("warn", f"Wolna odpowiedź serwera ({dt:.1f} s)",
                               where=ctx["final_url"],
                               found=f"Serwer odpowiedział po {dt:.1f} s (zalecane poniżej 2,5 s).",
                               m="Część osób zamyka stronę, zanim się załaduje.",
                               f="Włącz pamięć podręczną i sprawdź wydajność hostingu.", eff="srednie"))
    except requests.exceptions.SSLError as e:
        items.append(F("crit", "Błąd certyfikatu SSL", where=ctx["url"],
                       found=f"Nie udało się nawiązać bezpiecznego połączenia: {e.__class__.__name__}.",
                       m="Przeglądarki pokażą ostrzeżenie o niebezpiecznej stronie.",
                       f="Sprawdź i odnów certyfikat SSL.", eff="it"))
    except Exception as e:
        items.append(F("crit", "Strona nie odpowiada", where=ctx["url"],
                       found=f"Brak odpowiedzi: {e.__class__.__name__}.",
                       m="Strona jest niedostępna.",
                       f="Sprawdź, czy serwer działa i czy domena wskazuje na właściwy adres.", eff="it"))
    return cat("dostepnosc", "Dostępność i działanie",
               "Czy strona odpowiada i jak szybko się ładuje",
               "wysyłamy zapytanie HTTP i mierzymy kod odpowiedzi oraz czas.", items)


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
            items.append(F("ok", "Połączenie jest szyfrowane (HTTPS)", where="Cała domena",
                           found="Przekierowanie z http na https działa.",
                           m="Dane między klientem a stroną są zaszyfrowane.", f="Nic nie trzeba robić."))
        else:
            items.append(F("crit", "Strona nie wymusza HTTPS", where="http://" + host,
                           found="Wejście przez http nie przekierowuje na https.",
                           m="Dane mogą być przesyłane bez szyfrowania.",
                           f="Ustaw przekierowanie z http na https i włącz HSTS.", eff="it"))
    except Exception:
        pass

    # Certyfikat
    try:
        days, issuer = tls_cert_days(host)
        if days is None:
            pass
        elif days < 0:
            items.append(F("crit", "Certyfikat SSL wygasł", where="Domena główna",
                           found=f"Certyfikat dla {host} wygasł {abs(days)} dni temu (wystawca {issuer}).",
                           m="Przeglądarki pokazują czerwone ostrzeżenie i odstraszają klientów.",
                           f="Natychmiast odnów certyfikat.", eff="sam"))
        elif days < 14:
            items.append(F("crit", f"Certyfikat SSL wygasa za {days} dni", where="Domena główna",
                           found=f"Certyfikat dla {host} wygasa za {days} dni (wystawca {issuer}).",
                           m="Po wygaśnięciu strona będzie oznaczona jako niebezpieczna.",
                           f="Odnów certyfikat w panelu hostingu, najlepiej automatycznie.", eff="sam"))
        else:
            items.append(F("ok", "Certyfikat SSL jest ważny", where="Domena główna",
                           found=f"Certyfikat ważny jeszcze {days} dni (wystawca {issuer}).",
                           m="Połączenie jest zabezpieczone.", f="Nic nie trzeba robić."))
    except Exception:
        pass

    # Naglowki
    if r is not None:
        h = {k.lower(): v for k, v in r.headers.items()}
        if "strict-transport-security" not in h:
            items.append(F("warn", "Brak nagłówka bezpieczeństwa HSTS", where="Nagłówki odpowiedzi serwera",
                           found="W odpowiedzi brak nagłówka Strict-Transport-Security.",
                           m="Strona nie wymusza szyfrowanego połączenia na poziomie przeglądarki.",
                           f="Dodaj nagłówek HSTS w konfiguracji serwera.", eff="it"))
        if "content-security-policy" not in h:
            items.append(F("warn", "Brak nagłówka Content-Security-Policy", where="Nagłówki odpowiedzi serwera",
                           found="Brak nagłówka Content-Security-Policy.",
                           m="Brakuje zabezpieczenia utrudniającego wstrzyknięcie złośliwego skryptu.",
                           f="Dodaj nagłówek CSP dopasowany do strony.", eff="it"))
        if "x-frame-options" not in h and "content-security-policy" not in h:
            items.append(F("warn", "Brak ochrony przed osadzeniem w ramce", where="Nagłówki odpowiedzi serwera",
                           found="Brak nagłówka X-Frame-Options.",
                           m="Stronę można osadzić w ramce i użyć do oszustwa (clickjacking).",
                           f="Dodaj nagłówek X-Frame-Options: SAMEORIGIN.", eff="it"))
        srv = h.get("server", "") + " " + h.get("x-powered-by", "")
        if any(ch.isdigit() for ch in srv):
            items.append(F("warn", "Serwer ujawnia wersję oprogramowania", where="Nagłówki odpowiedzi serwera",
                           found=f"Nagłówek ujawnia wersję: {srv.strip()}.",
                           m="Ułatwia to szukanie dziur pasujących do tej wersji.",
                           f="Ukryj informacje o wersji w konfiguracji serwera.", eff="it"))
        if not any(x in h for x in ("strict-transport-security", "content-security-policy", "x-frame-options")):
            pass

    # Tresc po http na stronie https. Skrypty i style przegladarka wtedy
    # BLOKUJE (strona sie rozjezdza), a przy zdjeciach pokazuje klodke jako
    # niepelna. Typowa pozostalosc po przenosinach strony na certyfikat.
    soup = ctx.get("soup")
    if soup is not None and final.startswith("https://"):
        aktywne, bierne = [], []
        for tag, attr in (("script", "src"), ("iframe", "src"), ("link", "href"), ("img", "src")):
            for el in soup.find_all(tag):
                adres = (el.get(attr) or "").strip()
                if not adres.lower().startswith("http://"):
                    continue
                if tag == "link" and "stylesheet" not in " ".join(el.get("rel") or []).lower():
                    continue
                (bierne if tag == "img" else aktywne).append(adres)
        if aktywne:
            items.append(F("crit", "Strona wczytuje zasoby po niezabezpieczonym połączeniu",
                           where="Kod strony",
                           found=f"{len(aktywne)} skryptów lub stylów ładuje się przez http, np. {aktywne[0][:80]}.",
                           m="Przeglądarka zablokuje te pliki i strona może wyglądać na zepsutą.",
                           f="Zmień te adresy z http na https.", eff="it"))
        elif bierne:
            items.append(F("warn", "Zdjęcia wczytywane po niezabezpieczonym połączeniu",
                           where="Kod strony",
                           found=f"{len(bierne)} zdjęć ładuje się przez http, np. {bierne[0][:80]}.",
                           m="Przeglądarka przestaje pokazywać kłódkę jako w pełni bezpieczną.",
                           f="Zmień adresy zdjęć z http na https.", eff="sam"))

    # Wrazliwe pliki
    items += check_sensitive_paths(ctx)

    if not any(i["sev"] != "ok" for i in items):
        items.append(F("ok", "Nie wykryto typowych problemów bezpieczeństwa", where="Nagłówki i ścieżki",
                       found="Podstawowe nagłówki obecne, nie znaleziono publicznych plików z danymi.",
                       m="Podstawy bezpieczeństwa są na miejscu.", f="Nic nie trzeba robić."))
    return cat("bezpieczenstwo", "Bezpieczeństwo", "Czy strona i dane klientów są chronione",
               "czytamy nagłówki odpowiedzi i certyfikat TLS oraz sprawdzamy typowe wrażliwe ścieżki.", items)


def check_sensitive_paths(ctx):
    items = []
    base = ctx.get("final_url", ctx["url"])
    # baseline soft-404
    if ctx.get("soft404"):
        # Pomiar wykonal juz check_links — nie powtarzamy zapytania.
        base_status, base_len = ctx["soft404"]
    else:
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
                    items.append(F("crit", f"Publicznie dostępny wrażliwy plik ({path})",
                                   where=base + path,
                                   found=f"Plik {base}{path} otwiera się publicznie i wygląda na plik z danymi dostępowymi.",
                                   m="Dane dostępowe mogą być widoczne w internecie dla każdego.",
                                   f="Natychmiast usuń plik z serwera i zmień ujawnione hasła.", eff="it"))
        except Exception:
            continue
    return items


def check_seo(ctx):
    items = []
    soup = ctx.get("soup")
    base = ctx.get("final_url", ctx["url"])
    if soup is None:
        return cat("wydajnosc", "Wydajność i widoczność", "Jak szybko działa i czy da się ją znaleźć w Google",
                   "parser HTML czyta znaczniki meta, atrybuty alt oraz robots.txt i sitemap.xml.", items)

    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    desc = soup.find("meta", attrs={"name": "description"})
    imgs = soup.find_all("img")
    no_alt = [i for i in imgs if not i.get("alt")]

    if not title:
        items.append(F("warn", "Brak tytułu strony", where="sekcja <head>",
                       found="Brak znacznika <title>.", m="W wynikach Google nie pojawi się sensowny tytuł.",
                       f="Dodaj unikalny tytuł strony.", eff="sam"))
    if not desc or not desc.get("content"):
        items.append(F("warn", "Brak opisu meta na stronie głównej", where="sekcja <head>",
                       found="Brak znacznika <meta name='description'>.",
                       m="W wynikach Google pod tytułem nie pojawia się zachęcający opis.",
                       f="Dodaj krótki opis meta, do 160 znaków.", eff="sam"))
    if imgs and len(no_alt) > 0:
        items.append(F("warn", "Zdjęcia bez opisów alternatywnych", where="Cała strona",
                       found=f"{len(no_alt)} z {len(imgs)} zdjęć nie ma atrybutu alt.",
                       m="Wyszukiwarki i osoby niewidome nie wiedzą, co jest na zdjęciach.",
                       f="Dodaj opisy alt do zdjęć.", eff="sam"))

    # Blokada indeksowania. Najczestszy blad przy starcie: ustawienie z wersji
    # roboczej jedzie na produkcje i strona jest niewidoczna w Google.
    robots_meta = soup.find("meta", attrs={"name": lambda v: bool(v) and v.lower() == "robots"})
    meta_content = (robots_meta.get("content") or "").lower() if robots_meta else ""
    x_robots = ctx["main"].headers.get("X-Robots-Tag", "").lower() if ctx.get("main") is not None else ""
    if "noindex" in meta_content or "noindex" in x_robots:
        zrodlo = "znacznik <meta name='robots'>" if "noindex" in meta_content else "nagłówek X-Robots-Tag"
        items.append(F("crit", "Strona jest zablokowana przed Google (noindex)", where="sekcja <head>",
                       found=f"Znaleziono ustawienie noindex ({zrodlo}).",
                       m="Google nie pokaże tej strony w wynikach. Dla nowej firmy to tak, jakby strony nie było.",
                       f="Usuń noindex, gdy strona jest gotowa do pokazania klientom.", eff="it"))

    # Widok na telefonie. Bez tego telefon pokazuje pomniejszona wersje widoku
    # z komputera i strona jest praktycznie nieczytelna.
    if not soup.find("meta", attrs={"name": lambda v: bool(v) and v.lower() == "viewport"}):
        items.append(F("warn", "Brak ustawienia widoku na telefon", where="sekcja <head>",
                       found="Brak znacznika <meta name='viewport'>.",
                       m="Na telefonie strona wyświetli się jak pomniejszony widok z komputera.",
                       f="Dodaj znacznik viewport z szerokością urządzenia.", eff="it"))

    html_tag = soup.find("html")
    if not (html_tag and html_tag.get("lang")):
        items.append(F("warn", "Brak oznaczenia języka strony", where="znacznik <html>",
                       found="Znacznik <html> nie ma atrybutu lang.",
                       m="Wyszukiwarki i czytniki ekranu nie wiedzą, w jakim języku jest strona.",
                       f="Dodaj lang=\"pl\" do znacznika <html>.", eff="sam"))

    # Podglad linku. Bez tego link wyslany na Facebooku czy WhatsAppie wyglada
    # jak goly adres, bez tytulu i obrazka.
    if not (soup.find("meta", attrs={"property": "og:title"}) or soup.find("meta", attrs={"property": "og:image"})):
        items.append(F("warn", "Brak podglądu przy udostępnianiu linku", where="sekcja <head>",
                       found="Brak znaczników Open Graph (og:title, og:image).",
                       m="Link wysłany klientowi na Facebooku czy WhatsAppie pokaże się bez tytułu i obrazka.",
                       f="Dodaj znaczniki og:title, og:description i og:image.", eff="sam"))

    # waga HTML
    html_kb = len(ctx["main"].content) / 1024 if ctx.get("main") is not None else 0
    if html_kb > 500:
        items.append(F("warn", f"Ciężki kod strony ({html_kb:.0f} KB)", where="Strona główna (/)",
                       found=f"Sam dokument HTML waży {html_kb:.0f} KB (zalecane poniżej 150 KB).",
                       m="Strona ładuje się wolniej.", f="Ogranicz rozmiar kodu i wczytuj zasoby na żądanie.", eff="it"))

    # sitemap / robots
    for path, nm in [("/sitemap.xml", "sitemap"), ("/robots.txt", "robots")]:
        try:
            rr = fetch(urljoin(base + "/", path.lstrip("/")))
            if nm == "sitemap":
                if rr.status_code == 200 and "<urlset" in rr.text[:2000].lower():
                    items.append(F("ok", "Strona ma mapę witryny (sitemap)", where=base + path,
                                   found="Mapa witryny obecna.", m="Google łatwiej znajduje podstrony.",
                                   f="Nic nie trzeba robić."))
                else:
                    items.append(F("warn", "Brak mapy witryny (sitemap)", where=base + path,
                                   found="Nie znaleziono sitemap.xml.", m="Google trudniej indeksuje stronę.",
                                   f="Wygeneruj i wgraj sitemap.xml.", eff="sam"))
            elif rr.status_code == 200:
                # Regula "Disallow: /" zamyka cala witryne, ale TYLKO jesli
                # dotyczy wszystkich robotow. Liczy sie, w ktorym bloku stoi:
                # github.com ma "Disallow: /" pod "User-agent: Bytespider",
                # czyli blokuje jednego bota, a nie wyszukiwarki. Sprawdzanie
                # samej linii dawalo tam falszywy alarm.
                blokada = False
                agenci, poprzednia_to_agent = set(), False
                for linia in rr.text.splitlines():
                    tresc = linia.split("#")[0].strip().lower().replace(" ", "")
                    if not tresc:
                        continue
                    if tresc.startswith("user-agent:"):
                        if not poprzednia_to_agent:
                            agenci = set()
                        agenci.add(tresc.split(":", 1)[1])
                        poprzednia_to_agent = True
                        continue
                    poprzednia_to_agent = False
                    if tresc == "disallow:/" and "*" in agenci:
                        blokada = True
                        break
                if blokada:
                    items.append(F("crit", "Plik robots.txt blokuje całą stronę", where=base + path,
                                   found="W robots.txt jest reguła Disallow: / zamykająca całą witrynę.",
                                   m="Wyszukiwarki dostają polecenie, żeby pominąć wszystkie podstrony.",
                                   f="Usuń regułę Disallow: / albo zawęź ją do katalogów, które mają zostać ukryte.",
                                   eff="it"))
        except Exception:
            continue
    return cat("wydajnosc", "Wydajność i widoczność", "Jak szybko działa i czy da się ją znaleźć w Google",
               "parser HTML czyta znaczniki meta, atrybuty alt oraz robots.txt i sitemap.xml.", items)


def check_links(ctx):
    items = []
    soup = ctx.get("soup")
    base = ctx.get("final_url", ctx["url"])
    host = urlparse(base).hostname
    if soup is None:
        return cat("bledy", "Błędy i glitche", "Czy coś się psuje lub źle wyświetla",
                   "sprawdzamy odnośniki wewnętrzne. Pełne wykrywanie błędów JavaScript wymaga modułu przeglądarki.", items)
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
        items.append(F("warn", f"{len(broken)} linków prowadzi donikąd", where="Menu i treść",
                       found=f"Niedziałające odnośniki: {lst}.",
                       m="Klient klika i trafia na stronę z błędem.",
                       f="Popraw adresy linków albo je usuń.", eff="sam"))
    else:
        items.append(F("ok", "Linki wewnętrzne działają", where=f"Sprawdzono {len(seen)} odnośników",
                       found="Żaden sprawdzony link nie zwrócił błędu.",
                       m="Nawigacja po stronie działa.", f="Nic nie trzeba robić."))
    # Czy nieistniejacy adres zwraca 404. Wynik zapisujemy w ctx, bo tego samego
    # pomiaru uzywa pozniej wykrywanie wrazliwych plikow — jedno zapytanie zamiast dwoch.
    losowy = "/" + "".join(random.choices(string.ascii_lowercase, k=16)) + ".txt"
    try:
        pusty = fetch(urljoin(base + "/", losowy.lstrip("/")))
        ctx["soft404"] = (pusty.status_code, len(pusty.content))
        if pusty.status_code == 200:
            items.append(F("warn", "Nieistniejące adresy nie zwracają błędu 404",
                           where="Dowolny błędny adres",
                           found=f"Adres {base}{losowy} zwraca kod 200 zamiast 404.",
                           m="Literówka w adresie pokazuje klientowi zwykłą stronę zamiast informacji o błędzie, a Google indeksuje nieistniejące podstrony.",
                           f="Ustaw serwer tak, aby brakujące adresy zwracały kod 404 i stronę z informacją.", eff="it"))
    except Exception:
        pass

    # Tekst zastepczy zostawiony z szablonu. Dla nowej firmy to najbardziej
    # wstydliwy blad startu i widzi go kazdy odwiedzajacy.
    tresc = soup.get_text(" ", strip=True).lower()
    wypelniacze = [w for w in ("lorem ipsum", "dolor sit amet", "tu wpisz", "przykładowy tekst",
                               "wpisz tutaj", "hello world!") if w in tresc]
    if wypelniacze:
        items.append(F("warn", "Na stronie został tekst zastępczy z szablonu", where="Treść strony",
                       found=f"Znaleziono: {', '.join(wypelniacze)}.",
                       m="Odwiedzający widzi, że strona nie została dokończona.",
                       f="Zastąp tekst zastępczy własną treścią.", eff="sam"))

    items.append(F("ok", "Pełne wykrywanie błędów JS", where="Moduł przeglądarki",
                   found="Błędy konsoli i glitche na żywo wykrywa moduł Playwright (browser_checks.py). Włącz go, aby rozszerzyć ten test.",
                   m="", f=""))
    return cat("bledy", "Błędy i glitche", "Czy coś się psuje lub źle wyświetla",
               "sprawdzamy odnośniki wewnętrzne. Pełne wykrywanie błędów JavaScript włącza moduł przeglądarki.", items)


def check_rodo(ctx):
    items = []
    soup = ctx.get("soup")
    if soup is None:
        return cat("rodo", "Zgodność z RODO i prawem", "Czy strona spełnia wymogi prawne",
                   "szukamy skryptów śledzących, polityki prywatności i klauzul przy formularzach.", items, flag="Rzadko sprawdzane")
    html = str(soup).lower()

    trackers = [t for t in ("google-analytics.com", "googletagmanager.com", "gtag(", "fbevents", "connect.facebook.net")
                if t in html]
    if trackers:
        items.append(F("crit", "Skrypt śledzący ładuje się w kodzie strony", where="sekcja <head>",
                       found=f"Wykryto skrypty śledzące: {', '.join(set(trackers))}. Pasywnie nie da się potwierdzić, czy czekają na zgodę (to sprawdza moduł przeglądarki).",
                       m="Jeśli ładują się przed zgodą na cookies, to naruszenie RODO.",
                       f="Upewnij się, że skrypty śledzące ruszają dopiero po zgodzie użytkownika.", eff="it"))

    has_priv = any(("polityk" in (a.get_text() or "").lower() or "prywatn" in (a.get("href") or "").lower()
                    or "privacy" in (a.get("href") or "").lower()) for a in soup.find_all("a", href=True))
    if has_priv:
        items.append(F("ok", "Jest link do polityki prywatności", where="Strona",
                       found="Znaleziono odnośnik do polityki prywatności.",
                       m="Dokument jest dostępny dla użytkowników.", f="Nic nie trzeba robić."))
    else:
        items.append(F("crit", "Brak polityki prywatności", where="Stopka strony",
                       found="Nie znaleziono linku do polityki prywatności.",
                       m="Prawo wymaga informowania, jak strona przetwarza dane.",
                       f="Dodaj politykę prywatności i link do niej w stopce.", eff="sam"))

    has_cookie = "cookie" in html or "ciasteczk" in html
    forms = soup.find_all("form")
    personal_forms = [fm for fm in forms if fm.find("input", attrs={"type": ["email", "text"]}) or fm.find("textarea")]
    for fm in personal_forms:
        has_consent = bool(fm.find("input", attrs={"type": "checkbox"})) and ("zgod" in fm.get_text().lower())
        if not has_consent:
            items.append(F("warn", "Formularz bez zgody na przetwarzanie danych", where="Formularz na stronie",
                           found="Formularz zbiera dane, ale brak checkboxa zgody i klauzuli informacyjnej.",
                           m="Zbieranie danych bez zgody jest niezgodne z RODO.",
                           f="Dodaj pod formularzem informację i checkbox zgody.", eff="sam"))
            break
    if not has_cookie:
        items.append(F("warn", "Brak informacji o cookies", where="Strona",
                       found="Nie wykryto banera ani informacji o plikach cookies.",
                       m="Strona powinna informować o cookies i pytać o zgodę.",
                       f="Dodaj baner cookies z opcją zgody i odrzucenia.", eff="srednie"))
    return cat("rodo", "Zgodność z RODO i prawem", "Czy strona spełnia wymogi prawne",
               "szukamy skryptów śledzących, polityki prywatności i klauzul przy formularzach.", items, flag="Rzadko sprawdzane")


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
