# Czujka

Audyt strony WWW dla małego biznesu. Wklejasz link, dostajesz prosty raport po polsku:
gdzie jest problem, co dokładnie jest nie tak, jak to poprawić i od czego zacząć.

To jest działająca aplikacja, nie atrapa. Po uruchomieniu backendu skan jest prawdziwy.

## Uruchomienie (podstawowe, skan pasywny)

```bash
cd czujka
pip install -r requirements.txt
uvicorn app:app --port 8000
```

Otwórz `http://localhost:8000`, wpisz adres i kliknij Skanuj.
Plakietka w rogu pokazuje tryb: "Na żywo" (prawdziwy skan) albo "Demo" (gdy backend niedostępny).

Można też skorzystać ze skrótu:

```bash
./run.sh
```

## Co sprawdza skan pasywny (legalny z każdego URL)

Czyta tylko to, co strona sama oddaje przeglądarce.

- Dostępność: kod odpowiedzi HTTP, czas odpowiedzi
- Bezpieczeństwo: wymuszanie HTTPS, certyfikat TLS (data wygaśnięcia, wystawca),
  nagłówki (HSTS, CSP, X-Frame-Options, ujawnianie wersji serwera),
  publiczne wrażliwe pliki (`/.env`, `/.git/config`, kopie zapasowe)
- Błędy: sprawdzenie linków wewnętrznych (martwe odnośniki)
- Wydajność i widoczność: tytuł, opis meta, atrybuty `alt`, rozmiar HTML, `sitemap.xml`
- RODO: skrypty śledzące w kodzie, link do polityki prywatności, baner cookies,
  klauzula zgody przy formularzach

## Moduł przeglądarki (opcjonalny, też pasywny)

Łapie to, czego nie widać z samego HTML: błędy JavaScript, nieudane żądania,
rozjeżdżający się układ na telefonie.

```bash
pip install playwright
playwright install chromium
```

Po instalacji moduł włącza się sam i rozszerza kategorię "Błędy i glitche".

## Tryb aktywny (logika i nadużycia) - tylko za zgodą

Ten moduł realnie wysyła żądania, żeby sprawdzić limity i błędy logiczne
(np. brak limitu tworzenia paszportów DPP, dostęp do cudzego zasobu przez
zmianę numeru w adresie, brak ochrony przed botami).

WAŻNE: wolno go uruchamiać wyłącznie na własnej stronie (najlepiej na kopii/stagingu)
albo za pisemną zgodą właściciela. Dlatego jest schowany za tokenem:

```bash
export CZUJKA_AUTH_TOKEN=twoj-sekret
# wywołanie: /api/scan?url=...&mode=full&token=twoj-sekret
```

## Pliki

```
app.py             serwer FastAPI, serwuje interfejs i /api/scan
scanner.py         silnik skanu pasywnego + ocena + budowa raportu
browser_checks.py  opcjonalny moduł Playwright (błędy JS, glitche)
logic_checks.py    tryb aktywny (logika, nadużycia), za tokenem
frontend/index.html  interfejs; łączy się z /api/scan, w razie braku backendu działa jako demo
requirements.txt
run.sh
```

## Czego tu jeszcze nie ma (następne kroki)

- konta użytkowników, logowanie, zapisywanie i historia raportów
- weryfikacja własności domeny (plik na serwerze albo rekord DNS) przed trybem aktywnym
- płatności i abonament
- kolejka zadań dla wielu skanów naraz
- pełne testy specyficzne dla strony w module logiki (wskazanie konkretnego formularza)
