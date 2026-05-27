# Login Web App

Einfache Login-Web-App mit Registrierung und Passwort-Reset per E-Mail.

## Features

- Registrierung mit E-Mail und Passwort (bcrypt-Hashing)
- Anmeldung mit Session-Cookies
- Passwort-Reset per E-Mail (Token, 1h gültig)
- Geschütztes Dashboard
- SQLite als lokale Datenbank

## Setup

```bash
npm install
cp .env.example .env
# .env bearbeiten und SMTP-Daten eintragen
npm start
```

Ohne SMTP-Konfiguration werden Reset-Mails im Dev-Modus auf der Konsole ausgegeben –
praktisch zum lokalen Testen.

Standard-URL: http://localhost:3000

## Routen

| Methode | Pfad                      | Zweck                            |
|---------|---------------------------|----------------------------------|
| GET     | `/register`               | Registrierungsformular           |
| POST    | `/register`               | Neues Konto anlegen              |
| GET     | `/login`                  | Login-Formular                   |
| POST    | `/login`                  | Anmelden                         |
| POST    | `/logout`                 | Abmelden                         |
| GET     | `/forgot-password`        | Reset-Anforderung                |
| POST    | `/forgot-password`        | Reset-Mail versenden             |
| GET     | `/reset-password/:token`  | Neues Passwort vergeben          |
| POST    | `/reset-password/:token`  | Passwort aktualisieren           |
| GET     | `/dashboard`              | Geschützter Bereich              |

## Sicherheitshinweise

- `SESSION_SECRET` in `.env` durch zufälligen String ersetzen
- Für Produktion HTTPS verwenden und `cookie.secure = true` setzen
- Reset-Token sind 32 Byte zufällig, einmalig verwendbar, 1h gültig
- "E-Mail nicht gefunden" wird nicht offengelegt (User-Enumeration vermieden)
