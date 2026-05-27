# Login Web App (Vercel + Postgres + Brevo)

Einfache Login-Web-App mit Registrierung und Passwort-Reset per E-Mail.
Deployt als Serverless Function auf Vercel.

## Features

- Registrierung mit E-Mail und Passwort (bcrypt, 12 Runden)
- Cookie-basierte Sessions (stateless, serverless-tauglich)
- Passwort-Reset per E-Mail (32-Byte-Token, 1h gültig, einmalig nutzbar)
- Vercel Postgres als Datenbank
- Brevo SMTP für E-Mail-Versand
- Schutz vor User-Enumeration (gleiche Antwort bei Forgot-Password)

## Deployment auf Vercel

### 1. Repository verbinden

Im Vercel-Dashboard: **Add New → Project → Import Git Repository**, dann
diesen Branch wählen.

### 2. Vercel Postgres anlegen

Im Projekt unter **Storage → Create Database → Postgres**. Vercel setzt
automatisch alle `POSTGRES_*` Env-Vars. Beim ersten Request werden die
Tabellen via `CREATE TABLE IF NOT EXISTS` angelegt.

### 3. Brevo SMTP konfigurieren

Brevo-Konto erstellen → https://app.brevo.com/settings/keys/smtp →
SMTP-Login + Key kopieren. In Vercel unter **Settings → Environment
Variables** eintragen:

| Variable           | Wert                                          |
|--------------------|-----------------------------------------------|
| `SESSION_SECRET`   | langer Zufallsstring (z. B. `openssl rand -hex 32`) |
| `BREVO_SMTP_USER`  | dein Brevo SMTP-Login                          |
| `BREVO_SMTP_KEY`   | dein Brevo SMTP-Key                            |
| `MAIL_FROM`        | `Login App <no-reply@deine-domain.de>`         |
| `APP_URL`          | `https://dein-projekt.vercel.app` (optional)   |

Die Absenderadresse muss in Brevo als Sender verifiziert sein.

### 4. Deploy

Push auf den Branch → Vercel deployt automatisch.

## Lokale Entwicklung

```bash
npm install
vercel link            # Projekt verknüpfen
vercel env pull        # .env.local von Vercel ziehen
cp .env.example .env   # ergänzen falls nötig
npm run dev            # via `vercel dev`
# oder
npm start              # ohne vercel dev (braucht POSTGRES_URL in .env)
```

Ohne Brevo-Credentials landen Reset-Mails auf der Konsole.

## Routen

| Methode | Pfad                     | Zweck                       |
|---------|--------------------------|-----------------------------|
| GET     | `/register`              | Registrierungsformular      |
| POST    | `/register`              | Neues Konto anlegen         |
| GET     | `/login`                 | Login-Formular              |
| POST    | `/login`                 | Anmelden                    |
| POST    | `/logout`                | Abmelden                    |
| GET     | `/forgot-password`       | Reset-Anforderung           |
| POST    | `/forgot-password`       | Reset-Mail versenden        |
| GET     | `/reset-password/:token` | Neues Passwort vergeben     |
| POST    | `/reset-password/:token` | Passwort aktualisieren      |
| GET     | `/dashboard`             | Geschützter Bereich         |
