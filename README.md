# Login Web App (Vercel + Neon + Brevo)

Einfache Login-Web-App mit Registrierung, Welcome-Mail und
Passwort-Reset per E-Mail. Läuft als Serverless Function auf Vercel.

## Features

- Registrierung mit E-Mail und Passwort (bcrypt, 12 Runden)
- Welcome-Mail nach erfolgreicher Registrierung
- Cookie-basierte Sessions (stateless, serverless-tauglich)
- Passwort-Reset per E-Mail (32-Byte-Token, 1h gültig, einmalig nutzbar)
- Neon Postgres als Datenbank (Tabellen werden lazy via `CREATE TABLE IF NOT EXISTS` angelegt)
- Brevo REST-API für E-Mail-Versand (kein SMTP nötig)
- Schutz vor User-Enumeration (gleiche Antwort bei Forgot-Password)
- `trust proxy` aktiviert, damit Secure-Cookies hinter dem Vercel-Edge funktionieren

## Tech Stack

- Node.js / Express
- `@vercel/postgres` (kompatibel mit Neon-Connection-String)
- `cookie-session` (keine Server-State, perfekt für Serverless)
- `bcryptjs`
- `ejs` für Views
- Brevo Transactional Email API via native `fetch`

## Deployment auf Vercel

### 1. Repository verbinden

Vercel Dashboard → **Add New → Project → Import Git Repository** → diesen
Branch wählen. Framework Preset: **Other** (Vercel erkennt `vercel.json`).

### 2. Neon Postgres anbinden

Vercel Postgres wurde eingestellt und durch Marketplace-Provider ersetzt.
Empfehlung: **Neon**.

1. Projekt → **Storage → Browse Marketplace → Neon → Add Integration**
2. Plan: **Free**
3. Region möglichst nahe zur Function-Region (z. B. `eu-central-1` ↔ `fra1`)
4. Beim Verbinden: Projekt anhaken, alle Environments (Production / Preview / Development)

Neon setzt automatisch `POSTGRES_URL`, `POSTGRES_URL_NON_POOLING`,
`POSTGRES_HOST`, `POSTGRES_PASSWORD`, etc. Beim ersten Request werden die
Tabellen automatisch angelegt.

### 3. Brevo API-Key

https://app.brevo.com/settings/keys/api → **Create new API key** → kopieren.

### 4. Env-Vars in Vercel

**Settings → Environment Variables** (für Production + Preview):

| Variable         | Wert                                                | Pflicht |
|------------------|-----------------------------------------------------|---------|
| `POSTGRES_URL`   | Wird durch die Neon-Integration gesetzt             | ✅      |
| `SESSION_SECRET` | Langer Zufallsstring (`openssl rand -hex 32`)       | ✅      |
| `BREVO_API_KEY`  | Brevo API-Key (beginnt mit `xkeysib-`)              | ✅      |
| `MAIL_FROM`      | `Login App <no-reply@deine-domain.de>` (in Brevo verifiziert!) | ✅ |
| `APP_URL`        | `https://dein-projekt.vercel.app` (sonst aus Request-Headern) | optional |
| `DEBUG_ERRORS`   | `1` lässt 500-Stacks im Browser anzeigen (nur zum Debuggen) | optional |

Die Absenderadresse in `MAIL_FROM` muss in Brevo als **Sender** oder
verifizierte **Domain** eingetragen sein, sonst lehnt Brevo den Versand ab.

### 5. Deploy

Push auf den Branch → Vercel deployt automatisch. Wenn du Env-Vars
**nach** dem letzten Deploy hinzufügst: **Deployments → ⋯ → Redeploy**.

## Lokale Entwicklung

```bash
npm install
vercel link            # Projekt verknüpfen
vercel env pull        # zieht alle Env-Vars in .env.local
npm run dev            # via `vercel dev`
# oder ohne vercel CLI:
cp .env.example .env   # POSTGRES_URL + Brevo-Keys ergänzen
npm start              # direkt mit `node local.js`
```

Ohne `BREVO_API_KEY` landen alle Mails auf der Konsole (Dev-Modus).

## Routen

| Methode | Pfad                     | Zweck                                  |
|---------|--------------------------|----------------------------------------|
| GET     | `/register`              | Registrierungsformular                 |
| POST    | `/register`              | Neues Konto anlegen, Welcome-Mail senden |
| GET     | `/login`                 | Login-Formular                         |
| POST    | `/login`                 | Anmelden                               |
| POST    | `/logout`                | Abmelden                               |
| GET     | `/forgot-password`       | Reset-Anforderung                      |
| POST    | `/forgot-password`       | Reset-Mail versenden                   |
| GET     | `/reset-password/:token` | Neues Passwort vergeben                |
| POST    | `/reset-password/:token` | Passwort aktualisieren                 |
| GET     | `/dashboard`             | Geschützter Bereich                    |

## Projektstruktur

```
api/index.js          Vercel-Function-Entrypoint (re-exportiert lib/app.js)
local.js              Lokaler Dev-Entrypoint (express.listen)
lib/app.js            Express-App: Routen, Middleware, Sessions
lib/db.js             Postgres-Zugriff + Schema-Init
lib/mailer.js         Brevo API Wrapper (Welcome- und Reset-Mail)
views/                EJS-Templates
public/style.css      Stylesheet
vercel.json           Build- und Routing-Config
```

## Troubleshooting

**Internal Server Error nach Submit**
- `DEBUG_ERRORS=1` setzen → Redeploy → Stacktrace erscheint im Browser
- Runtime-Logs im Vercel-Dashboard → Functions → `api/index.js`

**Login redirected zurück auf /login statt /dashboard**
- `trust proxy` ist gesetzt — falls jemand das ändert: ohne diese Zeile
  verwirft `cookie-session` mit `secure: true` das Cookie hinter dem
  Vercel-Proxy

**Mail kommt nicht an**
- Brevo Dashboard → **Transactional → Logs** zeigt jeden Sendeversuch
- Absender in `MAIL_FROM` muss als Sender/Domain in Brevo verifiziert sein
- Spam-Ordner prüfen

**User löschen / DB direkt bearbeiten**
- Neon Console → **SQL Editor**
- z. B. `DELETE FROM users WHERE email = 'foo@example.com';`
