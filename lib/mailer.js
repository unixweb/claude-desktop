const BREVO_ENDPOINT = 'https://api.brevo.com/v3/smtp/email';

function parseSender(from) {
  const match = /^\s*(.*?)\s*<\s*([^>]+)\s*>\s*$/.exec(from || '');
  if (match) return { name: match[1] || undefined, email: match[2] };
  return { email: from };
}

async function sendMail({ to, subject, textContent, htmlContent }) {
  const apiKey = process.env.BREVO_API_KEY;
  const from = process.env.MAIL_FROM || 'no-reply@example.com';

  if (!apiKey) {
    console.warn('[mailer] BREVO_API_KEY nicht gesetzt – Mail wird auf der Konsole ausgegeben.');
    console.log('\n========== DEV-MAIL ==========');
    console.log('An:     ', to);
    console.log('Betreff:', subject);
    console.log('Text:\n' + textContent);
    console.log('==============================\n');
    return;
  }

  const res = await fetch(BREVO_ENDPOINT, {
    method: 'POST',
    headers: {
      'api-key': apiKey,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      sender: parseSender(from),
      to: [{ email: to }],
      subject,
      textContent,
      htmlContent,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Brevo API ${res.status}: ${body}`);
  }
}

async function sendPasswordResetMail(to, resetUrl) {
  await sendMail({
    to,
    subject: 'Passwort zurücksetzen',
    textContent:
      `Hallo,\n\n` +
      `du hast eine Zurücksetzung deines Passworts angefordert.\n` +
      `Klicke auf den folgenden Link, um ein neues Passwort zu vergeben (gültig 1 Stunde):\n\n` +
      `${resetUrl}\n\n` +
      `Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail einfach.\n`,
    htmlContent:
      `<p>Hallo,</p>` +
      `<p>du hast eine Zurücksetzung deines Passworts angefordert.</p>` +
      `<p><a href="${resetUrl}">Neues Passwort vergeben</a> (gültig 1 Stunde)</p>` +
      `<p>Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail einfach.</p>`,
  });
}

async function sendVerificationMail(to, verifyUrl) {
  await sendMail({
    to,
    subject: 'Bitte bestätige deine E-Mail-Adresse',
    textContent:
      `Hallo,\n\n` +
      `vielen Dank für deine Registrierung bei mygopage.de.\n` +
      `Bitte bestätige deine E-Mail-Adresse, indem du auf den folgenden Link klickst (gültig 24 Stunden):\n\n` +
      `${verifyUrl}\n\n` +
      `Sobald deine Adresse bestätigt ist, kannst du dich anmelden und Kurz-Links erstellen.\n\n` +
      `Wenn du dich nicht registriert hast, ignoriere diese E-Mail einfach.\n`,
    htmlContent:
      `<p>Hallo,</p>` +
      `<p>vielen Dank für deine Registrierung bei <strong>mygopage.de</strong>.</p>` +
      `<p>Bitte bestätige deine E-Mail-Adresse:</p>` +
      `<p><a href="${verifyUrl}" style="display:inline-block;background:#667eea;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">E-Mail bestätigen</a></p>` +
      `<p style="color:#666;font-size:13px">Der Link ist 24 Stunden gültig. Wenn du dich nicht registriert hast, ignoriere diese E-Mail einfach.</p>`,
  });
}

module.exports = { sendPasswordResetMail, sendVerificationMail };
