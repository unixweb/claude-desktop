const BREVO_ENDPOINT = 'https://api.brevo.com/v3/smtp/email';

function parseSender(from) {
  const match = /^\s*(.*?)\s*<\s*([^>]+)\s*>\s*$/.exec(from || '');
  if (match) return { name: match[1] || undefined, email: match[2] };
  return { email: from };
}

async function sendPasswordResetMail(to, resetUrl) {
  const apiKey = process.env.BREVO_API_KEY;
  const from = process.env.MAIL_FROM || 'no-reply@example.com';

  const subject = 'Passwort zurücksetzen';
  const textContent =
    `Hallo,\n\n` +
    `du hast eine Zurücksetzung deines Passworts angefordert.\n` +
    `Klicke auf den folgenden Link, um ein neues Passwort zu vergeben (gültig 1 Stunde):\n\n` +
    `${resetUrl}\n\n` +
    `Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail einfach.\n`;
  const htmlContent =
    `<p>Hallo,</p>` +
    `<p>du hast eine Zurücksetzung deines Passworts angefordert.</p>` +
    `<p><a href="${resetUrl}">Neues Passwort vergeben</a> (gültig 1 Stunde)</p>` +
    `<p>Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail einfach.</p>`;

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

module.exports = { sendPasswordResetMail };
