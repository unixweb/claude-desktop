const nodemailer = require('nodemailer');

let transporter;

function getTransporter() {
  if (transporter) return transporter;

  if (!process.env.BREVO_SMTP_USER || !process.env.BREVO_SMTP_KEY) {
    console.warn('[mailer] Brevo nicht konfiguriert – Mails werden auf der Konsole ausgegeben.');
    transporter = {
      sendMail: async (opts) => {
        console.log('\n========== DEV-MAIL ==========');
        console.log('An:     ', opts.to);
        console.log('Betreff:', opts.subject);
        console.log('Text:\n' + opts.text);
        console.log('==============================\n');
        return { messageId: 'dev-' + Date.now() };
      },
    };
    return transporter;
  }

  transporter = nodemailer.createTransport({
    host: process.env.BREVO_SMTP_HOST || 'smtp-relay.brevo.com',
    port: Number(process.env.BREVO_SMTP_PORT || 587),
    secure: false,
    auth: {
      user: process.env.BREVO_SMTP_USER,
      pass: process.env.BREVO_SMTP_KEY,
    },
  });

  return transporter;
}

async function sendPasswordResetMail(to, resetUrl) {
  const t = getTransporter();
  await t.sendMail({
    from: process.env.MAIL_FROM || 'no-reply@example.com',
    to,
    subject: 'Passwort zurücksetzen',
    text:
      `Hallo,\n\n` +
      `du hast eine Zurücksetzung deines Passworts angefordert.\n` +
      `Klicke auf den folgenden Link, um ein neues Passwort zu vergeben (gültig 1 Stunde):\n\n` +
      `${resetUrl}\n\n` +
      `Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail einfach.\n`,
    html:
      `<p>Hallo,</p>` +
      `<p>du hast eine Zurücksetzung deines Passworts angefordert.</p>` +
      `<p><a href="${resetUrl}">Neues Passwort vergeben</a> (gültig 1 Stunde)</p>` +
      `<p>Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail einfach.</p>`,
  });
}

module.exports = { sendPasswordResetMail };
