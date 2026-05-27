try { require('dotenv').config(); } catch (_) {}
const app = require('./lib/app');

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Login-App läuft auf http://localhost:${PORT}`);
});
