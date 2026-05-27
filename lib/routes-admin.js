const express = require('express');
const {
  listUsersWithStats,
  getTotals,
  setAdmin,
  setSuspended,
  deleteUserById,
  isRegistrationEnabled,
  setRegistrationEnabled,
} = require('./admin');

const router = express.Router();

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'Bitte zuerst anmelden.');
    return res.redirect('/login');
  }
  if (!req.session.user.is_admin) {
    return res.status(403).render('404');
  }
  next();
}

router.use(requireAdmin);

router.get('/', async (req, res, next) => {
  try {
    const [totals, users, registrationEnabled] = await Promise.all([
      getTotals(),
      listUsersWithStats(),
      isRegistrationEnabled(),
    ]);
    res.render('admin', {
      totals,
      users,
      registrationEnabled,
      currentUserId: req.session.user.id,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/registration', async (req, res, next) => {
  try {
    const enable = req.body.enable === '1';
    await setRegistrationEnabled(enable);
    req.flash('success', enable ? 'Registrierungen sind jetzt aktiviert.' : 'Registrierungen sind jetzt deaktiviert.');
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/toggle-admin', async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id === req.session.user.id) {
      req.flash('error', 'Du kannst dir nicht selbst die Admin-Rechte entziehen.');
      return res.redirect('/admin');
    }
    const value = req.body.value === '1';
    await setAdmin(id, value);
    req.flash('success', value ? 'Admin-Rechte vergeben.' : 'Admin-Rechte entzogen.');
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/toggle-suspended', async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id === req.session.user.id) {
      req.flash('error', 'Du kannst dich nicht selbst sperren.');
      return res.redirect('/admin');
    }
    const value = req.body.value === '1';
    await setSuspended(id, value);
    req.flash('success', value ? 'Konto gesperrt.' : 'Konto entsperrt.');
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/delete', async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id === req.session.user.id) {
      req.flash('error', 'Du kannst dich nicht selbst löschen.');
      return res.redirect('/admin');
    }
    await deleteUserById(id);
    req.flash('success', 'Konto gelöscht.');
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

module.exports = router;
