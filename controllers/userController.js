const db = require('../config/db');

// GET all users
exports.getUsers = (req, res) => {
  db.query('SELECT * FROM users', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
};

// GET all leads
exports.getLeads = (req, res) => {
  db.query('SELECT * FROM leads', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
};

