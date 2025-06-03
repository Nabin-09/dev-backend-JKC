import db from '../config/db.js';

// GET all users
export const getUsers = (req, res) => {
  db.query('SELECT id, name, email, role, phone, created_at FROM users', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({
      success: true,
      data: results
    });
  });
};

// GET all leads
export const getLeads = (req, res) => {
  db.query('SELECT * FROM leads', (err, results) => {
    if (err) return res.status(500).json({ 
      success: false,
      error: err.message 
    });
    res.json({
      success: true,
      data: results
    });
  });
};

// GET single user by ID
export const getUserById = (req, res) => {
  const { id } = req.params;
  
  db.query('SELECT id, name, email, role, phone, created_at FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return res.status(500).json({ 
      success: false,
      error: err.message 
    });
    
    if (results.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }
    
    res.json({
      success: true,
      data: results[0]
    });
  });
};