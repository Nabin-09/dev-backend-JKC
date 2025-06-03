import db from '../config/db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

// REGISTER USER
export const register = async (req, res) => {
  try {
    const { name, email, password, role = 'user', phone } = req.body;
    
    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name, email, and password are required' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide a valid email address' 
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Check if user already exists
    db.query('SELECT id FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

      if (results.length > 0) {
        return res.status(400).json({ 
          success: false, 
          message: 'User with this email already exists' 
        });
      }

      try {
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user
        db.query(
          'INSERT INTO users (name, email, password, role, phone) VALUES (?, ?, ?, ?, ?)',
          [name, email, hashedPassword, role, phone],
          (err, result) => {
            if (err) {
              console.error('Insert error:', err);
              return res.status(500).json({ 
                success: false, 
                message: 'Failed to create user' 
              });
            }

            res.status(201).json({
              success: true,
              message: 'User registered successfully',
              data: {
                userId: result.insertId,
                name,
                email,
                role
              }
            });
          }
        );
      } catch (hashError) {
        console.error('Password hashing error:', hashError);
        res.status(500).json({ 
          success: false, 
          message: 'Internal server error' 
        });
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

// LOGIN USER
export const login = (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    // Find user by email
    db.query(
      'SELECT id, name, email, password, role FROM users WHERE email = ?', 
      [email], 
      async (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error' 
          });
        }

        if (results.length === 0) {
          return res.status(401).json({ 
            success: false, 
            message: 'Invalid email or password' 
          });
        }

        const user = results[0];

        try {
          // Verify password
          const isPasswordValid = await bcrypt.compare(password, user.password);
          
          if (!isPasswordValid) {
            return res.status(401).json({ 
              success: false, 
              message: 'Invalid email or password' 
            });
          }

          // Generate JWT token
          const token = jwt.sign(
            { 
              userId: user.id, 
              email: user.email, 
              role: user.role 
            },
            JWT_SECRET,
            { expiresIn: '7d' }
          );

          // Return success response with token
          res.json({
            success: true,
            message: 'Login successful',
            data: {
              token: token,
              user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
              }
            }
          });

        } catch (bcryptError) {
          console.error('Password comparison error:', bcryptError);
          res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
          });
        }
      }
    );

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

// GET USER PROFILE (Protected route)
export const getProfile = (req, res) => {
  db.query(
    'SELECT id, name, email, role, phone, created_at FROM users WHERE id = ?',
    [req.user.userId],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error' 
        });
      }

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
    }
  );
};

// CHANGE PASSWORD (Protected route)
export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }

    // Get current user data
    db.query('SELECT password FROM users WHERE id = ?', [userId], async (err, results) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: 'Database error'
        });
      }

      if (results.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      try {
        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, results[0].password);
        
        if (!isCurrentPasswordValid) {
          return res.status(401).json({
            success: false,
            message: 'Current password is incorrect'
          });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        db.query(
          'UPDATE users SET password = ? WHERE id = ?',
          [hashedNewPassword, userId],
          (err, result) => {
            if (err) {
              return res.status(500).json({
                success: false,
                message: 'Failed to update password'
              });
            }

            res.json({
              success: true,
              message: 'Password changed successfully'
            });
          }
        );

      } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};