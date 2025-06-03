import db from '../config/db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

// REGISTER USER - Improved with better debugging
export const register = async (req, res) => {
  console.log('📝 Registration attempt started');
  console.log('📋 Request body:', JSON.stringify(req.body, null, 2));
  
  try {
    const { name, email, password, role = 'user', phone } = req.body;
    
    console.log('📊 Parsed registration data:', {
      name: name || 'MISSING',
      email: email || 'MISSING', 
      passwordLength: password ? password.length : 0,
      role,
      phone: phone || 'not provided'
    });
    
    // Validate required fields
    if (!name || !email || !password) {
      console.log('❌ Validation failed: Missing required fields');
      return res.status(400).json({ 
        success: false, 
        message: 'Name, email, and password are required',
        received: { name: !!name, email: !!email, password: !!password }
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log('❌ Validation failed: Invalid email format');
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide a valid email address' 
      });
    }

    // Validate password length
    if (password.length < 6) {
      console.log('❌ Validation failed: Password too short');
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters long' 
      });
    }

    console.log('✅ Input validation passed');
    console.log('🔍 Checking if user already exists...');

    // Check if user already exists
    const checkUserQuery = 'SELECT id FROM users WHERE email = ?';
    
    db.query(checkUserQuery, [email], async (err, results) => {
      if (err) {
        console.error('❌ Database error during user check:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error during registration',
          debug: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
      }

      console.log('📊 User existence check result:', {
        found: results.length > 0,
        count: results.length
      });

      if (results.length > 0) {
        console.log('❌ User already exists with email:', email);
        return res.status(400).json({ 
          success: false, 
          message: 'User with this email already exists' 
        });
      }

      try {
        console.log('🔐 Hashing password...');
        
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        console.log('✅ Password hashed successfully');
        console.log('💾 Inserting new user into database...');

        // Insert new user
        const insertQuery = 'INSERT INTO users (name, email, password, role, phone) VALUES (?, ?, ?, ?, ?)';
        const insertValues = [name, email, hashedPassword, role, phone];
        
        console.log('📝 Insert query values:', {
          name,
          email,
          passwordHashed: true,
          role,
          phone
        });

        db.query(insertQuery, insertValues, (err, result) => {
          if (err) {
            console.error('❌ Database insert error:', err);
            
            // Handle specific database errors
            if (err.code === 'ER_DUP_ENTRY') {
              return res.status(400).json({
                success: false,
                message: 'User with this email already exists'
              });
            }
            
            if (err.code === 'ER_NO_SUCH_TABLE') {
              return res.status(500).json({
                success: false,
                message: 'Database table not found. Please check database setup.'
              });
            }
            
            return res.status(500).json({ 
              success: false, 
              message: 'Failed to create user',
              debug: process.env.NODE_ENV === 'development' ? err.message : undefined
            });
          }

          console.log('✅ User created successfully with ID:', result.insertId);

          const responseData = {
            success: true,
            message: 'User registered successfully',
            data: {
              userId: result.insertId,
              name,
              email,
              role
            }
          };

          console.log('📤 Sending success response:', responseData);
          res.status(201).json(responseData);
        });

      } catch (hashError) {
        console.error('❌ Password hashing error:', hashError);
        res.status(500).json({ 
          success: false, 
          message: 'Internal server error during password processing',
          debug: process.env.NODE_ENV === 'development' ? hashError.message : undefined
        });
      }
    });

  } catch (error) {
    console.error('❌ Registration error (outer catch):', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// LOGIN USER - Also improved with better debugging
export const login = (req, res) => {
  console.log('🔐 Login attempt started');
  console.log('📋 Request body:', { email: req.body.email, hasPassword: !!req.body.password });
  
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      console.log('❌ Login validation failed: Missing credentials');
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    console.log('🔍 Looking up user by email...');

    // Find user by email
    db.query(
      'SELECT id, name, email, password, role FROM users WHERE email = ?', 
      [email], 
      async (err, results) => {
        if (err) {
          console.error('❌ Database error during login:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error during login',
            debug: process.env.NODE_ENV === 'development' ? err.message : undefined
          });
        }

        console.log('📊 User lookup result:', { found: results.length > 0 });

        if (results.length === 0) {
          console.log('❌ User not found for email:', email);
          return res.status(401).json({ 
            success: false, 
            message: 'Invalid email or password' 
          });
        }

        const user = results[0];
        console.log('👤 User found:', { id: user.id, name: user.name, role: user.role });

        try {
          console.log('🔍 Verifying password...');
          
          // Verify password
          const isPasswordValid = await bcrypt.compare(password, user.password);
          
          console.log('📊 Password verification result:', { valid: isPasswordValid });
          
          if (!isPasswordValid) {
            console.log('❌ Invalid password for user:', email);
            return res.status(401).json({ 
              success: false, 
              message: 'Invalid email or password' 
            });
          }

          console.log('🎫 Generating JWT token...');

          // Generate JWT token
          const tokenPayload = { 
            userId: user.id, 
            email: user.email, 
            role: user.role 
          };
          
          const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });
          
          console.log('✅ Login successful for user:', user.email);

          // Return success response with token
          const responseData = {
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
          };

          console.log('📤 Sending login success response');
          res.json(responseData);

        } catch (bcryptError) {
          console.error('❌ Password comparison error:', bcryptError);
          res.status(500).json({ 
            success: false, 
            message: 'Internal server error during authentication',
            debug: process.env.NODE_ENV === 'development' ? bcryptError.message : undefined
          });
        }
      }
    );

  } catch (error) {
    console.error('❌ Login error (outer catch):', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// GET USER PROFILE (Protected route)
export const getProfile = (req, res) => {
  console.log('👤 Profile request for user ID:', req.user.userId);
  
  db.query(
    'SELECT id, name, email, role, phone, created_at FROM users WHERE id = ?',
    [req.user.userId],
    (err, results) => {
      if (err) {
        console.error('❌ Database error getting profile:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error',
          debug: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
      }

      if (results.length === 0) {
        console.log('❌ User not found for ID:', req.user.userId);
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }

      console.log('✅ Profile retrieved successfully');
      res.json({
        success: true,
        data: results[0]
      });
    }
  );
};

// CHANGE PASSWORD (Protected route)
export const changePassword = async (req, res) => {
  console.log('🔐 Password change request for user ID:', req.user.userId);
  
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;

    if (!currentPassword || !newPassword) {
      console.log('❌ Password change validation failed: Missing passwords');
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 6) {
      console.log('❌ New password too short');
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }

    console.log('🔍 Getting current user password...');

    // Get current user data
    db.query('SELECT password FROM users WHERE id = ?', [userId], async (err, results) => {
      if (err) {
        console.error('❌ Database error during password change:', err);
        return res.status(500).json({
          success: false,
          message: 'Database error',
          debug: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
      }

      if (results.length === 0) {
        console.log('❌ User not found during password change');
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      try {
        console.log('🔍 Verifying current password...');
        
        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, results[0].password);
        
        if (!isCurrentPasswordValid) {
          console.log('❌ Current password verification failed');
          return res.status(401).json({
            success: false,
            message: 'Current password is incorrect'
          });
        }

        console.log('🔐 Hashing new password...');
        
        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        console.log('💾 Updating password in database...');

        // Update password
        db.query(
          'UPDATE users SET password = ? WHERE id = ?',
          [hashedNewPassword, userId],
          (err, result) => {
            if (err) {
              console.error('❌ Database error updating password:', err);
              return res.status(500).json({
                success: false,
                message: 'Failed to update password',
                debug: process.env.NODE_ENV === 'development' ? err.message : undefined
              });
            }

            console.log('✅ Password changed successfully for user ID:', userId);
            res.json({
              success: true,
              message: 'Password changed successfully'
            });
          }
        );

      } catch (error) {
        console.error('❌ Password change error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error',
          debug: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
      }
    });

  } catch (error) {
    console.error('❌ Change password error (outer catch):', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};