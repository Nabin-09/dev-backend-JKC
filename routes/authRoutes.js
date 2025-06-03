import express from 'express';
import { register, login, getProfile, changePassword } from '../controllers/authController.js';
import { verifyToken } from '../middleware/auth.js';

const router = express.Router();

// Public routes (no authentication required)
router.post('/register', register);
router.post('/login', login);

// Protected routes (authentication required)
router.get('/profile', verifyToken, getProfile);
router.put('/change-password', verifyToken, changePassword);

// Logout route (optional - mainly handled on frontend)
router.post('/logout', verifyToken, (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully',
    data: {
      message: 'Please remove the token from your client storage'
    }
  });
});

// Verify token route (useful for frontend to check if token is valid)
router.get('/verify', verifyToken, (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      user: {
        userId: req.user.userId,
        email: req.user.email,
        role: req.user.role
      }
    }
  });
});

export default router;