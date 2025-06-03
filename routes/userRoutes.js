import express from 'express';
import { getUsers, getLeads, getUserById } from '../controllers/userController.js';
import { verifyToken, verifyAdmin, verifyRole, verifyOwnership } from '../middleware/auth.js';

const router = express.Router();

// Protected routes - require authentication
router.get('/users', verifyToken, getUsers);
router.get('/users/:id', verifyToken, verifyOwnership, getUserById);
router.get('/leads', verifyToken, getLeads);

// Admin only routes
router.get('/admin/users', verifyToken, verifyAdmin, getUsers);

// Role-based access examples
router.get('/manager/leads', verifyToken, verifyRole(['admin', 'manager']), getLeads);

export default router;