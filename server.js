import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import userRoutes from './routes/userRoutes.js';
import authRoutes from './routes/authRoutes.js';
import productRoutes from './routes/productRoutes.js'; // 👈 Added
import './config/db.js'; // Initialize database connection

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging middleware (optional)
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Routes
app.use('/api/auth', authRoutes);    // Authentication routes
app.use('/api', userRoutes);         // User routes
app.use('/api', productRoutes);      // 👈 Product and variant routes

// Health check route
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'CRM API is running!',
    data: {
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    }
  });
});

// API info route
app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'CRM API v1.0.0',
    data: {
      endpoints: {
        auth: {
          register: 'POST /api/auth/register',
          login: 'POST /api/auth/login',
          profile: 'GET /api/auth/profile',
          changePassword: 'PUT /api/auth/change-password',
          logout: 'POST /api/auth/logout',
          verify: 'GET /api/auth/verify'
        },
        users: {
          getAllUsers: 'GET /api/users',
          getUserById: 'GET /api/users/:id',
          getAllLeads: 'GET /api/leads'
        },
        products: {
          create: 'POST /api/products',
          getAll: 'GET /api/products',
          getById: 'GET /api/products/:id',
          update: 'PUT /api/products/:id',
          delete: 'DELETE /api/products/:id'
        },
        variants: {
          create: 'POST /api/products/:productId/variants',
          getAllForProduct: 'GET /api/products/:productId/variants',
          getById: 'GET /api/variants/:id',
          update: 'PUT /api/variants/:id',
          delete: 'DELETE /api/variants/:id'
        }
      }
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    data: {
      requestedPath: req.originalUrl,
      method: req.method
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    data: {
      error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    }
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(` Server is running on port ${PORT}`);
  console.log(` Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(` API URL: http://localhost:${PORT}`);
});
