import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT token
export const verifyToken = (req, res, next) => {
  // Get token from header
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.startsWith('Bearer ') 
    ? authHeader.substring(7) 
    : null;

  // Check if token exists
  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access denied. No token provided.' 
    });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Add user info to request object
    next(); // Continue to the next middleware/route handler
  } catch (error) {
    console.error('Token verification error:', error);
    
    // Handle different types of JWT errors
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token has expired'
      });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    } else {
      return res.status(400).json({
        success: false,
        message: 'Token verification failed'
      });
    }
  }
};

// Middleware to check if user has admin role
export const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Admin role required.'
    });
  }
  next();
};

// Middleware to check if user has specific role
export const verifyRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required roles: ${allowedRoles.join(', ')}`
      });
    }
    next();
  };
};

// Middleware to check if user is accessing their own data
export const verifyOwnership = (req, res, next) => {
  const requestedUserId = parseInt(req.params.id);
  const currentUserId = req.user.userId;
  
  // Allow admins to access any user's data
  if (req.user.role === 'admin') {
    return next();
  }
  
  // Check if user is accessing their own data
  if (requestedUserId !== currentUserId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied. You can only access your own data.'
    });
  }
  
  next();
};