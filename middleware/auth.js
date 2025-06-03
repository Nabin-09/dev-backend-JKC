import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT token
export const verifyToken = (req, res, next) => {
  console.log(' Token verification started');
  
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') 
    ? authHeader.slice(7) 
    : null;

  console.log('Auth header present:', !!authHeader);
  console.log('Token extracted:', !!token);

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({
      success: false,
      message: 'Access denied. No token provided.'
    });
  }

  try {
    console.log('Verifying token...');
    const decoded = jwt.verify(token, JWT_SECRET);
    
    console.log('Token verified successfully for user:', decoded.userId);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification failed:', error.message);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token has expired'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
    
    return res.status(401).json({
      success: false,
      message: 'Token verification failed'
    });
  }
};

// Middleware to verify admin role
export const verifyAdmin = (req, res, next) => {
  console.log('🔐 Admin verification for user:', req.user.userId, 'Role:', req.user.role);
  
  if (req.user.role !== 'admin') {
    console.log('❌ Access denied - not admin');
    return res.status(403).json({
      success: false,
      message: 'Access denied. Admin privileges required.'
    });
  }
  
  console.log('✅ Admin access granted');
  next();
};

// Middleware to verify specific roles
export const verifyRole = (allowedRoles) => {
  return (req, res, next) => {
    console.log('🔐 Role verification for user:', req.user.userId);
    console.log('👤 User role:', req.user.role);
    console.log('✅ Allowed roles:', allowedRoles);
    
    if (!allowedRoles.includes(req.user.role)) {
      console.log('❌ Access denied - insufficient role');
      return res.status(403).json({
        success: false,
        message: `Access denied. Required roles: ${allowedRoles.join(', ')}`
      });
    }
    
    console.log('✅ Role access granted');
    next();
  };
};

// Middleware to verify user can only access their own data
export const verifyOwnership = (req, res, next) => {
  console.log(' Ownership verification');
  console.log('Requesting user ID:', req.user.userId);
  console.log('Target resource ID:', req.params.id);
  
  const requestedUserId = parseInt(req.params.id);
  const currentUserId = req.user.userId;
  
  // Admin can access any user's data
  if (req.user.role === 'admin') {
    console.log(' Admin override - access granted');
    return next();
  }
  
  // User can only access their own data
  if (currentUserId !== requestedUserId) {
    console.log('Access denied - not owner');
    return res.status(403).json({
      success: false,
      message: 'Access denied. You can only access your own data.'
    });
  }
  
  console.log('Ownership verified');
  next();
};