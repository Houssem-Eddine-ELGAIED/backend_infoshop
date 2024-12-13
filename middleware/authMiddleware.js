const protect = async (req, res, next) => {
  try {
    // Récupérer le token JWT depuis les cookies ou l'en-tête Authorization
    const token = req.cookies.jwt || (req.headers.authorization && req.headers.authorization.split(' ')[1]);

    if (!token) {
      res.status(401);
      throw new Error('Authentication failed: Token not provided.');
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    if (!decodedToken) {
      res.clearCookie('jwt');
      res.status(401);
      throw new Error('Authentication failed: Invalid token.');
    }

    req.user = await User.findById(decodedToken.userId).select('-password');

    if (!req.user) {
      res.clearCookie('jwt');
      res.status(401);
      throw new Error('Authentication failed: User not found.');
    }

    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      res.clearCookie('jwt');
      res.status(401).json({ message: 'Authentication failed: Invalid or expired token.' });
    } else if (error instanceof jwt.TokenExpiredError) {
      res.clearCookie('jwt');
      res.status(401).json({ message: 'Authentication failed: Token expired.' });
    } else {
      res.status(401).json({ message: error.message || 'Authentication failed' });
    }
  }
};
