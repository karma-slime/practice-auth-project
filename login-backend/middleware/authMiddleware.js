const jwt = require('jsonwebtoken');

// Middleware to authenticate JWT token the bouncer
exports.authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        const error = new Error("Access token required");
        error.statusCode = 401;
        return next(error);
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
        if (err) {
            const error = new Error("Invalid or expired token");
            error.statusCode = 403;
            return next(error);
        }
        req.user = decodedUser;
        next();
    });
}
