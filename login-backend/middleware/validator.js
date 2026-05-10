const {z} = require('zod');

// Validation schema for registration
const registerSchema = z.object({
    email: z.string().email("Invalid email address").min(5).max(255),
    password: z.string().min(6, "Password must be at least 6 characters long").max(100),
});

// Validation schema for login
const loginSchema = z.object({
    email: z.string().email("Invalid email address"),
    password: z.string().min(6, "Password must be at least 6 characters long").max(100),
});

// Middleware for validating data
const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (err) {
        const errorMessage = err.issues
        ? err.issues.map(issue => issue.message).join(', ')
        : "Validation failed";
        
        const error = new Error(errorMessage);
        error.statusCode = 400;
        next(error);
    }
};

module.exports = { registerSchema, loginSchema, validate };