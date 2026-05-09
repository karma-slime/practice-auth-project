const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

app.use(cors({
    origin: 'http://127.0.0.1:5500', // replace with your frontend URL
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: "Too many login attempts, please try again later",
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
        res.setHeader('Access-Control-Allow-Origin', 'http://127.0.0.1:5500');
        res.status(options.statusCode).json({ message: options.message });
    }

});

app.use('/login', authLimiter);
app.use('/register', authLimiter);

// db connection details / pooling for better performance and handling multiple connections
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root', // replace with user name once created
    password: process.env.DB_PASSWORD || '', // replace with password once added
    database: process.env.DB_NAME || 'user_auth',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// connection initializer to verify database connectivity on server start
db.getConnection((err, connection) => {
    if (err) {
        console.error("Database connection failed: ", err.stack);
        return;
    }
    console.log("Connected to mysql database as id " + connection.threadId);
    connection.release();
});

const pool = db.promise();

module.exports = { pool };

// centralized config for environment variables and database connection details
const config = {
    env: process.env.NODE_ENV || 'development',
    port: process.env.PORT || 5000,
    jwtSecret: process.env.JWT_SECRET,
    db: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        connectionLimit: process.env.NODE_ENV === 'production' ? 50 : 10
    }
};

module.exports = config;

// test route to check if server is running
db.on('error', (err) => {
    console.error("Database error: ", err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.error("Database connection was closed. (you might need to restart the server)");
        return;
    } 
    console.error("Unexpected database error: ", err);
});

// Health check
app.get('/', (req, res) => {
    res.status(200).send("Backend server is running!");
});

app.get('/test-db', catchAsync(async (req, res) => {
    await db.query('SELECT 1 AS result');
    res.status(200).send("Database connection is working!");
}));

// Middleware to authenticate JWT token the bouncer
function authenticateToken(req, res, next) {
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

// Post registration request handler
app.post('/register', catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        const error = new Error("Email and password are required");
        error.statusCode = 400;
        return next(error);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    try{
        await db.query('INSERT INTO user (email, password) VALUES (?, ?)', [email, hashedPassword]);
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        if (err.code === 'ER_DUP_ENTRY') {
            const error = new Error("Email already exists");
            error.statusCode = 400;
            return next(error);
        }
        next(error);
    }
}));

// Post login request handler
app.post('/login', catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    const [rows] = await db.query('SELECT * FROM user WHERE email = ?', [email]);
    
    if (rows.length === 0) {
        const error = new Error("Invalid email or password");
        error.statusCode = 401;
        throw error;
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        const error = new Error("Invalid email or password");
        error.statusCode = 401;
        throw error;
    }

    const token = jwt.sign(
        { id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: "Login successful", token: token });
    }));

// Example of a protected route
app.get('/test-token', authenticateToken, (req, res) => {
   res.status(200).json({ message: "Token is valid", user: req.user });
});

//start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log("Server is running on http://localhost:" + PORT);
});