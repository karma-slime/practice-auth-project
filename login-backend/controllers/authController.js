const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const catchAsync = require('../utils/catchAsync');

exports.register = catchAsync(async (req, res, next) => {
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
        } catch (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                const customErr = new Error("Email already exists");
                customErr.statusCode = 400;
                return next(customErr);
            }
            next(err);
        }
    });

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

        const [rows] = await db.query('SELECT * FROM user WHERE email = ?', [email]);
        
        if (rows.length === 0) {
            const error = new Error("Invalid email or password");
            error.statusCode = 401;
            return next(error);
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            const error = new Error("Invalid email or password");
            error.statusCode = 401;
            return next(error);
        }

        const token = jwt.sign(
            { id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' }
        );
        res.status(200).json({ message: "Login successful", token: token });
        
    });