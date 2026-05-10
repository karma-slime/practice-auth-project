const helmet = require('helmet');
const morgan = require('morgan');
const express = require('express');
const cors = require('cors');

require('dotenv').config();

// importing config, db connection, routes and middleware
const authRoutes = require('./routes/authRoutes');
const globalErrorHandler = require('./middleware/errorHandler');
const { authenticateToken } = require('./middleware/authMiddleware');

const app = express();
app.use(helmet());
app.use(morgan('dev'));

// CORS configuration to allow requests from the frontend
app.use(cors({
    origin: 'http://127.0.0.1:5500', // replace with your frontend URL
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// routes
app.use('/api/v1/auth', authRoutes);

// Example of a protected route
app.get('/api/v1/test-token', authenticateToken, (req, res) => {
   res.status(200).json({ message: "Token is valid", user: req.user });
});

// Health check
app.get('/', (req, res) => {
    res.status(200).send("Backend server is running!");
});

// global error handler
app.use(globalErrorHandler);

//start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log("Server is running on http://localhost:" + PORT);
});