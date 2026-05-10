const mysql = require('mysql2/promise');
require('dotenv').config();

// db connection details / pooling for better performance and handling multiple connections
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root', // replace with user name once created
    password: process.env.DB_PASSWORD, // replace with password once added
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: process.env.NODE_ENV === 'production' ? 50 : 10,
    queueLimit: 0
});

// connection initializer to verify database connectivity on server start
pool.getConnection((err, connection) => {
    if (err) {
        console.error("Database connection failed: ", err.stack);
        return;
    }
    console.log("Connected to mysql database as id " + connection.threadId);
    connection.release();
});

module.exports = pool;