module.exports = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || "error";

    console.error("Error: ", err);

    res.status(err.statusCode).json({
        status: err.status,
        message: err.message || "Internal Server Error"
    });    
};