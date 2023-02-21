const mysql = require("mysql2");
const dotenv = require("dotenv");
dotenv.config();

const connection = mysql.createConnection({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE
});

connection.connect((err, res) => {
    if (err) {
        throw err;
    }
    console.log("Connected to MYSQL DB")
})

module.exports = connection;