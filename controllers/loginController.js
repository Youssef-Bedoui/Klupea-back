const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const db = require("../database"); // Import the database connection
require("dotenv").config();

const login = (req, res) => {
  let { email, password } = req.body;

  const sql = `SELECT * FROM klupea.users WHERE email = ?;`;
  db.query(sql, email, (err, result) => {
    if (err) {
      res.send({ err: err });
    } else if (result.length > 0) {
      bcrypt.compare(password, result[0].password, (err, response) => {
        if (response) {
          const id = result[0].id;
          const token = generateAccessToken(id);
          const refreshToken = generateRefreshToken(id);

          const tokenExpiry = new Date(Date.now() + 60 * 1000); // 1 hour
          const refreshTokenExpiry = new Date(
            Date.now() + 30 * 24 * 60 * 60 * 1000
          ); // 30 days

          // Set the token and refresh token as HTTP-only cookies with expiry dates
          res.cookie("token", token, { httpOnly: true, expires: tokenExpiry });
          res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            expires: refreshTokenExpiry,
          });

          res.status(200).json({
            auth: true,
            result: result,
          });
        } else {
          return res.json({ msg: "Wrong Email or Password !" });
        }
      });
    } else {
      return res.json({ auth: false, msg: "User doesn't exisit" });
    }
  });
};

// Generate JWT token
const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_TOKEN, {
    expiresIn: "2h",
  });
};

// Generate Refresh Token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_RTOKEN, {
    expiresIn: "15d",
  });
};

const updateUserData = (req, res) => {
  const id = req.params.id;
  const data = req.body;
  const sql = `UPDATE users SET ? WHERE id = ?`;
  db.query(sql, [data, id], (err, result) => {
    if (err) {
      console.log(err, "errrrreur");
      return res.json(err);
    }
    console.log(result);
    return res.json(result);
  });
};

const userInfo = (req, res) => {
  const { id } = req.params;
  const sql = `SELECT * FROM klupea.users WHERE id=?;`;
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.send(result);
    }
  });
};

const deleteAccount = (req, res) => {
  const id = req.params.id;
  const sql = `DELETE FROM users WHERE id = ?`;
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.send(result);
    }
  });
};

const restPassword = (req, res) => {
  const { activationCode } = req.params;
  const { password, confirmPass } = req.body;
  if (password === confirmPass) {
    const sql = `SELECT * FROM users WHERE activationCode=? AND isActive="true"`;
    db.query(sql, [activationCode], (err, result) => {
      if (result.length > 0) {
        bcrypt.hash(password, saltRounds, (err, hash) => {
          if (err) {
            console.log(err);
          }
          const sql = `UPDATE klupea.users SET password=?`;
          db.query(sql, [hash], (err, result) => {
            if (err) {
              console.log(err);
              res.send("An error occured, please retry later");
            } else {
              res.send("Password Updated Successfully !");
            }
          });
        });
      }
    });
  }
};

module.exports = {
  login,
  updateUserData,
  userInfo,
  deleteAccount,
  restPassword,
};
