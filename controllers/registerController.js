const db = require("../database");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const { transporter } = require("../Nodemailer/Nodemailer_Config");

const register = (req, res) => {
  const {
    firstName,
    lastName,
    email,
    password,
    address,
    city,
    phone,
    activationCode,
  } = req.body;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
    }
    const sql = `INSERT INTO klupea.users SET firstName = ?,lastName=?,email = ?, password = ?, address=?, city=?, phone=?,activationCode=?,isActive="false"`;
    db.query(sql,[firstName, lastName, email, hash, address, city, phone, activationCode],(err, result) => {
        if (err) {
          res.send(err);
        } else {
          let mailOptions = {
            from: "Jozefbedoui@gmail.com",
            to: email,
            subject: "Klupea - VERIFICATION EMAIL",
            html: `
                  <html>
                    <head>
                      <style>
                        h1 {
                          color: blue;
                        }
                      </style>
                    </head>
                    <body>
                      <h1>Your activation code :</h1>
                      <p>Paste this code in the verification form :</p>
                      <h5 style={textDecoration:"underline"}>${activationCode}</h5>
                    </body>
                  </html>
                  `,
          };

          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.log(error);
            } else {
              console.log("Email sent Successfully");
               res.send("A Code has been sent to your email for verification");
            }
          });
        }
      }
    );
  });
};

const checkUser = (req,res)=>{
  const {email} = req.body;
  const sql= `SELECT * FROM users WHERE email=?`;
  db.query(sql,[email],(err,result)=>{
    if(err){
        console.log(err);
    }else{
        res.send(result);
    }
  })
}

module.exports = { register,checkUser };
