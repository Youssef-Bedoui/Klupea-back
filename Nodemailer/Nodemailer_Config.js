const nodemailer = require("nodemailer");
const db = require("../database");

let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        type: "OAuth2",
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
        clientId: process.env.OAUTH_CLIENTID,
        clientSecret: process.env.OAUTH_CLIENT_SECRET,
        refreshToken: process.env.OAUTH_REFRESH_TOKEN
    }
});


const sendResetPasswordMail = (req,res)=>{
    const { receiver, subject, text, activationCode } = req.body;
    let mailOptions = {
        from: "Jozefbedoui@gmail.com",
        to: receiver,
        subject: subject,
        html: text
    };
    transporter.sendMail(mailOptions, function (err, data) {
        if (err) {
            console.log("Error " + err);
            res.send("Email send failed");
        } else {
            const sql = `SELECT * FROM users WHERE email=?`;
            db.query(sql, [receiver], (err, result) => {
                if (err) {
                    console.log(err)
                } else {
                    if (result.length > 0) {
                        if (err) {
                            console.log(err)
                        }
                        const sql2 = `UPDATE klupea.users SET activationCode=? WHERE email=?`;
                        db.query(sql2, [activationCode, receiver], (err, result) => {
                            if (err) {
                                console.log(err);
                            } else {
                                console.log(result);
                            }
                        });
                    } else {
                        console.log("User not found in the database");
                        res.send("User not found in the database");
                    }
                }
            })
            res.send("Email sent successfully");
        }
    });
}


module.exports = {sendResetPasswordMail,transporter }