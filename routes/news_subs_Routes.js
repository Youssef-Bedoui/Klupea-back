const db = require("../database");
const express = require("express");
const router = express.Router();


router.post("/", (req, res) => {
    const email = req.body.email;
    console.log(email)
    const sql = "INSERT INTO klupea.news_subscriptions set ?"
    db.query(sql, { user_email: email }, (err, result) => {
        if (err) {
            console.log(err);
            console.log(err)
        } else {
            res.send(result);
            console.log(result);
        }
    })
})

module.exports = router;