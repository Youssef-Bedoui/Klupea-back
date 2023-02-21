const express = require("express");
const router = express.Router();
const nodemailer = require("../Nodemailer/Nodemailer_Config");


router.post("/", nodemailer.sendResetPasswordMail);



module.exports = router;