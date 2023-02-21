const express = require("express");
const router = express.Router();
const checkAuth = require("../middlewares/Authorization.js");


router.get("/checkRefToken", checkAuth.checkRefToken);
router.get("/logout", checkAuth.logout);

module.exports = router;