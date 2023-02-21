const express = require("express");
const router = express.Router();
const registerController = require("../controllers/registerController.js");

router.post("/", registerController.register);
router.post("/checkUser", registerController.checkUser);


module.exports = router;