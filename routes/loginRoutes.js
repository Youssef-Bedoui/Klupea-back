const express = require("express");
const router = express.Router();
const loginController = require("../controllers/loginController.js");

router.post("/", loginController.login);
router.get("/userInfo/:id", loginController.userInfo);
router.patch("/updateUser/:id", loginController.updateUserData);
router.delete("/deleteUser/:id", loginController.deleteAccount);

//password reset
router.post("/restPassword/:activationCode", loginController.restPassword);


module.exports = router;