const express = require("express");
const router = express.Router();
const wishController = require("../controllers/wishController.js");

router.get("/getWishList/:userID", wishController.getWishList);
router.post("/addWish", wishController.addToWish);
router.delete("/deleteItem/:id/:userID", wishController.deleteItem);


module.exports = router;