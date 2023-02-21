const express = require("express");
const router = express.Router();
const bagController = require("../controllers/bagController.js");

router.get("/:id", bagController.getItemsByID);
router.post("/addItem", bagController.addToBag)
router.delete("/deleteItem/:id", bagController.deleteItem)
router.delete("/emptyBag/:userID", bagController.emptyBagItems)
router.patch("/updateItem/:id", bagController.updateItem)

module.exports = router;