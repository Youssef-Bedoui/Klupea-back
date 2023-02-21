const express = require("express");
const router = express.Router();
const orderController = require("../controllers/orderController.js");

router.get("/getUserOrders/:id", orderController.getUserOrders);
router.get("/getOrderItems/:userID/:orderID", orderController.getOrderByID);
router.post("/placeOrder/:userID/", orderController.addOrder);
router.post("/placeOrderToUser/:userID/", orderController.addOrderToUser);
router.delete("/deleteOrder/:id", orderController.deleteOrder);
router.patch("/modifOrder/:id", orderController.modifyOrder);

module.exports = router;