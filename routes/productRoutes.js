const express = require("express");
const router = express.Router();
const productController = require("../controllers/productController.js");

router.get("/getSizes/:productID", productController.getSizes);
router.get("/search/:name", productController.searchProduct);
router.get("/:gender/:category", productController.getProducts);
router.get("/newArrival", productController.getNewArrival);
router.get("/:gender", productController.getCollection);
router.post("/addProduct", productController.addProduct);
router.delete("/delete/:id", productController.deleteProduct);
router.patch("/update/:id", productController.modifProduct);

module.exports = router;