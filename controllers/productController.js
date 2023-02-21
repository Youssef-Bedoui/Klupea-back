const db = require("../database");

const getProducts = (req, res) => {
  const { gender, category } = req.params;
  const sql = `SELECT * FROM klupea.products WHERE gender = ? AND category = ?`;
  db.query(sql, [gender, category], (err, result) => {
    if (err) {
      res.send(err);
    }
    res.send(result);
  });
};

const getSizes = (req, res) => {
  const { productID } = req.params;
  console.log(productID, "id");

  const sql = `SELECT s.size FROM klupea.sizes s
JOIN klupea.product_sizes ps ON s.sizeID = ps.sizeID
JOIN klupea.products p ON ps.productID = p.ID
WHERE p.ID = ?`;
  db.query(sql, [productID], (err, result) => {
    if (err) {
      console.log(err);
      res.send(err);
    }
    console.log(result);
    res.send(result);
  });
};

const getCollection = (req, res) => {
  const { gender } = req.params;
  const sql = `SELECT * FROM klupea.products WHERE gender = ?`;
  db.query(sql, [gender], (err, result) => {
    if (err) {
      console.log(err);
      res.send(err);
    }
    res.send(result);
  });
};
const getNewArrival = (req, res) => {
  const sql = `SELECT * FROM klupea.products ORDER BY STR_TO_DATE(arrivalDate, '%Y/%m/%d') DESC`;
  db.query(sql, (err, result) => {
    if (err) {
      console.log(err);
      res.send(err);
    }
    res.send(result);
  });
};

const searchProduct = (req, res) => {
  const { name } = req.params;
  console.log(name)
  const sql = `SELECT * FROM klupea.products WHERE name LIKE "%${name}%";`;
  db.query(sql, (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};

const addProduct = (req, res) => {
  const data = req.body;
  const sql = `INSERT INTO klupea.products SET ?`;
  db.query(sql, [data], (err, result) => {
    if (err) {
      res.send(err);
    }
    res.send(result);
    console.log("product added successfully");
  });
};
const deleteProduct = (req, res) => {
  const productID = req.params.id;
  const sql = `DELETE FROM klupea.products WHERE id=?`;
  db.query(sql, [productID], (err, result) => {
    if (err) {
      res.send(err);
      console.log(`Product ${productID} was deleted successfully`);
    }
    res.send(result);
  });
};
const modifProduct = (req, res) => {
  const productID = req.params.id;
  const updatedData = req.body;
  const sql = `UPDATE klupea.products SET ? WHERE id=?`;
  db.query(sql, [updatedData, productID], (err, result) => {
    if (err) {
      res.send(err);
    }
    res.send(result);
    console.log(`Product ${productID} was updated successfully`);
  });
};

module.exports = {
  getProducts,
  getSizes,
  getCollection,
  getNewArrival,
  searchProduct,
  addProduct,
  deleteProduct,
  modifProduct,
};
