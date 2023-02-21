const db = require("../database");

const getItemsByID = (req, res) => {
  const userID = req.params.id;
  const sql = ` SELECT * FROM klupea.bag INNER JOIN klupea.products ON bag.productID=products.ID WHERE userID=?`;

  db.query(sql, [userID], (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};

const addToBag = (req, res) => {
  const data = req.body;
  console.log(data);
  const sql = `INSERT INTO klupea.bag SET ?`;
  db.query(sql, [data], (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};
const deleteItem = (req, res) => {
  const id = req.params.id;
  const sql = `DELETE FROM klupea.bag WHERE id = ?`;

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};
const emptyBagItems = (req, res) => {
  const userID = req.params.userID;
  const sql = `DELETE FROM klupea.bag WHERE userID = ?`;

  db.query(sql, [userID], (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};

const updateItem = (req, res) => {
  const id = req.params.id;
  const newData = req.body;
  console.log(id);
  console.log(newData);

  const sql = `UPDATE klupea.bag SET ? WHERE id = ?`;
  db.query(sql, [newData, id], (err, result) => {
    if (err) {
      console.log(sql);
      console.log(err);
    }
    console.log("success");
    res.send(result);
  });
};

module.exports = {
  getItemsByID,
  addToBag,
  deleteItem,
  emptyBagItems,
  updateItem,
};
