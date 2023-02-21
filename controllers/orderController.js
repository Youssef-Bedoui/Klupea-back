const db = require("../database");
const uuid = require("uuid");
const orderToken = uuid.v4();

const getUserOrders = (req, res) => {
  const { id } = req.params;
  const sql = `SELECT uho.userID, uho.orderID,uho.paymentDate, o.productID, o.quantity,o.orderStatus,p.name, p.image, p.price
FROM user_has_orders AS uho
JOIN orders AS o ON uho.orderID = o.orderID
JOIN products AS p ON o.productID = p.ID
WHERE uho.userID = ?;`;
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};
const getOrderByID = (req, res) => {
  const { userID } = req.params;
  const { orderID } = req.params;
  const sql = `SELECT * FROM klupea.user_has_orders JOIN klupea.orders ON user_has_orders.orderID = orders.orderID WHERE user_has_orders.userID = ? AND user_has_orders.orderID = ?`;
  db.query(sql, [userID, orderID], (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};
const addOrder = (req, res) => {
  const { userID } = req.params;
  const { orders } = req.body;
  const orderID = JSON.stringify(orderToken);

  orders.forEach((order) => {
    const { productID, quantity } = order;

    let sql = `INSERT INTO klupea.orders SET orderID='${orderID}', productID='${productID}', quantity='${quantity}', userID='${userID}'`;

    db.query(sql, (err, result) => {
      if (err) {
        console.log(err);
      }
      console.log(result);
    });
  });
  console.log("Orders inserted successfully", orderID);
  res.send({ orderID: orderID });
};

const addOrderToUser = (req, res) => {
  const { userID } = req.params;
  const { orderID } = req.body;
  let orderDate = JSON.stringify(new Date().toLocaleString());
  let sql = `INSERT INTO user_has_orders SET userID='${userID}',orderID='${orderID}',paymentDate='${orderDate}';`;
  db.query(sql, (err, result) => {
    if (err) {
      console.log(err);
    }
    console.log(result);
  });
};

const deleteOrder = (req, res) => {
  const id = req.params.id;
  const sql = `DELETE FROM klupea.user_has_orders WHERE orderID = ?`;
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.log(err);
    }
    res.send(result);
  });
};

const modifyOrder = (req, res) => {
  const id = req.params.id;
  const newData = req.body;
  console.log(id, newData);
  const sql = `UPDATE klupea.user_has_orders SET ? WHERE orderID = ?`;
  db.query(sql, [newData, id], (err, result) => {
    if (err) {
      console.log(err);
    }
    console.log(result, "heeere");
    res.send(result);
  });
};

module.exports = {
  getUserOrders,
  getOrderByID,
  addOrder,
  addOrderToUser,
  deleteOrder,
  modifyOrder,
};
