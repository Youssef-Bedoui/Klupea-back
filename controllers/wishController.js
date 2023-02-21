const db = require("../database");

const getWishList = (req, res) => {
    const { userID } = req.params;
    const sql = `SELECT * FROM klupea.wishlist WHERE userID = ?`;
    db.query(sql, [userID], (err, result) => {
        if (err) {
            console.log(err)
        } else {
            res.send(result);
        }
    })
};

const addToWish = (req,res) => {
    const wishProduct = req.body;
    const sql = `INSERT INTO klupea.wishlist SET ?`;
    db.query(sql, [wishProduct], (err, result) => {
        if (err) {
            console.log(err)
        } else {
            res.send(result);
        }
    })
}

const deleteItem = (req, res) => {
    const { id, userID } = req.params;
    const sql = `DELETE FROM klupea.wishlist WHERE id = ? AND userID = ?`;
    db.query(sql, [id, userID], (err, result) => {
        if (err) {
            console.log(err)
        } else {
            res.send(result);
        }
    })
}




module.exports = { getWishList, addToWish, deleteItem };