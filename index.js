const express = require("express");
const app = express();
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require('express-session')
require("dotenv").config();
const stripe = require("./routes/stripe.js");
const productRoutes = require("./routes/productRoutes.js");
const bagRoutes = require("./routes/bagRoutes.js");
const orderRoutes = require("./routes/orderRoutes.js");
const registerRoutes = require("./routes/registerRoutes.js");
const loginRoutes = require("./routes/loginRoutes.js");
const authRoutes = require("./routes/authRoutes.js");
const wishRoutes = require("./routes/wishRoutes.js");
const newsletterRoutes = require("./routes/news_subs_Routes.js");
const nodemailerRoutes = require("./routes/nodemailerRoutes.js");
const { verifyAndRefreshToken } = require("././middlewares/Authorization.js");
const port = process.env.PORT;


app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "DELETE", "PATCH", "PUT"],
    credentials: true,
}));

//set session
// app.use(session({
//     secret: "rg78H46klGs64hkizlg54rg6Z5rrj/htN",
//     resave: false,
//     saveUninitialized: true,
//     cookie: {
//         secure: "auto",
//         maxAge: 60 * 1000
//     }
// }));

// app.use(function (req, res, next) {
//     console.log("session", req.session.user);
//     console.log("expired", req.session.user === undefined);
//     if (req.session.user === undefined) {
//         return res.redirect("http://localhost:3000/signIn");
//     }
//     next();
// });
app.use(session({
    secret: "secret",
    resave: false,
    saveUninitialized: true
}));



app.use(cookieParser());


app.use("/products", productRoutes);
app.use("/bag", bagRoutes);
app.use("/wishList", verifyAndRefreshToken, wishRoutes);
app.use("/orders", verifyAndRefreshToken, orderRoutes);
app.use("/register", registerRoutes);
app.use("/signIn", loginRoutes);
app.use("/auth", verifyAndRefreshToken, authRoutes);
app.use("/stripe", stripe);
app.use("/newsletter", newsletterRoutes);
app.use("/sendMail", nodemailerRoutes);


app.listen(port, () => {
    console.log(`APP IS RUNNING AT PORT ${port}`);
})