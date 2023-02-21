const express = require("express");
const Stripe = require("stripe");

require("dotenv").config();

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const router = express.Router();

router.post('/create-checkout-session', async (req, res) => {
    const lineItems = req.body;
    const session = await stripe.checkout.sessions.create({
        line_items: lineItems,
        mode: 'payment',
        success_url: `http://localhost:3000/checkout-success`,
        cancel_url: `http://localhost:3000/address`,
    });
    if (session.error) {
        res.redirect("/bag");
        res.send("Payment Failed");
    } else {
        // The checkout session was created successfully
        res.json({ url: session.url })
    }
    // res.redirect(303, session.url);
});

module.exports = router;