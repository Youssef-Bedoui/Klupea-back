const jwt = require("jsonwebtoken");


const verifyAndRefreshToken = (req, res, next) => {
    const { token, refreshToken } = req.cookies;
    req.token = token;
    req.refreshToken = refreshToken;
    console.log(token, refreshToken)
    req.token = token;

    // check for presence of token in cookies
    if (!token) {
        // check for presence of refreshToken in cookies
        if (!refreshToken) {
            return res.status(401).send("No Token Found");
        }

        jwt.verify(refreshToken, process.env.SECRET_RTOKEN, (err, refreshTokenInfo) => {
            // if refresh token is invalid 
            if (err) {
                return res.status(401).send("Invalid refresh token");
            } else {
                const { id } = refreshTokenInfo;
                // generate new token 
                let newToken = jwt.sign({ id },
                    process.env.SECRET_TOKEN,
                    { expiresIn: "1m" });

                // set the new token as an http-only cookie with an expiration time of 2 hours
                res.cookie("token", newToken, {
                    httpOnly: true,
                    maxAge:  60 * 1000
                });
                req.token = newToken;
                next();
            }
        });
    } else {
        jwt.verify(token, process.env.SECRET_TOKEN, (err, tokenInfo) => {
            if (err) {
                return res.send("not authorized")
            }
            next();
        });
    }
};

const checkRefToken = (req, res) => {
    // Get the refresh token from the cookies
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.send({ msg: "No refreshToken" });
    }

    // Verify the refresh token
    jwt.verify(refreshToken, process.env.SECRET_RTOKEN, (err, userData) => {
        if (err) {
            return res.send({ msg: "Invalid refreshToken" });
        }

        // Return a success message if the refresh token is valid
        return res.send({ msg: "Valid refreshToken" });
    });
};


const logout = (req, res) => {
    res.clearCookie("token");
    res.clearCookie("refreshToken");
    res.status(200).send("Logout succes");
};

require("dotenv").config();
module.exports = { verifyAndRefreshToken, checkRefToken, logout }