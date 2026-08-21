const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const { registerUser } = require("./register-backend");

require("./firebase");

const app = express();

/* =========================================================
   SECURITY
   ========================================================= */

app.use(helmet());

app.use(cors({
    origin: true,
    credentials: true
}));

app.use(express.json({
    limit: "10kb"
}));

/* =========================================================
   RATE LIMIT
   ========================================================= */

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: "draft-7",
    legacyHeaders: false
});

app.use(apiLimiter);

/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "NovaPay backend is running."
    });
});

/* =========================================================
   REGISTRATION
   ========================================================= */

app.post("/api/register", async (req, res) => {

    try {

        const {
    idToken,
    username,
    password
} = req.body || {};

        /* -------------------------------------------------
           BASIC INPUT CHECK
        ------------------------------------------------- */

        if (!idToken) {
            return res.status(400).json({
                success: false,
                message: "Phone verification is required."
            });
        }

        if (!username) {
            return res.status(400).json({
                success: false,
                message: "Username is required."
            });
        }

        if (!password) {
            return res.status(400).json({
                success: false,
                message: "Password is required."
            });
        }

        /* -------------------------------------------------
           REGISTER USER
        ------------------------------------------------- */

        const result = await registerUser({
            idToken,
            username,
            password
        });

        return res.status(201).json(result);

    } catch (error) {

        console.error(
            "NovaPay registration error:",
            error
        );

        return res.status(400).json({
            success: false,
            message:
                error.message ||
                "Unable to create your NovaPay account."
        });
    }
});

/* =========================================================
   SERVER
   ========================================================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(
        `NovaPay backend running on port ${PORT}`
    );
});