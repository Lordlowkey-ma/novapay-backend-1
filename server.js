const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const {
    registerUser,
    verifyPasswordHash
} = require("./register-backend");

require("./firebase");

const {
    getAuth
} = require("firebase-admin/auth");

const {
    getFirestore
} = require("firebase-admin/firestore");

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
   FIREBASE SERVICES
   ========================================================= */

const auth = getAuth();
const db = getFirestore();


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
   REGISTER
   ========================================================= */

app.post("/api/register", async (req, res) => {

    try {

        const {
            idToken,
            username,
            password
        } = req.body || {};


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


        const result =
            await registerUser({
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
   LOGIN
   ========================================================= */

app.post("/api/login", async (req, res) => {

    try {

        const {
            phone,
            password
        } = req.body || {};


        /* -------------------------------------------------
           INPUT VALIDATION
        ------------------------------------------------- */

        if (!phone) {

            return res.status(400).json({
                success: false,
                message: "Phone number is required."
            });

        }


        if (!password) {

            return res.status(400).json({
                success: false,
                message: "Password is required."
            });

        }


        /* -------------------------------------------------
           NORMALIZE PHONE
        ------------------------------------------------- */

        let normalizedPhone =
            String(phone)
                .trim()
                .replace(/\s+/g, "")
                .replace(/-/g, "")
                .replace(/[()]/g, "");


        if (
            normalizedPhone.startsWith("0") &&
            normalizedPhone.length === 11
        ) {

            normalizedPhone =
                "+234" +
                normalizedPhone.substring(1);

        }


        if (
            normalizedPhone.startsWith("234") &&
            !normalizedPhone.startsWith("+234")
        ) {

            normalizedPhone =
                "+" +
                normalizedPhone;

        }


        /* -------------------------------------------------
           FIND USER
        ------------------------------------------------- */

        const userQuery =
            await db
                .collection("novapayUsers")
                .where(
                    "phoneNumber",
                    "==",
                    normalizedPhone
                )
                .limit(1)
                .get();


        if (userQuery.empty) {

            return res.status(401).json({
                success: false,
                message: "Incorrect phone number or password."
            });

        }


        const userDoc =
            userQuery.docs[0];

        const user =
            userDoc.data();


        /* -------------------------------------------------
           PASSWORD DATA
        ------------------------------------------------- */

        if (
            !user.passwordHash ||
            !user.passwordSalt
        ) {

            console.error(
                "NovaPay login: password data missing:",
                userDoc.id
            );

            return res.status(500).json({
                success: false,
                message:
                    "This account cannot be logged in at the moment."
            });

        }


        /* -------------------------------------------------
           VERIFY PASSWORD
        ------------------------------------------------- */

        const passwordCorrect =
            await verifyPasswordHash(
                password,
                user.passwordSalt,
                user.passwordHash
            );


        if (!passwordCorrect) {

            return res.status(401).json({
                success: false,
                message:
                    "Incorrect phone number or password."
            });

        }


        /* -------------------------------------------------
           VERIFY FIREBASE USER EXISTS
        ------------------------------------------------- */

        const uid =
            user.uid || userDoc.id;

        try {

            await auth.getUser(uid);

        } catch (error) {

            console.error(
                "NovaPay login: Firebase user not found:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Your authentication account could not be found."
            });

        }


        /* -------------------------------------------------
           CREATE FIREBASE CUSTOM TOKEN
        ------------------------------------------------- */

        const customToken =
            await auth.createCustomToken(uid, {
                novaPayUser: true
            });


        /* -------------------------------------------------
           SAFE RESPONSE
        ------------------------------------------------- */

        return res.status(200).json({

            success: true,

            message:
                "Login successful.",

            token:
                customToken,

            user: {

                uid: uid,

                username:
                    user.username || "",

                phoneNumber:
                    user.phoneNumber || "",

                phoneVerified:
                    user.phoneVerified === true

            }

        });


    } catch (error) {

        console.error(
            "NovaPay login error:",
            error
        );


        return res.status(500).json({

            success: false,

            message:
                "Unable to process your login right now."

        });

    }

});


/* =========================================================
   SERVER
   ========================================================= */

const PORT =
    process.env.PORT || 3000;


app.listen(
    PORT,
    () => {

        console.log(
            `NovaPay backend running on port ${PORT}`
        );

    }
);