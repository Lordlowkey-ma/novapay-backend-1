const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const {
    registerUser,
    verifyPasswordHash,
    hashPassword
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


/* =========================================================
   PAYSTACK WEBHOOK
   MUST BE BEFORE express.json()
========================================================= */

app.post(
    "/api/payments/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {

        try {

            const signature =
                req.headers["x-paystack-signature"];

            const secret =
                process.env.PAYSTACK_SECRET_KEY;

            if (!secret) {
                console.error(
                    "PAYSTACK_SECRET_KEY is missing."
                );

                return res.sendStatus(500);
            }

            if (!signature) {
                return res.sendStatus(401);
            }


            /* -----------------------------------------
               VERIFY PAYSTACK SIGNATURE
            ----------------------------------------- */

            const expectedSignature =
                crypto
                    .createHmac("sha512", secret)
                    .update(req.body)
                    .digest("hex");


            const signaturesMatch =
                signature.length === expectedSignature.length &&
                crypto.timingSafeEqual(
                    Buffer.from(signature),
                    Buffer.from(expectedSignature)
                );


            if (!signaturesMatch) {

                console.warn(
                    "Invalid Paystack webhook signature."
                );

                return res.sendStatus(401);
            }


            /* -----------------------------------------
               PARSE EVENT
            ----------------------------------------- */

            const event =
                JSON.parse(
                    req.body.toString("utf8")
                );


            /*
               Only successful charges can
               credit a NovaPay wallet.
            */

            if (
                event.event !==
                "charge.success"
            ) {
                return res.sendStatus(200);
            }


            const payment =
                event.data;


            const reference =
                payment?.reference;


            if (!reference) {
                return res.sendStatus(200);
            }


            /* -----------------------------------------
               FIND NOVAPAY PAYMENT
            ----------------------------------------- */

            const paymentRef =
                db
                    .collection("novapayPayments")
                    .doc(reference);


            /*
               Firestore transaction prevents the
               same Paystack webhook from crediting
               the wallet twice.
            */

            await db.runTransaction(
                async (transaction) => {

                    const paymentDoc =
                        await transaction.get(
                            paymentRef
                        );


                    if (!paymentDoc.exists) {

                        console.warn(
                            "Unknown Paystack payment:",
                            reference
                        );

                        return;
                    }


                    const savedPayment =
                        paymentDoc.data();


                    /* ---------------------------------
                       ALREADY CREDITED
                    --------------------------------- */

                    if (
                        savedPayment.status ===
                        "credited"
                    ) {
                        return;
                    }


                    /* ---------------------------------
                       BASIC VALIDATION
                    --------------------------------- */

                    if (
                        payment.status !==
                        "success"
                    ) {
                        return;
                    }


                    if (
                        payment.currency !==
                        "NGN"
                    ) {

                        console.warn(
                            "Unexpected payment currency:",
                            payment.currency
                        );

                        return;
                    }


                    if (
                        Number(payment.amount) !==
                        Number(
                            savedPayment.amountKobo
                        )
                    ) {

                        console.error(
                            "Paystack amount mismatch:",
                            reference
                        );

                        return;
                    }


                    const uid =
                        savedPayment.uid;


                    if (!uid) {

                        console.error(
                            "Payment has no user UID:",
                            reference
                        );

                        return;
                    }


                    /* ---------------------------------
                       USER WALLET
                    --------------------------------- */

                    const userRef =
                        db
                            .collection("novapayUsers")
                            .doc(uid);


                    const userDoc =
                        await transaction.get(
                            userRef
                        );


                    if (!userDoc.exists) {

                        throw new Error(
                            "NovaPay user does not exist."
                        );
                    }


                    const user =
                        userDoc.data();


                    const currentBalance =
                        Number(
                            user.walletBalance || 0
                        );


                    const amountNaira =
                        Number(
                            savedPayment.amountNaira
                        );


                    const newBalance =
                        Number(
                            (
                                currentBalance +
                                amountNaira
                            ).toFixed(2)
                        );


                    /* ---------------------------------
                       UPDATE WALLET
                    --------------------------------- */

                    transaction.update(
                        userRef,
                        {
                            walletBalance:
                                newBalance,

                            updatedAt:
                                require(
                                    "firebase-admin/firestore"
                                )
                                    .FieldValue
                                    .serverTimestamp()
                        }
                    );


                    /* ---------------------------------
                       SAVE TRANSACTION
                    --------------------------------- */

                    const transactionRef =
                        db
                            .collection(
                                "novapayTransactions"
                            )
                            .doc(reference);


                    transaction.set(
                        transactionRef,
                        {
                            uid:
                                uid,

                            type:
                                "wallet_funding",

                            amount:
                                amountNaira,

                            currency:
                                "NGN",

                            reference:
                                reference,

                            status:
                                "successful",

                            paymentMethod:
                                payment.channel ||
                                "paystack",

                            createdAt:
                                require(
                                    "firebase-admin/firestore"
                                )
                                    .FieldValue
                                    .serverTimestamp()
                        }
                    );


                    /* ---------------------------------
                       MARK PAYMENT CREDITED
                    --------------------------------- */

                    transaction.update(
                        paymentRef,
                        {
                            status:
                                "credited",

                            paystackStatus:
                                payment.status,

                            creditedAt:
                                require(
                                    "firebase-admin/firestore"
                                )
                                    .FieldValue
                                    .serverTimestamp()
                        }
                    );
                }
            );


            return res.sendStatus(200);


        } catch (error) {

            console.error(
                "NovaPay Paystack webhook error:",
                error
            );

            return res.sendStatus(500);
        }
    }
); 
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
                message:
                    "Phone verification is required."
            });

        }


        if (!username) {

            return res.status(400).json({
                success: false,
                message:
                    "Username is required."
            });

        }


        if (!password) {

            return res.status(400).json({
                success: false,
                message:
                    "Password is required."
            });

        }


        const result =
            await registerUser({
                idToken,
                username,
                password
            });


        return res.status(201).json({
            success: true,
            message:
                "Account created successfully.",
            uid:
                result.uid
        });


    } catch (error) {

        console.error(
            "Register error:",
            error
        );


        return res.status(400).json({
            success: false,
            message:
                error.message ||
                "Unable to create account."
        });

    }

}); 
/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {

    try {

        const {
            username,
            password
        } = req.body || {};


        /* -----------------------------------------
           VALIDATION
        ----------------------------------------- */

        if (!username) {

            return res.status(400).json({
                success: false,
                message:
                    "Username is required."
            });

        }


        if (!password) {

            return res.status(400).json({
                success: false,
                message:
                    "Password is required."
            });

        }


        /* -----------------------------------------
           FIND USER
        ----------------------------------------- */

        const snapshot =
            await db
                .collection("novapayUsers")
                .where(
                    "username",
                    "==",
                    username.trim()
                )
                .limit(1)
                .get();


        if (snapshot.empty) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid username or password."
            });

        }


        const userDoc =
            snapshot.docs[0];


        const user =
            userDoc.data();


        /* -----------------------------------------
           VERIFY PASSWORD
        ----------------------------------------- */

        const passwordValid =
            await verifyPasswordHash(
                password,
                user.passwordHash
            );


        if (!passwordValid) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid username or password."
            });

        }


        /* -----------------------------------------
           RETURN USER
        ----------------------------------------- */

        return res.status(200).json({

            success: true,

            message:
                "Login successful.",

            user: {

                uid:
                    userDoc.id,

                username:
                    user.username,

                phoneNumber:
                    user.phoneNumber || null
            }
        });


    } catch (error) {

        console.error(
            "Login error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to complete login right now."
        });

    }

}); 
/* =========================================================
   RESET PASSWORD
========================================================= */

app.post(
    "/api/reset-password",
    async (req, res) => {

        try {

            const {
                idToken,
                newPassword
            } = req.body || {};


            /* -----------------------------------------
               VALIDATION
            ----------------------------------------- */

            if (!idToken) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Verification is required."
                });

            }


            if (!newPassword) {

                return res.status(400).json({
                    success: false,
                    message:
                        "New password is required."
                });

            }


            if (
                typeof newPassword !== "string" ||
                newPassword.length < 6
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be at least 6 characters."
                });

            }


            /* -----------------------------------------
               VERIFY FIREBASE USER
            ----------------------------------------- */

            let decodedToken;

            try {

                decodedToken =
                    await auth.verifyIdToken(
                        idToken
                    );

            } catch (error) {

                console.error(
                    "Reset password token verification failed:",
                    error
                );

                return res.status(401).json({
                    success: false,
                    message:
                        "Your verification has expired. Please try again."
                });

            }


            const uid =
                decodedToken.uid;


            /* -----------------------------------------
               HASH NEW PASSWORD
            ----------------------------------------- */

            const passwordHash =
                await hashPassword(
                    newPassword
                );


            /* -----------------------------------------
               UPDATE FIRESTORE
            ----------------------------------------- */

            await db
                .collection("novapayUsers")
                .doc(uid)
                .update({

                    passwordHash:
                        passwordHash,

                    updatedAt:
                        require(
                            "firebase-admin/firestore"
                        )
                            .FieldValue
                            .serverTimestamp()
                });


            /* -----------------------------------------
               SUCCESS
            ----------------------------------------- */

            return res.status(200).json({

                success: true,

                message:
                    "Password updated successfully."
            });


        } catch (error) {

            console.error(
                "Reset password error:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "We couldn't update your password right now. Please try again."
            });

        }

    }
); 
/* =========================================================
   PAYSTACK — INITIALIZE WALLET FUNDING
========================================================= */

app.post(
    "/api/payments/initialize",
    async (req, res) => {

        try {

            /* -----------------------------------------
               AUTHENTICATION
            ----------------------------------------- */

            const authHeader =
                req.headers.authorization || "";


            if (
                !authHeader.startsWith("Bearer ")
            ) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Authentication is required."
                });

            }


            const idToken =
                authHeader.substring(7);


            let decodedToken;

            try {

                decodedToken =
                    await auth.verifyIdToken(
                        idToken
                    );

            } catch (error) {

                console.error(
                    "Payment Firebase token verification failed:",
                    error
                );

                return res.status(401).json({
                    success: false,
                    message:
                        "Your session has expired. Please log in again."
                });

            }


            const uid =
                decodedToken.uid;


            /* -----------------------------------------
               INPUT
            ----------------------------------------- */

            const {
                amount,
                email
            } = req.body || {};


            const amountNumber =
                Number(amount);


            const normalizedEmail =
                String(email || "")
                    .trim()
                    .toLowerCase();


            /* -----------------------------------------
               VALIDATE AMOUNT
            ----------------------------------------- */

            if (
                !Number.isFinite(amountNumber) ||
                amountNumber < 100
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Enter a valid amount of at least ₦100."
                });

            }


            if (
                amountNumber > 10000000
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "The payment amount is too large."
                });

            }


            /* -----------------------------------------
               VALIDATE EMAIL
            ----------------------------------------- */

            const emailPattern =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


            if (
                !emailPattern.test(
                    normalizedEmail
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Enter a valid email address."
                });

            }


            /* -----------------------------------------
               PAYSTACK SECRET
            ----------------------------------------- */

            const paystackSecret =
                process.env.PAYSTACK_SECRET_KEY;


            if (!paystackSecret) {

                console.error(
                    "PAYSTACK_SECRET_KEY is not configured."
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "Payment service is temporarily unavailable."
                });

            }


            /* -----------------------------------------
               VERIFY NOVAPAY USER
            ----------------------------------------- */

            const userRef =
                db
                    .collection("novapayUsers")
                    .doc(uid);


            const userDoc =
                await userRef.get();


            if (!userDoc.exists) {

                return res.status(404).json({
                    success: false,
                    message:
                        "NovaPay account not found."
                });

            }


            /* -----------------------------------------
               AMOUNT → KOBO
            ----------------------------------------- */

            const amountKobo =
                Math.round(
                    amountNumber * 100
                );


            /* -----------------------------------------
               UNIQUE PAYMENT REFERENCE
            ----------------------------------------- */

            const reference =
                `NP-${uid}-${Date.now()}-${crypto
                    .randomBytes(4)
                    .toString("hex")}`;


            /* -----------------------------------------
               SAVE PENDING PAYMENT
            ----------------------------------------- */

            await db
                .collection("novapayPayments")
                .doc(reference)
                .set({

                    uid:
                        uid,

                    email:
                        normalizedEmail,

                    amountNaira:
                        Number(
                            amountNumber.toFixed(2)
                        ),

                    amountKobo:
                        amountKobo,

                    currency:
                        "NGN",

                    reference:
                        reference,

                    status:
                        "pending",

                    provider:
                        "paystack",

                    createdAt:
                        require(
                            "firebase-admin/firestore"
                        )
                            .FieldValue
                            .serverTimestamp()

                });


            /* -----------------------------------------
               INITIALIZE PAYSTACK
            ----------------------------------------- */

            const paystackResponse =
                await fetch(
                    "https://api.paystack.co/transaction/initialize",
                    {
                        method: "POST",

                        headers: {

                            "Authorization":
                                `Bearer ${paystackSecret}`,

                            "Content-Type":
                                "application/json"

                        },

                        body: JSON.stringify({

                            email:
                                normalizedEmail,

                            amount:
                                String(
                                    amountKobo
                                ),

                            currency:
                                "NGN",

                            reference:
                                reference,

                            channels: [
                                "card",
                                "bank_transfer"
                            ],

                            metadata: {

                                uid:
                                    uid,

                                type:
                                    "wallet_funding",

                                novaPayReference:
                                    reference

                            }

                        })

                    }
                );


            const paystackData =
                await paystackResponse.json();


            /* -----------------------------------------
               PAYSTACK ERROR
            ----------------------------------------- */

            if (
                !paystackResponse.ok ||
                !paystackData.status
            ) {

                console.error(
                    "Paystack initialization failed:",
                    paystackData
                );


                await db
                    .collection("novapayPayments")
                    .doc(reference)
                    .update({

                        status:
                            "initialization_failed",

                        updatedAt:
                            require(
                                "firebase-admin/firestore"
                            )
                                .FieldValue
                                .serverTimestamp()

                    });


                return res.status(502).json({
                    success: false,
                    message:
                        "We couldn't start your payment. Please try again."
                });

            }


            const paymentData =
                paystackData.data;


            /* -----------------------------------------
               SAVE PAYSTACK DETAILS
            ----------------------------------------- */

            await db
                .collection("novapayPayments")
                .doc(reference)
                .update({

                    accessCode:
                        paymentData.access_code,

                    authorizationUrl:
                        paymentData.authorization_url,

                    paystackReference:
                        paymentData.reference,

                    status:
                        "initialized",

                    updatedAt:
                        require(
                            "firebase-admin/firestore"
                        )
                            .FieldValue
                            .serverTimestamp()

                });


            /* -----------------------------------------
               RETURN CHECKOUT URL
            ----------------------------------------- */

            return res.status(200).json({

                success:
                    true,

                authorization_url:
                    paymentData.authorization_url,

                reference:
                    paymentData.reference

            });


        } catch (error) {

            console.error(
                "NovaPay payment initialization error:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "We couldn't start your payment right now."
            });

        }

    }
);
/* =========================================================
   START NOVAPAY SERVER
========================================================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`NovaPay backend running on port ${PORT}`);
});