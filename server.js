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
    getFirestore,
    FieldValue
} = require("firebase-admin/firestore");

const app = express();

const auth = getAuth();
const db = getFirestore();


/* =========================================================
   SECURITY
========================================================= */

app.use(helmet());

app.use(cors({
    origin: true,
    credentials: true
}));


/* =========================================================
   PAYSTACK HELPERS
========================================================= */

/*
   This function is the ONLY place that actually credits
   a NovaPay wallet from a Paystack payment.

   Both:
   - Paystack webhook
   - Server-side verification

   use this same function.

   This prevents different payment paths from having
   different wallet-credit rules.
*/

async function creditPaystackPayment(
    payment,
    expectedReference = null
) {

    if (!payment) {
        return {
            credited: false,
            reason: "missing_payment"
        };
    }


    const reference =
        payment.reference;


    if (!reference) {
        return {
            credited: false,
            reason: "missing_reference"
        };
    }


    /* -----------------------------------------
       REFERENCE CHECK
    ----------------------------------------- */

    if (
        expectedReference &&
        reference !== expectedReference
    ) {

        console.error(
            "Paystack reference mismatch:",
            reference,
            expectedReference
        );

        return {
            credited: false,
            reason: "reference_mismatch"
        };
    }


    const paymentRef =
        db
            .collection("novapayPayments")
            .doc(reference);


    let result = {
        credited: false,
        alreadyCredited: false,
        reason: "not_processed"
    };


    await db.runTransaction(
        async (transaction) => {

            const paymentDoc =
                await transaction.get(
                    paymentRef
                );


            /* ---------------------------------
               PAYMENT MUST EXIST
            --------------------------------- */

            if (!paymentDoc.exists) {

                console.warn(
                    "Unknown Paystack payment:",
                    reference
                );

                result = {
                    credited: false,
                    reason: "payment_not_found"
                };

                return;
            }


            const savedPayment =
                paymentDoc.data();


            /* ---------------------------------
               PREVENT DOUBLE CREDIT
            --------------------------------- */

            if (
                savedPayment.status ===
                "credited"
            ) {

                result = {
                    credited: false,
                    alreadyCredited: true,
                    reason: "already_credited"
                };

                return;
            }


            /* ---------------------------------
               PAYMENT MUST BE SUCCESSFUL
            --------------------------------- */

            if (
                payment.status !==
                "success"
            ) {

                result = {
                    credited: false,
                    reason: "payment_not_successful"
                };

                return;
            }


            /* ---------------------------------
               CURRENCY CHECK
            --------------------------------- */

            if (
                String(payment.currency)
                    .toUpperCase() !==
                "NGN"
            ) {

                console.error(
                    "Unexpected Paystack currency:",
                    payment.currency
                );

                result = {
                    credited: false,
                    reason: "invalid_currency"
                };

                return;
            }


            /* ---------------------------------
               AMOUNT CHECK
            --------------------------------- */

            const paystackAmount =
                Number(payment.amount);

            const expectedAmount =
                Number(
                    savedPayment.amountKobo
                );


            if (
                !Number.isSafeInteger(
                    paystackAmount
                ) ||
                !Number.isSafeInteger(
                    expectedAmount
                ) ||
                paystackAmount !==
                expectedAmount
            ) {

                console.error(
                    "Paystack amount mismatch:",
                    reference
                );

                result = {
                    credited: false,
                    reason: "amount_mismatch"
                };

                return;
            }


            /* ---------------------------------
               USER UID CHECK
            --------------------------------- */

            const uid =
                savedPayment.uid;


            if (!uid) {

                console.error(
                    "Payment has no user UID:",
                    reference
                );

                result = {
                    credited: false,
                    reason: "missing_user"
                };

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


            if (
                !Number.isFinite(
                    currentBalance
                ) ||
                currentBalance < 0
            ) {

                throw new Error(
                    "Invalid existing wallet balance."
                );
            }


            const amountNaira =
                Number(
                    (
                        paystackAmount /
                        100
                    ).toFixed(2)
                );


            const newBalance =
                Number(
                    (
                        currentBalance +
                        amountNaira
                    ).toFixed(2)
                );


            if (
                !Number.isFinite(
                    newBalance
                )
            ) {

                throw new Error(
                    "Invalid new wallet balance."
                );
            }


            /* ---------------------------------
               UPDATE WALLET
            --------------------------------- */

            transaction.update(
                userRef,
                {

                    walletBalance:
                        newBalance,

                    updatedAt:
                        FieldValue
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
                        FieldValue
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

                    paystackAmount:
                        paystackAmount,

                    creditedAt:
                        FieldValue
                            .serverTimestamp()
                }
            );


            result = {
                credited: true,
                alreadyCredited: false,
                reason: "credited",
                uid: uid,
                amount: amountNaira,
                reference: reference
            };
        }
    );


    return result;
}


/* =========================================================
   PAYSTACK WEBHOOK
   MUST COME BEFORE express.json()
========================================================= */

app.post(
    "/api/payments/webhook",
    express.raw({
        type: "application/json"
    }),
    async (req, res) => {

        try {

            const signature =
                req.headers[
                    "x-paystack-signature"
                ];

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
                    .createHmac(
                        "sha512",
                        secret
                    )
                    .update(req.body)
                    .digest("hex");


            const signatureBuffer =
                Buffer.from(
                    String(signature),
                    "utf8"
                );

            const expectedBuffer =
                Buffer.from(
                    expectedSignature,
                    "utf8"
                );


            if (
                signatureBuffer.length !==
                expectedBuffer.length ||
                !crypto.timingSafeEqual(
                    signatureBuffer,
                    expectedBuffer
                )
            ) {

                console.warn(
                    "Invalid Paystack webhook signature."
                );

                return res.sendStatus(401);
            }


            /* -----------------------------------------
               PARSE PAYLOAD
            ----------------------------------------- */

            let event;

            try {

                event =
                    JSON.parse(
                        req.body.toString(
                            "utf8"
                        )
                    );

            } catch (error) {

                console.error(
                    "Invalid Paystack webhook JSON:",
                    error
                );

                return res.sendStatus(400);
            }


            /* -----------------------------------------
               ONLY SUCCESSFUL PAYMENTS
            ----------------------------------------- */

            if (
                event.event !==
                "charge.success"
            ) {

                return res.sendStatus(200);
            }


            const payment =
                event.data;


            if (!payment) {

                return res.sendStatus(200);
            }


            /* -----------------------------------------
               CREDIT WALLET
            ----------------------------------------- */

            const result =
                await creditPaystackPayment(
                    payment
                );


            console.log(
                "NovaPay Paystack webhook result:",
                result
            );


            /*
               Returning 200 tells Paystack that the
               webhook was received.

               If the payment was already credited,
               we still return 200 because there is
               nothing else to credit.
            */

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


/* =========================================================
   JSON BODY PARSER
========================================================= */

app.use(
    express.json({
        limit: "10kb"
    })
);


/* =========================================================
   RATE LIMIT
========================================================= */

const apiLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        limit:
            100,

        standardHeaders:
            "draft-7",

        legacyHeaders:
            false
    });


app.use(apiLimiter);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            success:
                true,

            message:
                "NovaPay backend is running."
        });

    }
);


/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/register",
    async (req, res) => {

        try {

            const {
                idToken,
                username,
                password
            } = req.body || {};


            if (!idToken) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Phone verification is required."
                });
            }


            if (!username) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Username is required."
                });
            }


            if (!password) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Password is required."
                });
            }


            const result =
                await registerUser({

                    idToken:
                        idToken,

                    username:
                        username,

                    password:
                        password
                });


            return res.status(201).json({

                success:
                    true,

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

                success:
                    false,

                message:
                    error.message ||
                    "Unable to create account."
            });
        }
    }
);


/* =========================================================
   LOGIN
   PHONE NUMBER + PASSWORD
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const {
                phone,
                password
            } = req.body || {};


            if (!phone) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Phone number is required."
                });
            }


            if (!password) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Password is required."
                });
            }


            /* -----------------------------------------
               NORMALIZE PHONE
            ----------------------------------------- */

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


            /* -----------------------------------------
               FIND USER
            ----------------------------------------- */

            const userQuery =
                await db
                    .collection(
                        "novapayUsers"
                    )
                    .where(
                        "phoneNumber",
                        "==",
                        normalizedPhone
                    )
                    .limit(1)
                    .get();


            if (userQuery.empty) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Incorrect phone number or password."
                });
            }


            const userDoc =
                userQuery.docs[0];

            const user =
                userDoc.data();


            if (
                !user.passwordHash ||
                !user.passwordSalt
            ) {

                console.error(
                    "NovaPay login: password data missing:",
                    userDoc.id
                );


                return res.status(500).json({

                    success:
                        false,

                    message:
                        "This account cannot be logged in at the moment."
                });
            }


            const passwordCorrect =
                await verifyPasswordHash(
                    password,
                    user.passwordSalt,
                    user.passwordHash
                );


            if (!passwordCorrect) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Incorrect phone number or password."
                });
            }


            const uid =
                user.uid ||
                userDoc.id;


            try {

                await auth.getUser(
                    uid
                );

            } catch (error) {

                console.error(
                    "NovaPay login: Firebase user not found:",
                    error
                );


                return res.status(500).json({

                    success:
                        false,

                    message:
                        "Your authentication account could not be found."
                });
            }


            const customToken =
                await auth.createCustomToken(
                    uid,
                    {
                        novaPayUser:
                            true
                    }
                );


            return res.status(200).json({

                success:
                    true,

                message:
                    "Login successful.",

                token:
                    customToken,

                user: {

                    uid:
                        uid,

                    username:
                        user.username ||
                        "",

                    phoneNumber:
                        user.phoneNumber ||
                        "",

                    phoneVerified:
                        user.phoneVerified ===
                        true
                }
            });


        } catch (error) {

            console.error(
                "NovaPay login error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                message:
                    "Unable to process your login right now."
            });
        }
    }
);


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


            if (!idToken) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Verification is required."
                });
            }


            if (!newPassword) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "New password is required."
                });
            }


            if (
                typeof newPassword !==
                    "string" ||
                newPassword.length < 6
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Password must be at least 6 characters."
                });
            }


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

                    success:
                        false,

                    message:
                        "Your verification has expired. Please try again."
                });
            }


            const uid =
                decodedToken.uid;


            const passwordHash =
                await hashPassword(
                    newPassword
                );


            await db
                .collection(
                    "novapayUsers"
                )
                .doc(uid)
                .update({

                    passwordHash:
                        passwordHash,

                    updatedAt:
                        FieldValue
                            .serverTimestamp()
                });


            return res.status(200).json({

                success:
                    true,

                message:
                    "Password updated successfully."
            });


        } catch (error) {

            console.error(
                "Reset password error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                message:
                    "We couldn't update your password right now. Please try again."
            });
        }
    }
); 
/* =========================================================
   PAYSTACK
   INITIALIZE WALLET FUNDING
========================================================= */

app.post(
    "/api/payments/initialize",
    async (req, res) => {

        try {

            /* -----------------------------------------
               AUTHENTICATION
            ----------------------------------------- */

            const authHeader =
                req.headers.authorization ||
                "";


            if (
                !authHeader.startsWith(
                    "Bearer "
                )
            ) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Authentication is required."
                });
            }


            const idToken =
                authHeader.substring(7).trim();


            if (!idToken) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Authentication is required."
                });
            }


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

                    success:
                        false,

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
                !Number.isFinite(
                    amountNumber
                ) ||
                amountNumber < 100
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Enter a valid amount of at least ₦100."
                });
            }


            if (
                amountNumber >
                10000000
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "The payment amount is too large."
                });
            }


            /*
               Only two decimal places are accepted.
            */

            if (
                Math.round(
                    amountNumber * 100
                ) !==
                amountNumber * 100
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Enter a valid amount."
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

                    success:
                        false,

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

                    success:
                        false,

                    message:
                        "Payment service is temporarily unavailable."
                });
            }


            /* -----------------------------------------
               VERIFY NOVAPAY USER
            ----------------------------------------- */

            const userRef =
                db
                    .collection(
                        "novapayUsers"
                    )
                    .doc(uid);


            const userDoc =
                await userRef.get();


            if (!userDoc.exists) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "NovaPay account not found."
                });
            }


            /* -----------------------------------------
               KOBO
            ----------------------------------------- */

            const amountKobo =
                Math.round(
                    amountNumber * 100
                );


            if (
                !Number.isSafeInteger(
                    amountKobo
                )
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Invalid payment amount."
                });
            }


            /* -----------------------------------------
               UNIQUE REFERENCE
            ----------------------------------------- */

            const reference =
                `NP-${uid}-${Date.now()}-${crypto
                    .randomBytes(8)
                    .toString("hex")}`;


            /* -----------------------------------------
               SAVE PENDING PAYMENT
            ----------------------------------------- */

            await db
                .collection(
                    "novapayPayments"
                )
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
                        FieldValue
                            .serverTimestamp()
                });


            /* -----------------------------------------
               INITIALIZE PAYSTACK
            ----------------------------------------- */

            let paystackResponse;


            try {

                paystackResponse =
                    await fetch(
                        "https://api.paystack.co/transaction/initialize",
                        {

                            method:
                                "POST",

                            headers: {

                                "Authorization":
                                    `Bearer ${paystackSecret}`,

                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({

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

            } catch (error) {

                console.error(
                    "Paystack API connection error:",
                    error
                );


                await db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference)
                    .update({

                        status:
                            "initialization_failed",

                        updatedAt:
                            FieldValue
                                .serverTimestamp()
                    });


                return res.status(502).json({

                    success:
                        false,

                    message:
                        "We couldn't connect to the payment service. Please try again."
                });
            }


            let paystackData;


            try {

                paystackData =
                    await paystackResponse.json();

            } catch (error) {

                console.error(
                    "Invalid Paystack response:",
                    error
                );


                await db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference)
                    .update({

                        status:
                            "initialization_failed",

                        updatedAt:
                            FieldValue
                                .serverTimestamp()
                    });


                return res.status(502).json({

                    success:
                        false,

                    message:
                        "The payment service returned an invalid response."
                });
            }


            /* -----------------------------------------
               PAYSTACK ERROR
            ----------------------------------------- */

            if (
                !paystackResponse.ok ||
                !paystackData.status ||
                !paystackData.data
            ) {

                console.error(
                    "Paystack initialization failed:",
                    paystackData
                );


                await db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference)
                    .update({

                        status:
                            "initialization_failed",

                        paystackResponse:
                            paystackData,

                        updatedAt:
                            FieldValue
                                .serverTimestamp()
                    });


                return res.status(502).json({

                    success:
                        false,

                    message:
                        "We couldn't start your payment. Please try again."
                });
            }


            const paymentData =
                paystackData.data;


            if (
                !paymentData.authorization_url ||
                !paymentData.reference
            ) {

                console.error(
                    "Paystack returned incomplete payment data:",
                    paymentData
                );


                await db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference)
                    .update({

                        status:
                            "initialization_failed",

                        updatedAt:
                            FieldValue
                                .serverTimestamp()
                    });


                return res.status(502).json({

                    success:
                        false,

                    message:
                        "Paystack did not return a valid checkout."
                });
            }


            /*
               Paystack should return the same
               reference that NovaPay supplied.

               If it doesn't, do not continue.
            */

            if (
                paymentData.reference !==
                reference
            ) {

                console.error(
                    "Paystack reference mismatch during initialization:",
                    reference,
                    paymentData.reference
                );


                await db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference)
                    .update({

                        status:
                            "initialization_failed",

                        updatedAt:
                            FieldValue
                                .serverTimestamp()
                    });


                return res.status(502).json({

                    success:
                        false,

                    message:
                        "Payment reference verification failed."
                });
            }


            /* -----------------------------------------
               SAVE PAYSTACK DETAILS
            ----------------------------------------- */

            await db
                .collection(
                    "novapayPayments"
                )
                .doc(reference)
                .update({

                    accessCode:
                        paymentData.access_code ||
                        null,

                    authorizationUrl:
                        paymentData.authorization_url,

                    paystackReference:
                        paymentData.reference,

                    status:
                        "initialized",

                    updatedAt:
                        FieldValue
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

                success:
                    false,

                message:
                    "We couldn't start your payment right now."
            });
        }
    }
);


/* =========================================================
   VERIFY PAYSTACK PAYMENT
   SERVER-SIDE VERIFICATION
========================================================= */

app.get(
    "/api/payments/verify/:reference",
    async (req, res) => {

        try {

            /* -----------------------------------------
               AUTHENTICATION
            ----------------------------------------- */

            const authHeader =
                req.headers.authorization ||
                "";


            if (
                !authHeader.startsWith(
                    "Bearer "
                )
            ) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Authentication is required."
                });
            }


            const idToken =
                authHeader.substring(7).trim();


            let decodedToken;


            try {

                decodedToken =
                    await auth.verifyIdToken(
                        idToken
                    );

            } catch (error) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Your session has expired. Please log in again."
                });
            }


            const uid =
                decodedToken.uid;


            /* -----------------------------------------
               REFERENCE
            ----------------------------------------- */

            const reference =
                String(
                    req.params.reference ||
                    ""
                ).trim();


            if (
                !reference ||
                reference.length > 200
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Invalid payment reference."
                });
            }


            /* -----------------------------------------
               FIND NOVAPAY PAYMENT
            ----------------------------------------- */

            const paymentRef =
                db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference);


            const paymentDoc =
                await paymentRef.get();


            if (!paymentDoc.exists) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "Payment record not found."
                });
            }


            const savedPayment =
                paymentDoc.data();


            /* -----------------------------------------
               USER OWNERSHIP CHECK
            ----------------------------------------- */

            if (
                savedPayment.uid !==
                uid
            ) {

                return res.status(403).json({

                    success:
                        false,

                    message:
                        "You are not authorized to verify this payment."
                });
            }


            /* -----------------------------------------
               ALREADY CREDITED
            ----------------------------------------- */

            if (
                savedPayment.status ===
                "credited"
            ) {

                return res.status(200).json({

                    success:
                        true,

                    status:
                        "credited",

                    alreadyCredited:
                        true,

                    reference:
                        reference
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

                    success:
                        false,

                    message:
                        "Payment service is temporarily unavailable."
                });
            }


            /* -----------------------------------------
               ASK PAYSTACK
            ----------------------------------------- */

            let verifyResponse;


            try {

                verifyResponse =
                    await fetch(
                        `https://api.paystack.co/transaction/verify/${encodeURIComponent(
                            reference
                        )}`,
                        {

                            method:
                                "GET",

                            headers: {

                                "Authorization":
                                    `Bearer ${paystackSecret}`,

                                "Content-Type":
                                    "application/json"
                            }
                        }
                    );

            } catch (error) {

                console.error(
                    "Paystack verification connection error:",
                    error
                );


                return res.status(502).json({

                    success:
                        false,

                    message:
                        "We couldn't verify the payment right now."
                });
            }


            let verifyData;


            try {

                verifyData =
                    await verifyResponse.json();

            } catch (error) {

                return res.status(502).json({

                    success:
                        false,

                    message:
                        "The payment service returned an invalid verification response."
                });
            }


            if (
                !verifyResponse.ok ||
                !verifyData.status ||
                !verifyData.data
            ) {

                console.error(
                    "Paystack verification failed:",
                    verifyData
                );


                return res.status(502).json({

                    success:
                        false,

                    message:
                        "Paystack could not verify this payment."
                });
            }


            const payment =
                verifyData.data;


            /* -----------------------------------------
               CONFIRM REFERENCE
            ----------------------------------------- */

            if (
                payment.reference !==
                reference
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Payment reference verification failed."
                });
            }


            /* -----------------------------------------
               CREDIT IF SUCCESSFUL
            ----------------------------------------- */

            const result =
                await creditPaystackPayment(
                    payment,
                    reference
                );


            if (
                result.credited
            ) {

                return res.status(200).json({

                    success:
                        true,

                    status:
                        "credited",

                    credited:
                        true,

                    amount:
                        result.amount,

                    reference:
                        reference
                });
            }


            if (
                result.alreadyCredited
            ) {

                return res.status(200).json({

                    success:
                        true,

                    status:
                        "credited",

                    alreadyCredited:
                        true,

                    reference:
                        reference
                });
            }


            return res.status(200).json({

                success:
                    true,

                status:
                    payment.status ||
                    "pending",

                credited:
                    false,

                reference:
                    reference,

                message:
                    "Payment has not been confirmed as successful yet."
            });


        } catch (error) {

            console.error(
                "NovaPay payment verification error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                message:
                    "We couldn't verify your payment right now."
            });
        }
    }
);


/* =========================================================
   SERVER START
========================================================= */

const PORT =
    process.env.PORT || 3000;


app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `NovaPay backend running on port ${PORT}`
        );

    }
);