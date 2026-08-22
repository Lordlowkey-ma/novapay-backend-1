const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

require("./firebase");

const { getAuth } =
    require("firebase-admin/auth");

const {
    getFirestore,
    FieldValue
} =
    require("firebase-admin/firestore");


const app = express();

const auth = getAuth();
const db = getFirestore();

const PORT =
    Number(
        process.env.PORT || 3000
    );


/* =========================================================
   PAYSTACK WEBHOOK
   ---------------------------------------------------------
   IMPORTANT:
   The webhook must receive the raw request body before
   express.json() processes normal JSON requests.
========================================================= */

app.post(
    "/api/payments/webhook",
    express.raw({
        type: "application/json"
    }),
    async (req, res) => {

        try {

            if (
                !PAYSTACK_SECRET_KEY
            ) {

                return res
                    .status(500)
                    .send(
                        "Webhook unavailable."
                    );
            }


            const rawBody =
                Buffer.isBuffer(
                    req.body
                )
                    ? req.body
                    : Buffer.from("");


            const signature =
                String(
                    req.headers[
                        "x-paystack-signature"
                    ] || ""
                ).trim();


            if (!signature) {

                return res
                    .status(401)
                    .send(
                        "Invalid signature."
                    );
            }


            const expectedSignature =
                crypto
                    .createHmac(
                        "sha512",
                        PAYSTACK_SECRET_KEY
                    )
                    .update(rawBody)
                    .digest("hex");


            const received =
                Buffer.from(
                    signature,
                    "utf8"
                );


            const expected =
                Buffer.from(
                    expectedSignature,
                    "utf8"
                );


            if (
                received.length !==
                    expected.length ||
                !crypto.timingSafeEqual(
                    received,
                    expected
                )
            ) {

                return res
                    .status(401)
                    .send(
                        "Invalid signature."
                    );
            }


            const event =
                JSON.parse(
                    rawBody.toString(
                        "utf8"
                    )
                );


            if (
                event.event !==
                "charge.success"
            ) {

                return res
                    .status(200)
                    .send(
                        "Event received."
                    );
            }


            const transaction =
                event.data || {};


            const reference =
                String(
                    transaction.reference ||
                    ""
                ).trim();


            if (
                !reference ||
                transaction.status !==
                    "success" ||
                String(
                    transaction.currency ||
                    ""
                ).toUpperCase() !==
                    "NGN"
            ) {

                return res
                    .status(200)
                    .send(
                        "Event received."
                    );
            }


            const paymentSnapshot =
                await db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference)
                    .get();


            if (
                !paymentSnapshot.exists
            ) {

                return res
                    .status(200)
                    .send(
                        "Event received."
                    );
            }


            const savedPayment =
                paymentSnapshot.data() ||
                {};


            if (
                !savedPayment.uid
            ) {

                return res
                    .status(200)
                    .send(
                        "Event received."
                    );
            }


            const result =
                await creditPayment(
                    reference,
                    transaction
                );


            console.log(
                "Paystack webhook processed:",
                {
                    reference,
                    result
                }
            );


            return res
                .status(200)
                .send(
                    "Event processed."
                );

        } catch (error) {

            console.error(
                "Paystack webhook error:",
                error
            );


            return res
                .status(500)
                .send(
                    "Webhook processing failed."
                );
        }
    }
);


/* =========================================================
   BODY PARSING
========================================================= */

app.use(
    express.json({
        limit: "1mb"
    })
);


app.use(
    express.urlencoded({
        extended: true,
        limit: "1mb"
    })
);


const FRONTEND_URL =
    "https://lordlowkey-ma.github.io/NovaPay1";


const PAYSTACK_SECRET_KEY =
    process.env.PAYSTACK_SECRET_KEY;


/* =========================================================
   SECURITY
========================================================= */

app.use(
    helmet()
);


app.use(
    cors({
        origin: [
            FRONTEND_URL
        ],
        credentials: true
    })
);


/* =========================================================
   RATE LIMIT
========================================================= */

const apiLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max:
            300,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


app.use(
    "/api",
    apiLimiter
);


/* =========================================================
   FIREBASE AUTHENTICATION
========================================================= */

async function requireUser(req) {

    const authorization =
        String(
            req.headers.authorization ||
            ""
        );


    if (
        !authorization.startsWith(
            "Bearer "
        )
    ) {

        const error =
            new Error(
                "Authentication required."
            );

        error.statusCode =
            401;

        throw error;
    }


    const token =
        authorization
            .slice(7)
            .trim();


    if (!token) {

        const error =
            new Error(
                "Authentication required."
            );

        error.statusCode =
            401;

        throw error;
    }


    try {

        const decoded =
            await auth.verifyIdToken(
                token
            );


        return decoded;

    } catch (error) {

        console.error(
            "Firebase authentication failed:",
            error.message
        );


        const authError =
            new Error(
                "Your session has expired. Please log in again."
            );


        authError.statusCode =
            401;


        throw authError;
    }
}


/* =========================================================
   FIRESTORE USER HELPERS
========================================================= */

async function getUserDocument(
    uid
) {

    const userRef =
        db
            .collection("users")
            .doc(uid);


    const snapshot =
        await userRef.get();


    if (
        !snapshot.exists
    ) {

        return {
            ref: userRef,
            exists: false,
            data: {}
        };
    }


    return {
        ref: userRef,
        exists: true,
        data:
            snapshot.data() || {}
    };
}


/* =========================================================
   NUMBER HELPERS
========================================================= */

function toFiniteNumber(
    value,
    fallback = 0
) {

    const number =
        Number(value);


    return Number.isFinite(
        number
    )
        ? number
        : fallback;
}


function toNairaFromKobo(
    amountKobo
) {

    return (
        toFiniteNumber(
            amountKobo,
            0
        ) / 100
    );
}


function toKoboFromNaira(
    amountNaira
) {

    return Math.round(
        toFiniteNumber(
            amountNaira,
            0
        ) * 100
    );
}


/* =========================================================
   PAYMENT CONSTANTS
========================================================= */

const MIN_DEPOSIT_NAIRA =
    50;


const MAX_DEPOSIT_NAIRA =
    1000000;


/* =========================================================
   PAYMENT VALIDATION
========================================================= */

function validateDepositAmount(
    amountNaira
) {

    const amount =
        Number(
            amountNaira
        );


    if (
        !Number.isFinite(
            amount
        )
    ) {

        return {
            valid: false,
            message:
                "Invalid payment amount."
        };
    }


    if (
        amount <
        MIN_DEPOSIT_NAIRA
    ) {

        return {
            valid: false,
            message:
                "Minimum amount is ₦50."
        };
    }


    if (
        amount >
        MAX_DEPOSIT_NAIRA
    ) {

        return {
            valid: false,
            message:
                "Maximum amount is ₦1,000,000."
        };
    }


    if (
        Math.round(
            amount * 100
        ) !==
        amount * 100
    ) {

        return {
            valid: false,
            message:
                "Amount can have no more than two decimal places."
        };
    }


    return {
        valid: true,
        amount:
            Number(
                amount.toFixed(2)
            )
    };
} 
/* =========================================================
   GET USER WALLET
========================================================= */

async function getWalletBalance(
    uid
) {

    const user =
        await getUserDocument(
            uid
        );


    const balance =
        toFiniteNumber(
            user.data.walletBalance ??
            user.data.balance ??
            0,
            0
        );


    return balance;
}


/* =========================================================
   CREATE PAYMENT REFERENCE
========================================================= */

function createPaymentReference() {

    return (
        "NP_" +
        Date.now() +
        "_" +
        crypto
            .randomBytes(8)
            .toString("hex")
    );
}


/* =========================================================
   CREDIT VERIFIED PAYMENT
   ---------------------------------------------------------
   This function is the ONLY place where a successful
   payment is allowed to increase the user's wallet.
========================================================= */

async function creditPayment(
    reference,
    transaction
) {

    if (!reference) {

        return {
            success: false,
            reason:
                "Missing payment reference."
        };
    }


    const transactionReference =
        String(
            transaction?.reference ||
            ""
        ).trim();


    if (
        transactionReference !==
        reference
    ) {

        return {
            success: false,
            reason:
                "Payment reference mismatch."
        };
    }


    if (
        transaction?.status !==
        "success"
    ) {

        return {
            success: false,
            reason:
                "Payment was not successful."
        };
    }


    const currency =
        String(
            transaction?.currency ||
            ""
        ).toUpperCase();


    if (
        currency !==
        "NGN"
    ) {

        return {
            success: false,
            reason:
                "Invalid payment currency."
        };
    }


    const paymentRef =
        db
            .collection(
                "novapayPayments"
            )
            .doc(reference);


    return db.runTransaction(
        async (firestoreTransaction) => {

            const paymentSnapshot =
                await firestoreTransaction.get(
                    paymentRef
                );


            if (
                !paymentSnapshot.exists
            ) {

                return {
                    success: false,
                    reason:
                        "Payment record not found."
                };
            }


            const payment =
                paymentSnapshot.data() ||
                {};


            const uid =
                String(
                    payment.uid ||
                    ""
                ).trim();


            if (!uid) {

                return {
                    success: false,
                    reason:
                        "Payment has no user."
                };
            }


            /*
             * Duplicate protection.
             *
             * If the payment was already credited,
             * NEVER add it again.
             */

            if (
                payment.status ===
                "credited"
            ) {

                return {
                    success: true,
                    alreadyCredited:
                        true,
                    uid,
                    walletBalance:
                        toFiniteNumber(
                            payment.balanceAfter,
                            0
                        )
                };
            }


            const savedAmountKobo =
                toFiniteNumber(
                    payment.amountKobo,
                    0
                );


            const paystackAmountKobo =
                toFiniteNumber(
                    transaction.amount,
                    0
                );


            /*
             * The amount Paystack confirms MUST match
             * the amount NovaPay originally initialized.
             */

            if (
                savedAmountKobo <= 0
            ) {

                return {
                    success: false,
                    reason:
                        "Invalid saved payment amount."
                };
            }


            if (
                paystackAmountKobo !==
                savedAmountKobo
            ) {

                return {
                    success: false,
                    reason:
                        "Payment amount mismatch."
                };
            }


            const amountNaira =
                toNairaFromKobo(
                    savedAmountKobo
                );


            const amountValidation =
                validateDepositAmount(
                    amountNaira
                );


            if (
                !amountValidation.valid
            ) {

                return {
                    success: false,
                    reason:
                        amountValidation.message
                };
            }


            /*
             * Get the user's wallet document.
             */

            const userRef =
                db
                    .collection(
                        "users"
                    )
                    .doc(uid);


            const userSnapshot =
                await firestoreTransaction.get(
                    userRef
                );


            if (
                !userSnapshot.exists
            ) {

                return {
                    success: false,
                    reason:
                        "User wallet was not found."
                };
            }


            const user =
                userSnapshot.data() ||
                {};


            const currentBalance =
                toFiniteNumber(
                    user.walletBalance ??
                    user.balance ??
                    0,
                    0
                );


            const newBalance =
                Number(
                    (
                        currentBalance +
                        amountNaira
                    ).toFixed(2)
                );


            /*
             * Update the canonical wallet balance.
             */

            firestoreTransaction.update(
                userRef,
                {
                    walletBalance:
                        newBalance,

                    updatedAt:
                        FieldValue.serverTimestamp()
                }
            );


            /*
             * Mark the payment as credited.
             *
             * This is what prevents the same Paystack
             * payment from being credited twice.
             */

            firestoreTransaction.update(
                paymentRef,
                {
                    status:
                        "credited",

                    amountNaira:
                        amountNaira,

                    amountKobo:
                        savedAmountKobo,

                    paystackAmountKobo:
                        paystackAmountKobo,

                    balanceBefore:
                        currentBalance,

                    balanceAfter:
                        newBalance,

                    creditedAt:
                        FieldValue.serverTimestamp(),

                    updatedAt:
                        FieldValue.serverTimestamp()
                }
            );


            /*
             * Save the wallet transaction.
             */

            const walletTransactionRef =
                db
                    .collection(
                        "users"
                    )
                    .doc(uid)
                    .collection(
                        "transactions"
                    )
                    .doc(reference);


            firestoreTransaction.set(
                walletTransactionRef,
                {
                    reference:
                        reference,

                    type:
                        "deposit",

                    category:
                        "wallet",

                    description:
                        "Wallet funding",

                    amount:
                        amountNaira,

                    amountNaira:
                        amountNaira,

                    amountKobo:
                        savedAmountKobo,

                    currency:
                        "NGN",

                    direction:
                        "credit",

                    status:
                        "successful",

                    balanceBefore:
                        currentBalance,

                    balanceAfter:
                        newBalance,

                    paystackTransactionId:
                        transaction.id ||
                        null,

                    createdAt:
                        FieldValue.serverTimestamp(),

                    updatedAt:
                        FieldValue.serverTimestamp()
                }
            );


            return {
                success: true,

                alreadyCredited:
                    false,

                uid,

                walletBalance:
                    newBalance,

                amountNaira
            };
        }
    );
}


/* =========================================================
   INITIALIZE PAYMENT
========================================================= */

app.post(
    "/api/payments/initialize",
    async (req, res) => {

        try {

            const decodedUser =
                await requireUser(
                    req
                );


            const uid =
                decodedUser.uid;


            const amountNaira =
                Number(
                    req.body?.amountNaira
                );


            const email =
                String(
                    req.body?.email ||
                    decodedUser.email ||
                    ""
                )
                    .trim()
                    .toLowerCase();


            const validation =
                validateDepositAmount(
                    amountNaira
                );


            if (
                !validation.valid
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        validation.message
                });
            }


            if (!email) {

                return res.status(400).json({

                    success: false,

                    message:
                        "A valid email address is required."
                });
            }


            if (
                !PAYSTACK_SECRET_KEY
            ) {

                console.error(
                    "PAYSTACK_SECRET_KEY is missing."
                );


                return res.status(500).json({

                    success: false,

                    message:
                        "Payment service is temporarily unavailable."
                });
            }


            const amountKobo =
                toKoboFromNaira(
                    validation.amount
                );


            const reference =
                createPaymentReference();


            const paymentRef =
                db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference);


            await paymentRef.set({

                reference,

                uid,

                email,

                amountNaira:
                    validation.amount,

                amountKobo,

                currency:
                    "NGN",

                status:
                    "initialized",

                createdAt:
                    FieldValue.serverTimestamp(),

                updatedAt:
                    FieldValue.serverTimestamp()
            });


            let paystackResponse;


            try {

                paystackResponse =
                    await fetch(
                        "https://api.paystack.co/transaction/initialize",
                        {

                            method:
                                "POST",

                            headers: {

                                Authorization:
                                    `Bearer ${PAYSTACK_SECRET_KEY}`,

                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({

                                    email,

                                    amount:
                                        amountKobo,

                                    reference,

                                    callback_url:
                                        `${FRONTEND_URL}/add-money.html`
                                })
                        }
                    );

            } catch (error) {

                console.error(
                    "Paystack connection error:",
                    error
                );


                await paymentRef.update({

                    status:
                        "initialization_failed",

                    updatedAt:
                        FieldValue.serverTimestamp()
                });


                return res.status(502).json({

                    success: false,

                    message:
                        "Unable to contact the payment service."
                });
            }


            let paystackData;


            try {

                paystackData =
                    await paystackResponse.json();

            } catch (error) {

                await paymentRef.update({

                    status:
                        "initialization_failed",

                    updatedAt:
                        FieldValue.serverTimestamp()
                });


                return res.status(502).json({

                    success: false,

                    message:
                        "Invalid response from payment service."
                });
            }


            if (
                !paystackResponse.ok ||
                !paystackData.status ||
                !paystackData.data
            ) {

                console.error(
                    "Paystack initialization failed:",
                    paystackData
                );


                await paymentRef.update({

                    status:
                        "initialization_failed",

                    paystackResponse:
                        paystackData,

                    updatedAt:
                        FieldValue.serverTimestamp()
                });


                return res.status(400).json({

                    success: false,

                    message:
                        paystackData?.message ||
                        "Unable to initialize payment."
                });
            }


            await paymentRef.update({

                status:
                    "pending",

                authorizationUrl:
                    paystackData.data.authorization_url,

                accessCode:
                    paystackData.data.access_code,

                updatedAt:
                    FieldValue.serverTimestamp()
            });


            return res.status(200).json({

                success: true,

                reference,

                authorization_url:
                    paystackData.data.authorization_url,

                access_code:
                    paystackData.data.access_code,

                amountNaira:
                    validation.amount,

                amountKobo
            });

        } catch (error) {

            console.error(
                "Payment initialization error:",
                error
            );


            const statusCode =
                error.statusCode ||
                500;


            return res.status(
                statusCode
            ).json({

                success: false,

                message:
                    statusCode === 401
                        ? "Your session has expired. Please log in again."
                        : "Unable to initialize payment."
            });
        }
    }
);
/* =========================================================
   VERIFY PAYMENT
   ---------------------------------------------------------
   Paystack is checked directly from the server.
   The browser cannot declare a payment successful.
========================================================= */

app.get(
    "/api/payments/verify/:reference",
    async (req, res) => {

        try {

            const decodedUser =
                await requireUser(req);


            const uid =
                decodedUser.uid;


            const reference =
                String(
                    req.params.reference ||
                    ""
                ).trim();


            if (!reference) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Payment reference is required."
                });
            }


            const paymentRef =
                db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference);


            const paymentSnapshot =
                await paymentRef.get();


            if (
                !paymentSnapshot.exists
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Payment record not found."
                });
            }


            const savedPayment =
                paymentSnapshot.data() ||
                {};


            /*
             * Make sure the authenticated user owns
             * this payment.
             */

            if (
                String(
                    savedPayment.uid ||
                    ""
                ) !== uid
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        "This payment does not belong to your account."
                });
            }


            /*
             * If the webhook already credited this payment,
             * simply return the fresh wallet balance.
             */

            if (
                savedPayment.status ===
                "credited"
            ) {

                const walletBalance =
                    await getWalletBalance(
                        uid
                    );


                return res.status(200).json({

                    success: true,

                    status:
                        "credited",

                    alreadyCredited:
                        true,

                    reference,

                    amountNaira:
                        toFiniteNumber(
                            savedPayment.amountNaira,
                            0
                        ),

                    walletBalance
                });
            }


            if (
                !PAYSTACK_SECRET_KEY
            ) {

                console.error(
                    "PAYSTACK_SECRET_KEY is missing."
                );


                return res.status(500).json({

                    success: false,

                    message:
                        "Payment service is temporarily unavailable."
                });
            }


            let paystackResponse;


            try {

                paystackResponse =
                    await fetch(
                        `https://api.paystack.co/transaction/verify/${encodeURIComponent(
                            reference
                        )}`,
                        {

                            method:
                                "GET",

                            headers: {

                                Authorization:
                                    `Bearer ${PAYSTACK_SECRET_KEY}`,

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

                    success: false,

                    message:
                        "Unable to contact the payment service."
                });
            }


            let paystackData;


            try {

                paystackData =
                    await paystackResponse.json();

            } catch (error) {

                console.error(
                    "Invalid Paystack verification response:",
                    error
                );


                return res.status(502).json({

                    success: false,

                    message:
                        "Invalid response from payment service."
                });
            }


            if (
                !paystackResponse.ok ||
                !paystackData.status ||
                !paystackData.data
            ) {

                console.error(
                    "Paystack verification failed:",
                    paystackData
                );


                return res.status(400).json({

                    success: false,

                    message:
                        "Unable to verify this payment."
                });
            }


            const transaction =
                paystackData.data;


            /*
             * Reference must match exactly.
             */

            if (
                String(
                    transaction.reference ||
                    ""
                ) !== reference
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Payment reference verification failed."
                });
            }


            /*
             * Only a successful Paystack transaction
             * can credit the wallet.
             */

            if (
                transaction.status !==
                "success"
            ) {

                return res.status(400).json({

                    success: false,

                    status:
                        transaction.status ||
                        "pending",

                    message:
                        "This payment has not been completed."
                });
            }


            /*
             * Currency must be NGN.
             */

            if (
                String(
                    transaction.currency ||
                    ""
                ).toUpperCase() !==
                "NGN"
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid payment currency."
                });
            }


            /*
             * Credit the payment using the same
             * duplicate-safe function used by the webhook.
             */

            const creditResult =
                await creditPayment(
                    reference,
                    transaction
                );


            if (
                !creditResult.success
            ) {

                return res.status(400).json({

                    success: false,

                    status:
                        "failed",

                    message:
                        creditResult.reason ||
                        "Payment could not be credited."
                });
            }


            /*
             * Read Firestore again after the credit.
             *
             * This is important:
             * the dashboard and payment response use
             * the actual wallet balance stored in Firestore.
             */

            const walletBalance =
                await getWalletBalance(
                    uid
                );


            return res.status(200).json({

                success: true,

                status:
                    "credited",

                alreadyCredited:
                    Boolean(
                        creditResult.alreadyCredited
                    ),

                reference,

                amountNaira:
                    toFiniteNumber(
                        creditResult.amountNaira ??
                        savedPayment.amountNaira,
                        0
                    ),

                walletBalance
            });

        } catch (error) {

            console.error(
                "Payment verification error:",
                error
            );


            const statusCode =
                error.statusCode ||
                500;


            return res.status(
                statusCode
            ).json({

                success: false,

                message:
                    statusCode === 401
                        ? "Your session has expired. Please log in again."
                        : "Unable to verify your payment."
            });
        }
    }
);


/* =========================================================
   PAYMENT STATUS
========================================================= */

app.get(
    "/api/payments/status/:reference",
    async (req, res) => {

        try {

            const decodedUser =
                await requireUser(req);


            const uid =
                decodedUser.uid;


            const reference =
                String(
                    req.params.reference ||
                    ""
                ).trim();


            if (!reference) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Payment reference is required."
                });
            }


            const paymentSnapshot =
                await db
                    .collection(
                        "novapayPayments"
                    )
                    .doc(reference)
                    .get();


            if (
                !paymentSnapshot.exists
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Payment record not found."
                });
            }


            const payment =
                paymentSnapshot.data() ||
                {};


            /*
             * Payment ownership check.
             */

            if (
                String(
                    payment.uid ||
                    ""
                ) !== uid
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        "This payment does not belong to your account."
                });
            }


            /*
             * Always read the current balance from
             * Firestore rather than trusting an old
             * payment response.
             */

            const walletBalance =
                await getWalletBalance(
                    uid
                );


            return res.status(200).json({

                success: true,

                reference,

                status:
                    payment.status ||
                    "pending",

                amountNaira:
                    toFiniteNumber(
                        payment.amountNaira ??
                        toNairaFromKobo(
                            payment.amountKobo
                        ),
                        0
                    ),

                amountKobo:
                    toFiniteNumber(
                        payment.amountKobo,
                        0
                    ),

                currency:
                    payment.currency ||
                    "NGN",

                walletBalance
            });

        } catch (error) {

            console.error(
                "Payment status error:",
                error
            );


            const statusCode =
                error.statusCode ||
                500;


            return res.status(
                statusCode
            ).json({

                success: false,

                message:
                    statusCode === 401
                        ? "Your session has expired. Please log in again."
                        : "Unable to check payment status."
            });
        }
    }
);


/* =========================================================
   DASHBOARD
   ---------------------------------------------------------
   Returns the current wallet balance directly from
   Firestore every time.
========================================================= */

app.get(
    "/api/dashboard",
    async (req, res) => {

        try {

            const decodedUser =
                await requireUser(req);


            const uid =
                decodedUser.uid;


            const user =
                await getUserDocument(
                    uid
                );


            const walletBalance =
                toFiniteNumber(
                    user.data.walletBalance ??
                    user.data.balance ??
                    0,
                    0
                );


            /*
             * Load recent transactions.
             */

            let recentTransactions =
                [];


            try {

                const transactionSnapshot =
                    await db
                        .collection(
                            "users"
                        )
                        .doc(uid)
                        .collection(
                            "transactions"
                        )
                        .orderBy(
                            "createdAt",
                            "desc"
                        )
                        .limit(10)
                        .get();


                recentTransactions =
                    transactionSnapshot.docs.map(
                        (doc) => {

                            const data =
                                doc.data() ||
                                {};


                            return {

                                id:
                                    doc.id,

                                ...data
                            };
                        }
                    );

            } catch (error) {

                /*
                 * If the transaction query fails because
                 * an index is unavailable, the dashboard
                 * balance should still work.
                 */

                console.warn(
                    "Recent transaction query failed:",
                    error.message
                );
            }


            return res.status(200).json({

                success: true,

                balance:
                    walletBalance,

                walletBalance,

                user: {

                    uid,

                    email:
                        decodedUser.email ||
                        user.data.email ||
                        "",

                    displayName:
                        user.data.displayName ||
                        decodedUser.name ||
                        "",

                    walletBalance
                },

                transactions:
                    recentTransactions,

                recentTransactions
            });

        } catch (error) {

            console.error(
                "Dashboard error:",
                error
            );


            const statusCode =
                error.statusCode ||
                500;


            return res.status(
                statusCode
            ).json({

                success: false,

                message:
                    statusCode === 401
                        ? "Your session has expired. Please log in again."
                        : "Unable to load dashboard."
            });
        }
    }
);
/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    "/health",
    (req, res) => {

        return res.status(200).json({

            success: true,

            service:
                "NovaPay Backend",

            status:
                "online",

            timestamp:
                new Date().toISOString()
        });
    }
);


/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        return res.status(200).json({

            success: true,

            service:
                "NovaPay Backend",

            status:
                "online"
        });
    }
);


/* =========================================================
   404 HANDLER
========================================================= */

app.use(
    (req, res) => {

        return res.status(404).json({

            success: false,

            message:
                "Endpoint not found."
        });
    }
);


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "NovaPay server error:",
            error
        );


        if (
            res.headersSent
        ) {

            return next(error);
        }


        return res.status(
            error.statusCode || 500
        ).json({

            success: false,

            message:
                error.statusCode === 401
                    ? "Your session has expired. Please log in again."
                    : "An unexpected server error occurred."
        });
    }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            "=========================================="
        );

        console.log(
            "NovaPay Backend Started"
        );

        console.log(
            `Port: ${PORT}`
        );

        console.log(
            `Frontend: ${FRONTEND_URL}`
        );

        console.log(
            `Minimum deposit: ₦${MIN_DEPOSIT_NAIRA}`
        );

        console.log(
            `Maximum deposit: ₦${MAX_DEPOSIT_NAIRA.toLocaleString("en-NG")}`
        );

        console.log(
            "Paystack: configured"
        );

        console.log(
            "=========================================="
        );
    }
);