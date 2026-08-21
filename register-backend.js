/**
 * =========================================================
 * NOVAPAY — REGISTRATION BACKEND
 * =========================================================
 *
 * Registration flow:
 *
 * Phone number
 *      ↓
 * Firebase Phone Auth / test code
 *      ↓
 * Firebase verifies phone
 *      ↓
 * Frontend receives Firebase ID token
 *      ↓
 * Backend verifies Firebase ID token
 *      ↓
 * Username + NovaPay password
 *      ↓
 * Password is securely hashed
 *      ↓
 * NovaPay account created
 *
 * =========================================================
 */

const crypto = require("crypto");

/*
 * IMPORTANT:
 * server.js loads ./firebase first.
 *
 * That file is responsible for initializing Firebase Admin.
 *
 * We do NOT initialize Firebase Admin again here.
 */

require("./firebase");

const {
    getAuth
} = require("firebase-admin/auth");

const {
    getFirestore,
    FieldValue
} = require("firebase-admin/firestore");


/* =========================================================
   FIREBASE SERVICES
   ========================================================= */

const auth = getAuth();

const db = getFirestore();


/* =========================================================
   PASSWORD SETTINGS
   ========================================================= */

const PASSWORD_MIN_LENGTH = 8;


/* =========================================================
   PASSWORD HASHING
   ========================================================= */

function hashPassword(password) {

    return new Promise((resolve, reject) => {

        const salt =
            crypto
                .randomBytes(16)
                .toString("hex");

        crypto.scrypt(
            password,
            salt,
            64,
            {
                N: 16384,
                r: 8,
                p: 1
            },
            (error, derivedKey) => {

                if (error) {
                    reject(error);
                    return;
                }

                resolve({
                    salt: salt,
                    hash: derivedKey.toString("hex")
                });
            }
        );
    });
}


/* =========================================================
   PASSWORD VERIFICATION
   ========================================================= */

function verifyPasswordHash(
    password,
    salt,
    storedHash
) {

    return new Promise((resolve, reject) => {

        crypto.scrypt(
            password,
            salt,
            64,
            {
                N: 16384,
                r: 8,
                p: 1
            },
            (error, derivedKey) => {

                if (error) {
                    reject(error);
                    return;
                }

                try {

                    const calculatedHash =
                        derivedKey.toString("hex");

                    const a =
                        Buffer.from(
                            calculatedHash,
                            "hex"
                        );

                    const b =
                        Buffer.from(
                            storedHash,
                            "hex"
                        );

                    if (a.length !== b.length) {
                        resolve(false);
                        return;
                    }

                    resolve(
                        crypto.timingSafeEqual(a, b)
                    );

                } catch (error) {

                    resolve(false);
                }
            }
        );
    });
}


/* =========================================================
   PHONE NORMALIZATION
   ========================================================= */

function normalizePhone(phone) {

    if (!phone) {
        return "";
    }

    return String(phone)
        .trim()
        .replace(/\s+/g, "");
}


/* =========================================================
   USERNAME VALIDATION
   ========================================================= */

function validateUsername(username) {

    if (!username) {
        return "Username is required.";
    }

    if (username.length < 3) {
        return "Username must be at least 3 characters.";
    }

    if (username.length > 30) {
        return "Username must not exceed 30 characters.";
    }

    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
        return "Username can only contain letters, numbers, dots, underscores and hyphens.";
    }

    return null;
}


/* =========================================================
   PASSWORD VALIDATION
   ========================================================= */

function validatePassword(password) {

    if (!password) {
        return "Password is required.";
    }

    if (password.length < PASSWORD_MIN_LENGTH) {
        return `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
    }

    return null;
}


/* =========================================================
   REGISTER USER
   ========================================================= */

async function registerUser({
    idToken,
    username,
    password
}) {

    /* -------------------------------------------------------
       BASIC VALIDATION
    ------------------------------------------------------- */

    if (!idToken) {

        throw new Error(
            "Phone verification is required before creating the account."
        );
    }


    username =
        String(username || "").trim();

    password =
        String(password || "");


    const usernameError =
        validateUsername(username);

    if (usernameError) {
        throw new Error(usernameError);
    }


    const passwordError =
        validatePassword(password);

    if (passwordError) {
        throw new Error(passwordError);
    }


    /* -------------------------------------------------------
       VERIFY FIREBASE PHONE AUTH TOKEN
    ------------------------------------------------------- */

    let decodedToken;

    try {

        decodedToken =
            await auth.verifyIdToken(idToken);

    } catch (error) {

        console.error(
            "Firebase ID token verification failed:",
            error
        );

        throw new Error(
            "Your phone verification session is invalid or has expired. Please verify your phone again."
        );
    }


    /* -------------------------------------------------------
       GET VERIFIED PHONE NUMBER
    ------------------------------------------------------- */

    const uid =
        decodedToken.uid;

    const phoneNumber =
        normalizePhone(
            decodedToken.phone_number
        );


    if (!phoneNumber) {

        throw new Error(
            "A verified phone number is required."
        );
    }


    /* -------------------------------------------------------
       CONFIRM FIREBASE USER
    ------------------------------------------------------- */

    let firebaseUser;

    try {

        firebaseUser =
            await auth.getUser(uid);

    } catch (error) {

        console.error(
            "Unable to retrieve Firebase user:",
            error
        );

        throw new Error(
            "We could not retrieve your verified account."
        );
    }


    if (!firebaseUser.phoneNumber) {

        throw new Error(
            "Your Firebase account does not contain a verified phone number."
        );
    }


    /* -------------------------------------------------------
       NOVAPAY USER DOCUMENT
    ------------------------------------------------------- */

    const userRef =
        db
            .collection("novapayUsers")
            .doc(uid);


    const existingUser =
        await userRef.get();


    if (existingUser.exists) {

        throw new Error(
            "A NovaPay account already exists for this phone number."
        );
    }


    /* -------------------------------------------------------
       CHECK USERNAME
    ------------------------------------------------------- */

    const usernameQuery =
        await db
            .collection("novapayUsers")
            .where(
                "usernameLower",
                "==",
                username.toLowerCase()
            )
            .limit(1)
            .get();


    if (!usernameQuery.empty) {

        throw new Error(
            "That username is already taken."
        );
    }


    /* -------------------------------------------------------
       HASH NOVAPAY PASSWORD
    ------------------------------------------------------- */

    const passwordData =
        await hashPassword(password);


    /* -------------------------------------------------------
       CREATE NOVAPAY USER
    ------------------------------------------------------- */

    await userRef.set({

        uid: uid,

        username: username,

        usernameLower:
            username.toLowerCase(),

        phoneNumber: phoneNumber,

        passwordHash:
            passwordData.hash,

        passwordSalt:
            passwordData.salt,

        phoneVerified: true,

        createdAt:
            FieldValue.serverTimestamp(),

        updatedAt:
            FieldValue.serverTimestamp()

    });


    /* -------------------------------------------------------
       SAFE RESPONSE
    ------------------------------------------------------- */

    return {

        success: true,

        uid: uid,

        username: username,

        phoneNumber: phoneNumber,

        phoneVerified: true,

        message:
            "Your NovaPay account was created successfully."

    };
}


/* =========================================================
   EXPORT
   ========================================================= */

module.exports = {

    registerUser,

    hashPassword,

    verifyPasswordHash

};