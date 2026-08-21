const {
  initializeApp,
  cert,
  getApps,
  getApp
} = require("firebase-admin/app");

const secret = process.env.NOVAPAY_FIREBASE_SERVICE_ACCOUNT;

if (!secret) {
  throw new Error(
    "NOVAPAY_FIREBASE_SERVICE_ACCOUNT secret is not available."
  );
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(secret);
} catch (error) {
  throw new Error(
    "NOVAPAY_FIREBASE_SERVICE_ACCOUNT is not valid JSON."
  );
}

/*
=========================================================
NOVAPAY FIREBASE ADMIN INITIALIZATION
=========================================================

Reuse the existing Firebase Admin app if one already
exists. Otherwise create it.

This prevents:

Firebase app named "[DEFAULT]" already exists
=========================================================
*/

const firebaseApp = getApps().length
  ? getApp()
  : initializeApp({
      credential: cert(serviceAccount)
    });

console.log("Firebase Admin connected successfully.");

module.exports = firebaseApp;