const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

/**
 * Generates a 6-character alphanumeric code.
 */
function generateCode() {
  return crypto.randomBytes(4).toString("hex").substring(0, 6);
}

/**
 * POST /shorten
 * Secured Endpoint: Requires Firebase Auth Bearer Token
 */
exports.shorten = functions.https.onRequest(async (req, res) => {
  // CORS configuration
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'POST');
    res.set('Access-Control-Max-Age', '3600');
    return res.status(204).send('');
  }

  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  // Security: Verify the Firebase Auth Token sent from creator.html
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send("Unauthorized: Missing Auth Token");
  }
  
  const idToken = authHeader.split('Bearer ')[1];
  let decodedToken;
  try {
    decodedToken = await admin.auth().verifyIdToken(idToken);
  } catch (error) {
    console.error("Token verification failed:", error);
    return res.status(401).send("Unauthorized: Invalid Token");
  }

  // Extract the data sent from the Creator Panel
  const { url, brandName, config } = req.body;
  if (!url) {
    return res.status(400).send("URL is required");
  }

  try {
    const code = generateCode();
    const shortDoc = db.collection("short_urls").doc(code);

    // Save the complete details to Firestore for the Admin Panel
    await shortDoc.set({
      original_url: url,
      brandName: brandName || "Unnamed Brand",
      config: config || null,
      creator_uid: decodedToken.uid, // Track which admin created it
      owner_email: null, // Claimed later by end-user
      owner_uid: null,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      device_fingerprints: [],
      status: 'active'
    });

    const projectId = process.env.GCLOUD_PROJECT || "metaforge-6afdf";
    const shortUrl = `https://${projectId}.web.app/r/${code}`;

    return res.status(200).json({
      code: code,
      shortUrl: shortUrl
    });
  } catch (error) {
    console.error("Error shortening URL:", error);
    return res.status(500).send("Internal Server Error");
  }
});

/**
 * GET /{code}
 * Performs 301 redirect and passes the code to the engine
 */
exports.redirect = functions.https.onRequest(async (req, res) => {
  const code = req.path.split("/").pop();
  if (!code || code.length !== 6) {
    return res.status(400).send("Invalid code");
  }

  try {
    const doc = await db.collection("short_urls").doc(code).get();
    if (!doc.exists) {
      return res.status(404).send("URL not found");
    }

    let originalUrl = doc.data().original_url;
    // Append the short code to the hash so engine.html can detect it's a claimable link
    const separator = originalUrl.includes("#") ? "_sc=" : "#sc=";
    originalUrl += `${separator}${code}`;
    
    res.set("Cache-Control", "public, max-age=3600");
    return res.redirect(301, originalUrl);
  } catch (error) {
    console.error("Error redirecting:", error);
    return res.status(500).send("Internal Server Error");
  }
});
