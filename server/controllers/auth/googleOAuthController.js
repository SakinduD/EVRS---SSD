import * as client from "openid-client";
import jwt from "jsonwebtoken";
import Citizen from "../../models/patientModel.js";

/**
 * "Sign in with Google" for citizens: OpenID Connect Authorization Code flow
 * with PKCE (S256), state and nonce.
 *
 *   GET /api/auth/oauth/google           -> redirect to Google
 *   GET /api/auth/oauth/google/callback  -> code exchange, then session cookie
 */

const GOOGLE_ISSUER = new URL("https://accounts.google.com");
const TX_COOKIE = "oauth_tx";
const TX_AUDIENCE = "evrs-oauth-transaction";
const TX_TTL_MS = 10 * 60 * 1000;
const TX_PATH = "/api/auth/oauth";

const isProd = () => process.env.NODE_ENV === "production";

// env is read lazily: this module is imported before server.js runs dotenv.config()
let configPromise;
function getConfig() {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    throw new Error("GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not set");
  }
  configPromise ??= client
    .discovery(GOOGLE_ISSUER, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
    .catch((err) => {
      configPromise = undefined; // allow a retry after a transient discovery failure
      throw err;
    });
  return configPromise;
}

function frontendRedirect(res, path, error) {
  const url = new URL(path, process.env.FRONTEND_URL || "http://localhost:3000");
  if (error) url.searchParams.set("error", error);
  return res.redirect(url.toString());
}

function clearTxCookie(res) {
  res.clearCookie(TX_COOKIE, {
    httpOnly: true,
    secure: isProd(),
    sameSite: "Lax",
    path: TX_PATH,
  });
}

export const startGoogleLogin = async (req, res) => {
  try {
    const config = await getConfig();

    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = client.randomState();
    const nonce = client.randomNonce();

    // Stateless transaction record: signed, HttpOnly, short-lived, and scoped to
    // the OAuth path. A separate audience stops it being replayed as a session token.
    const tx = jwt.sign({ state, nonce, codeVerifier }, process.env.JWT_SECRET, {
      expiresIn: TX_TTL_MS / 1000,
      audience: TX_AUDIENCE,
    });
    res.cookie(TX_COOKIE, tx, {
      httpOnly: true,
      secure: isProd(),
      sameSite: "Lax", // must accompany the top-level redirect back from Google
      maxAge: TX_TTL_MS,
      path: TX_PATH,
    });

    const authUrl = client.buildAuthorizationUrl(config, {
      redirect_uri: process.env.GOOGLE_REDIRECT_URI,
      scope: "openid email profile",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce,
      prompt: "select_account",
    });

    return res.redirect(authUrl.toString());
  } catch (err) {
    console.error("Google OAuth start error:", err);
    return frontendRedirect(res, "/login", "oauth_unavailable");
  }
};

export const googleCallback = async (req, res) => {
  const txToken = req.cookies?.[TX_COOKIE];
  clearTxCookie(res); // single use, whatever happens next

  try {
    if (!txToken) {
      return frontendRedirect(res, "/login", "oauth_failed");
    }

    let tx;
    try {
      tx = jwt.verify(txToken, process.env.JWT_SECRET, {
        audience: TX_AUDIENCE,
      });
    } catch {
      return frontendRedirect(res, "/login", "oauth_failed");
    }

    if (req.query.error) {
      return frontendRedirect(res, "/login", "oauth_denied");
    }

    const config = await getConfig();

    // rebuild the callback URL from our configured origin, not the Host header
    const currentUrl = new URL(process.env.GOOGLE_REDIRECT_URI);
    currentUrl.search = new URL(req.originalUrl, currentUrl).search;

    // verifies state, PKCE, and the ID token's iss / aud / exp / nonce
    const tokens = await client.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: tx.codeVerifier,
      expectedState: tx.state,
      expectedNonce: tx.nonce,
      idTokenExpected: true,
    });

    const claims = tokens.claims();
    if (!claims?.sub || !claims.email || claims.email_verified !== true) {
      return frontendRedirect(res, "/login", "oauth_unverified");
    }

    let citizen = await Citizen.findOne({ googleSub: claims.sub });

    if (!citizen) {
      // case-insensitive exact match (collation, not a regex built from input)
      citizen = await Citizen.findOne({ email: claims.email }).collation({
        locale: "en",
        strength: 2,
      });

      if (!citizen) {
        return frontendRedirect(res, "/login", "oauth_no_account");
      }

      // Google verified this email and it matches the profile email, so (re)link.
      // This also covers a user who changed their profile email to another Google
      // account: the old link is replaced and the old account can no longer sign in.
      citizen.googleSub = claims.sub;
      await citizen.save();
    } else if (
      claims.email.toLowerCase() !== String(citizen.email || "").toLowerCase()
    ) {
      // linked Google account no longer matches the profile email
      return frontendRedirect(res, "/login", "oauth_no_account");
    }

    // same session as the password login (loginCitizen)
    const token = jwt.sign(
      { citizenId: citizen.citizenId, role: "citizen" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.cookie("citizen_token", token, {
      httpOnly: true,
      secure: isProd(),
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return frontendRedirect(res, "/dashboard");
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    return frontendRedirect(res, "/login", "oauth_failed");
  }
};
