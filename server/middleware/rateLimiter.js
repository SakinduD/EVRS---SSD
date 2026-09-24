import rateLimit, { ipKeyGenerator } from "express-rate-limit";

const MINUTE = 60 * 1000;

function tooMany(message) {
  return (req, res) => res.status(429).json({ message });
}

// caller IP (IPv6-safe) plus the targeted account: every account gets its own
// counter per IP, so failed logins for one ID never block other IDs behind the same IP
function ipAndAccount(idField) {
  return (req) => {
    const id = typeof req.body?.[idField] === "string" ? req.body[idField] : "";
    return `${ipKeyGenerator(req.ip)}|${id.toLowerCase()}`;
  };
}

// Password logins: 5 failed attempts / 15 min per IP + account.
// Successful logins are not counted, so legitimate users are not penalised.
export const loginLimiter = (idField) =>
  rateLimit({
    windowMs: 15 * MINUTE,
    limit: 5,
    skipSuccessfulRequests: true,
    keyGenerator: ipAndAccount(idField),
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: tooMany("Too many login attempts. Please try again in 15 minutes."),
  });

// Coarse per-IP cap across every auth endpoint (stops one IP rotating account IDs)
export const authIpLimiter = rateLimit({
  windowMs: 15 * MINUTE,
  limit: 50,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: tooMany("Too many requests. Please try again later."),
});

// forgot-password sends e-mail, so it is capped hard to prevent mail bombing
export const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * MINUTE,
  limit: 5,
  keyGenerator: ipAndAccount("id"),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: tooMany("Too many password reset requests. Please try again later."),
});

// reset-password guesses a 256-bit token, this mainly stops brute-force noise
export const resetPasswordLimiter = rateLimit({
  windowMs: 15 * MINUTE,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: tooMany("Too many attempts. Please try again later."),
});

// keyed on the authenticated user (routes sit behind authenticateRole)
function perUser(req) {
  const u = req.user || {};
  const id = u.citizenId || u.hcpId || u.hospitalId || u.mohId || u.adminId;
  return id ? `${u.role}:${id}` : ipKeyGenerator(req.ip);
}

// OTP verification: 10 attempts / 15 min per user (5 per code is enforced in helpers/otp.js)
export const otpVerifyLimiter = rateLimit({
  windowMs: 15 * MINUTE,
  limit: 10,
  keyGenerator: perUser,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: tooMany("Too many verification attempts. Please try again later."),
});

// OTP sending costs money (Twilio / SMTP) and can harass third parties
export const otpRequestLimiter = rateLimit({
  windowMs: 60 * MINUTE,
  limit: 5,
  keyGenerator: perUser,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: tooMany("Too many code requests. Please try again later."),
});

// V10: staff citizen-vaccination lookups (HCP/Hospital/MOH). Cross-facility
// access is intentional (national registry), so this is not an ownership
// check - it only blunts scripted citizenId enumeration from one account
// while staying well above normal one-patient-at-a-time clinical use.
export const vaccinationLookupLimiter = rateLimit({
  windowMs: 15 * MINUTE,
  limit: 60,
  keyGenerator: perUser,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: tooMany("Too many lookups. Please try again later."),
});
