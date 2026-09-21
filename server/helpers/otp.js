import crypto from "crypto";

export const MAX_OTP_ATTEMPTS = 5;

// 6-digit code from the OS CSPRNG (Math.random is predictable and must not be used for secrets)
export function generateOtp() {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
}

// constant-time comparison so response timing does not leak how many digits matched
export function otpMatches(supplied, expected) {
  if (typeof supplied !== "string" || typeof expected !== "string") {
    return false;
  }
  const a = crypto.createHash("sha256").update(supplied).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

async function clearPending(Model, filter, field) {
  await Model.updateOne(filter, {
    $set: {
      [`${field}.code`]: "",
      [`${field}.expires`]: null,
      [`${field}.attempts`]: 0,
    },
  });
}

/**
 * Verifies a pending OTP (pendingEmail / pendingPhone) with attempt lockout.
 *
 * The attempt counter is incremented atomically BEFORE the code is compared, so
 * parallel guesses cannot exceed MAX_OTP_ATTEMPTS. Once the limit is hit (or the
 * code expires) the pending code is destroyed and a new one must be requested.
 *
 * @returns {{status: "ok"|"none"|"expired"|"invalid"|"locked", pending?: object}}
 */
export async function verifyPendingOtp({ Model, filter, field, code }) {
  const doc = await Model.findOneAndUpdate(
    filter,
    { $inc: { [`${field}.attempts`]: 1 } },
    { new: true }
  )
    .select(field)
    .lean();

  const pending = doc?.[field];
  if (!pending?.code) {
    return { status: "none" };
  }

  if (pending.attempts > MAX_OTP_ATTEMPTS) {
    await clearPending(Model, filter, field);
    return { status: "locked" };
  }

  if (!pending.expires || new Date() > pending.expires) {
    await clearPending(Model, filter, field);
    return { status: "expired" };
  }

  if (!otpMatches(code, pending.code)) {
    if (pending.attempts >= MAX_OTP_ATTEMPTS) {
      await clearPending(Model, filter, field);
      return { status: "locked" };
    }
    return { status: "invalid" };
  }

  return { status: "ok", pending };
}

const LOCKED = [
  429,
  "Too many incorrect attempts. Please request a new verification code.",
];

const FAILURES = {
  email: {
    none: [404, "No pending email change found"],
    expired: [410, "Verification code expired"],
    invalid: [401, "Invalid verification code"],
    locked: LOCKED,
  },
  phone: {
    none: [400, "No pending phone change"],
    expired: [400, "Verification code expired"],
    invalid: [400, "Invalid verification code"],
    locked: LOCKED,
  },
};

export function sendOtpFailure(res, kind, status) {
  const [httpStatus, message] = FAILURES[kind][status];
  return res.status(httpStatus).json({ message });
}
