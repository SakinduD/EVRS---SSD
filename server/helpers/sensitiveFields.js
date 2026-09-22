// Fields that must never be sent to a client, including to admins:
// password hash, pending OTP codes, password-reset token and the Google subject.
export const SENSITIVE_FIELDS =
  "-password -pendingEmail -pendingPhone -resetPassword -googleSub -__v";

const SENSITIVE_KEYS = [
  "password",
  "pendingEmail",
  "pendingPhone",
  "resetPassword",
  "googleSub",
  "__v",
];

// plain-object copy of a mongoose document with the sensitive fields removed
export function stripSensitive(doc) {
  const obj = typeof doc?.toObject === "function" ? doc.toObject() : { ...doc };
  for (const key of SENSITIVE_KEYS) delete obj[key];
  return obj;
}
