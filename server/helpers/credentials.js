import bcrypt from "bcryptjs";

// Same message for "no such account" and "wrong password" so the login API cannot
// be used to discover which IDs exist (user enumeration, CWE-204).
export const INVALID_CREDENTIALS = "Invalid ID or password";

// Compared against when the account does not exist, so a missing account costs the
// same bcrypt time as a wrong password and timing does not reveal it either.
const DUMMY_HASH = bcrypt.hashSync("evrs-timing-equaliser", 10);

export async function checkPassword(password, storedHash) {
  const matches = await bcrypt.compare(password, storedHash || DUMMY_HASH);
  return Boolean(storedHash) && matches;
}
