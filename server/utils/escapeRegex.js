export function escapeRegex(value) {
  if (typeof value !== "string") {
    throw new TypeError("Search value must be a string");
  }
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Case-insensitive "contains" condition where the user's text is matched literally.
// Returned as a MongoDB $regex operator object, so no RegExp is built from request data
// and regex metacharacters typed by the user cannot cause catastrophic backtracking.
export function literalSearch(value) {
  return { $regex: escapeRegex(value), $options: "i" };
}
