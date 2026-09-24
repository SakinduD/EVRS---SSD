export function escapeRegex(value) {
  if (typeof value !== "string") {
    throw new TypeError("Search value must be a string");
  }
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
