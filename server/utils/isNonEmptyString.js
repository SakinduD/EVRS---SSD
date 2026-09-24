export const isNonEmptyString = (value) =>
  typeof value === "string" && value.trim().length > 0;
