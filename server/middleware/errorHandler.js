export function errorHandler(err, req, res, next) {
  console.error(`Unhandled ${req.method} ${req.originalUrl}:`, err);
  if (res.headersSent) return next(err);
  const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 500
    ? err.status : 500;
  const message = status === 500 ? "Internal server error" :
    (err.expose ? err.message : "Bad request");
  res.status(status).json({ message });
}
