export function corsOptions(frontendUrl = process.env.FRONTEND_URL) {
  const frontendOrigin = frontendUrl?.trim();
  return {
    origin(origin, callback) {
      if (!origin || (frontendOrigin && origin === frontendOrigin)) {
        return callback(null, true);
      }
      const error = new Error("Origin not allowed");
      error.status = 403;
      return callback(error);
    },
    credentials: true,
  };
}
