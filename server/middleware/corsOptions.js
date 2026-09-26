// browsers send a bare origin ("http://localhost:3000"), so reduce the
// configured URL to one too; a trailing slash or path would never match
function toOrigin(url) {
  try {
    return new URL(url.trim()).origin;
  } catch {
    return null;
  }
}

export function corsOptions(frontendUrl = process.env.FRONTEND_URL) {
  const frontendOrigin = frontendUrl ? toOrigin(frontendUrl) : null;
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
