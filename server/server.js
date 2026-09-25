import express from "express";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import adminRoutes from "./routes/adminRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import citizenRoutes from "./routes/citizenRoutes.js";
import hcpRoutes from "./routes/hcpRoutes.js";
import hospitalRoutes from "./routes/hospitalRoutes.js";
import mohRoutes from "./routes/mohRoutes.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import { corsOptions } from "./middleware/corsOptions.js";
import { errorHandler } from "./middleware/errorHandler.js";

dotenv.config();

const app = express();

// behind a reverse proxy, req.ip (used by the rate limiters) is the proxy unless this is set
if (process.env.TRUST_PROXY) {
  app.set("trust proxy", Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);
}

// security response headers, before anything that can answer a request.
// The ZAP scan reported the API advertising Express in X-Powered-By on 81
// responses and omitting X-Content-Type-Options on 62; helmet covers those,
// plus HSTS, frame options and a default CSP.
//
// The one default that has to be overridden: the frontend is a different
// origin and sends cookies, and helmet's same-origin resource policy would
// refuse those responses. CORS, configured below, is what decides who may
// call this API.
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions()));

app.get("/", (req, res) => {
  res.send("API is running...");
});

app.use("/api/admin", adminRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/citizen", citizenRoutes);
app.use("/api/hcp", hcpRoutes);
app.use("/api/hospital", hospitalRoutes);
app.use("/api/moh", mohRoutes);

app.use(errorHandler);

connectDB();

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
