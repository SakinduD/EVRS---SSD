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
import { corsOptions } from "./middleware/corsOptions.js";
import { errorHandler } from "./middleware/errorHandler.js";

dotenv.config();

const app = express();

// behind a reverse proxy, req.ip (used by the rate limiters) is the proxy unless this is set
if (process.env.TRUST_PROXY) {
  app.set("trust proxy", Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);
}

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
