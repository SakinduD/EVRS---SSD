import express from "express";
import {
  loginCitizen,
  logoutCitizen,
} from "../controllers/auth/citizenAuthController.js";
import { loginHCP, logoutHCP } from "../controllers/auth/hcpAuthController.js";
import {
  loginHospital,
  logoutHospital,
} from "../controllers/auth/hospitalAuthController.js";
import { loginMOH, logoutMOH } from "../controllers/auth/mohAuthController.js";
import {
  loginAdmin,
  logoutAdmin,
} from "../controllers/auth/adminAuthController.js";
import {
  forgotPassword,
  resetPassword,
} from "../controllers/authController.js";
import {
  startGoogleLogin,
  googleCallback,
} from "../controllers/auth/googleOAuthController.js";
import {
  authIpLimiter,
  loginLimiter,
  forgotPasswordLimiter,
  resetPasswordLimiter,
} from "../middleware/rateLimiter.js";

const router = express.Router();

// coarse per-IP cap on every auth endpoint
router.use(authIpLimiter);

router.post("/login/admin", loginLimiter("adminId"), loginAdmin);
router.post("/logout/admin", logoutAdmin);

router.post("/login/citizen", loginLimiter("citizenId"), loginCitizen);
router.post("/logout/citizen", logoutCitizen);

router.post("/login/hcp", loginLimiter("hcpId"), loginHCP);
router.post("/logout/hcp", logoutHCP);

router.post("/login/hospital", loginLimiter("hospitalId"), loginHospital);
router.post("/logout/hospital", logoutHospital);

router.post("/login/moh", loginLimiter("mohId"), loginMOH);
router.post("/logout/moh", logoutMOH);

router.post("/forgot-password", forgotPasswordLimiter, forgotPassword);
router.post("/reset-password", resetPasswordLimiter, resetPassword);

// Sign in with Google (OpenID Connect, authorization code + PKCE) for citizens
router.get("/oauth/google", startGoogleLogin);
router.get("/oauth/google/callback", googleCallback);

export default router;
