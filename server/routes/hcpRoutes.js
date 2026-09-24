import express from "express";
import {
  requestEmailChange,
  verifyEmailChange,
  requestPhoneChange,
  verifyPhoneChange,
  changePassword,
  addVaccination,
  getHCPProfile,
} from "../controllers/hcpController.js";
import { authenticateRole, authorize } from "../middleware/auth.js";
import {
  otpRequestLimiter,
  otpVerifyLimiter,
} from "../middleware/rateLimiter.js";
import {
  getAllVaccines,
  getStats,
  getVaccinationsByCitizenId,
} from "../controllers/sharedController.js";

const router = express.Router();

router.use(authenticateRole("hcp"), authorize("hcp"));

router.get("/vaccines", getAllVaccines);
router.get("/vaccinations/:citizenId", getVaccinationsByCitizenId);
router.post("/add-vaccination", addVaccination);

router.get("/stats", getStats);

router.get("/get/profile", getHCPProfile);
router.post("/profile/email/request", otpRequestLimiter, requestEmailChange);
router.post("/profile/email/verify", otpVerifyLimiter, verifyEmailChange);

router.post("/profile/phone/request", otpRequestLimiter, requestPhoneChange);
router.post("/profile/phone/verify", otpVerifyLimiter, verifyPhoneChange);

router.put("/profile/password", changePassword);

export default router;
