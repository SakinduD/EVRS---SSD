import express from "express";
import {
  requestPhoneChange,
  verifyPhoneChange,
  changePassword,
  addVaccination,
  registerPatient,
  getMOHProfile,
} from "../controllers/mohController.js";
import { authenticateRole, authorize } from "../middleware/auth.js";
import {
  otpRequestLimiter,
  otpVerifyLimiter,
} from "../middleware/rateLimiter.js";
import {
  getAllVaccines,
  getVaccinationsByCitizenId,
} from "../controllers/sharedController.js";

const router = express.Router();

router.use(authenticateRole("moh"), authorize("moh"));

router.get("/vaccines", getAllVaccines);
router.get("/vaccinations/:citizenId", getVaccinationsByCitizenId);
router.post("/add-vaccination", addVaccination);
router.post("/register-patient", registerPatient);

router.get("/get/profile", getMOHProfile);
router.post("/profile/phone/request", otpRequestLimiter, requestPhoneChange);
router.post("/profile/phone/verify", otpVerifyLimiter, verifyPhoneChange);

router.put("/profile/password", changePassword);

export default router;
