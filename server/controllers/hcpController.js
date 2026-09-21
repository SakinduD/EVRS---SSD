import bcrypt from "bcryptjs";
import crypto from "crypto";
import {
  generateOtp,
  verifyPendingOtp,
  sendOtpFailure,
} from "../helpers/otp.js";
import { sendMail } from "../services/mailer.js";
import { sendWhatsAppOTP } from "../services/twilio.js";
import HealthcareProvider from "../models/hcpModel.js";
import VaccinationRecord from "../models/vaccinationModel.js";

function generateVaccinationId() {
  const digits = crypto.randomInt(1000000000, 10000000000);
  return `VR${digits}`;
}

const OTP_TTL_MS = 10 * 60 * 1000;

export const requestEmailChange = async (req, res) => {
  const { newEmail } = req.body;
  const { hcpId } = req.user;

  if (!newEmail) {
    return res.status(400).json({ message: "New email is required" });
  }

  // gen 6 digit code
  const code = generateOtp();

  try {
    const expires = new Date(Date.now() + OTP_TTL_MS);
    await HealthcareProvider.findOneAndUpdate(
      { hcpId },
      {
        pendingEmail: { address: newEmail, code, expires, attempts: 0 },
      }
    );

    await sendMail({
      to: newEmail,
      subject: "Your EVRS Email Verification Code",
      text: `Your verification code is: ${code}\n\nThis code will expire in 10 minutes.`,
      html: `<p>Your verification code is: <strong>${code}</strong></p>
                <p>This code will expire in 10 minutes.</p>`,
    });

    res.json({ message: "Verification code sent to new email" });
  } catch (err) {
    console.error("requestEmailChange error:", err);
    res.status(500).json({ message: "Failed to send verification code" });
  }
};

export const verifyEmailChange = async (req, res) => {
  const { code } = req.body;
  const { hcpId } = req.user;

  if (!code) {
    return res.status(400).json({ message: "Verification code is required" });
  }

  try {
    const result = await verifyPendingOtp({
      Model: HealthcareProvider,
      filter: { hcpId },
      field: "pendingEmail",
      code,
    });
    if (result.status !== "ok") {
      return sendOtpFailure(res, "email", result.status);
    }

    const hcp = await HealthcareProvider.findOne({ hcpId });
    hcp.email = result.pending.address;

    hcp.pendingEmail = { address: "", code: "", expires: null };
    await hcp.save();

    res.json({ message: "Email updated successfully", email: hcp.email });
  } catch (err) {
    console.error("verifyEmailChange error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

export const requestPhoneChange = async (req, res) => {
  const hcpId = req.user.hcpId;
  const { newPhone } = req.body;
  if (!newPhone) {
    return res.status(400).json({ message: "newPhone is required" });
  }

  // dupli check
  const exists = await HealthcareProvider.findOne({ phoneNumber: newPhone });
  if (exists) {
    return res.status(409).json({ message: "Phone already in use" });
  }

  const code = generateOtp();
  const expires = new Date(Date.now() + 15 * 60 * 1000);

  // store pendingPhone
  const updated = await HealthcareProvider.findOneAndUpdate(
    { hcpId },
    { pendingPhone: { number: newPhone, code, expires, attempts: 0 } },
    { new: true }
  );
  if (!updated) {
    return res.status(404).json({ message: "Citizen not found" });
  }

  try {
    await sendWhatsAppOTP(newPhone, code);

    return res.json({ message: "Verification code sent via WhatsApp" });
  } catch (err) {
    console.error("WhatsApp send failed:", err?.code, err?.message);
    return res.status(500).json({ message: "Failed to send WhatsApp OTP" });
  }
};

export const verifyPhoneChange = async (req, res) => {
  const hcpId = req.user.hcpId;
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ message: "code is required" });
  }

  const result = await verifyPendingOtp({
    Model: HealthcareProvider,
    filter: { hcpId },
    field: "pendingPhone",
    code,
  });
  if (result.status !== "ok") {
    return sendOtpFailure(res, "phone", result.status);
  }

  const user = await HealthcareProvider.findOne({ hcpId });
  user.phoneNumber = result.pending.number;
  user.pendingPhone = undefined;
  await user.save();

  res.json({
    message: "Phone number updated successfully",
    phone: user.phoneNumber,
  });
};

export async function changePassword(req, res) {
  const { hcpId } = req.user;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res
      .status(400)
      .json({ message: "Both current and new passwords are required" });
  }
  if (newPassword.length < 8) {
    return res
      .status(400)
      .json({ message: "New password must be at least 8 characters" });
  }

  try {
    const hcp = await HealthcareProvider.findOne({ hcpId }).select("password");
    if (!hcp) {
      return res.status(404).json({ message: "Citizen not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, hcp.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    const sameAsOld = await bcrypt.compare(newPassword, hcp.password);
    if (sameAsOld) {
      return res
        .status(400)
        .json({ message: "New password must be different from current" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    hcp.password = hashed;
    await hcp.save();

    return res.json({ message: "Password changed successfully" });
  } catch (err) {
    console.error("changePassword error:", err);
    return res.status(500).json({ message: "Server error" });
  }
}

export const addVaccination = async (req, res) => {
  const {
    citizenId,
    vaccineId,
    batchNumber,
    expiryDate,
    vaccinationLocation,
    division,
    additionalNotes,
  } = req.body;
  const { hcpId, role } = req.user;

  if (
    !citizenId ||
    !vaccineId ||
    !batchNumber ||
    !expiryDate ||
    !hcpId ||
    !role ||
    !vaccinationLocation ||
    !division
  ) {
    return res.status(400).json({
      message: "All fields except additionalNotes are required",
    });
  }

  try {
    const newRecord = await VaccinationRecord.create({
      vaccinationId: generateVaccinationId(),
      citizenId,
      vaccineId,
      batchNumber,
      expiryDate,
      recordedBy: {
        id: hcpId,
        role: role,
      },
      vaccinationLocation,
      division,
      additionalNotes: additionalNotes || "",
    });

    res.status(201).json({
      message: "Vaccination record created successfully",
      record: newRecord,
    });
  } catch (error) {
    console.error("Add vaccination error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const getHCPProfile = async (req, res) => {
  const { hcpId } = req.user;

  try {
    const hcp = await HealthcareProvider.findOne({ hcpId })
      .select("-password -pendingEmail -pendingPhone -__v")
      .lean();

    if (!hcp) {
      return res.status(404).json({ message: "Healthcare Provider not found" });
    }

    res.status(200).json({
      loggedIn: true,
      hcp: {
        hcpId: hcp.hcpId,
        fullName: hcp.fullName,
        email: hcp.email,
        phoneNumber: hcp.phoneNumber,
        role: hcp.role,
        nic: hcp.nic,
      },
    });
  } catch (error) {
    console.error("getHcpProfile error:", err);
    res.status(403).json({ message: "Invalid or expired token." });
  }
};
