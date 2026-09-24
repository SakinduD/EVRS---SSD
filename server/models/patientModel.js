import mongoose from "mongoose";

const pendingSub = {
  address: { type: String, default: "" },
  code: { type: String, default: "" },
  expires: { type: Date, default: null },
  // wrong-code counter; the code is destroyed once MAX_OTP_ATTEMPTS is reached
  attempts: { type: Number, default: 0 },
};

const patientSchema = new mongoose.Schema(
  {
    citizenId: {
      type: String,
      required: true,
      unique: true,
    },
    serialNumber: {
      type: String,
      required: true,
      unique: true,
    },
    firstName: {
      type: String,
      required: true,
    },
    lastName: {
      type: String,
      required: true,
    },
    birthDate: {
      type: Date,
      required: true,
    },
    district: {
      type: String,
      required: true,
    },
    division: {
      type: String,
      required: true,
    },
    guardianNIC: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    address: {
      type: String,
    },
    email: {
      type: String,
      unique: true,
      sparse: true,
    },
    phoneNumber: {
      type: String,
      unique: true,
      sparse: true,
    },
    // Google (OIDC) subject; bound on the first successful "Sign in with Google"
    googleSub: {
      type: String,
      unique: true,
      sparse: true,
    },
    // otp for email
    pendingEmail: {
      address: pendingSub.address,
      code: pendingSub.code,
      expires: pendingSub.expires,
      attempts: pendingSub.attempts,
    },
    // otp for phone
    pendingPhone: {
      number: { type: String, default: "" },
      code: pendingSub.code,
      expires: pendingSub.expires,
      attempts: pendingSub.attempts,
    },
    resetPassword: {
      token: { type: String },
      expires: { type: Date },
    },
    // medical info
    bloodType: {
      type: String,
      enum: ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"],
      default: null,
    },
    allergies: {
      type: [String],
      default: [],
    },
    medicalConditions: {
      type: [String],
      default: [],
    },
    emergencyContact: {
      name: {
        type: String,
        default: "",
      },
      phoneNumber: {
        type: String,
        default: "",
      },
    },
    recordedBy: {
      id: { type: String },
      role: {
        type: String,
        enum: ["hcp", "hospital", "moh", "admin"],
      },
    },
  },
  { timestamps: true }
);

export default mongoose.model("Patient", patientSchema);
