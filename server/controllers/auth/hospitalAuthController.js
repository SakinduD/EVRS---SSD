import Hospital from "../../models/hospitalModel.js";
import { checkPassword, INVALID_CREDENTIALS } from "../../helpers/credentials.js";
import jwt from "jsonwebtoken";

export const loginHospital = async (req, res) => {
  const { hospitalId, password } = req.body;

  if (typeof hospitalId !== "string" || typeof password !== "string" || !hospitalId || !password) {
    return res
      .status(400)
      .json({ message: "Hospital ID and password are required" });
  }

  try {
    const hospital = await Hospital.findOne({ hospitalId });
    const isMatch = await checkPassword(password, hospital?.password);

    if (!hospital || !isMatch) {
      return res.status(401).json({ message: INVALID_CREDENTIALS });
    }

    const token = jwt.sign(
      { hospitalId: hospital.hospitalId, role: "hospital" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("hospital_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Login successful",
      hospital: {
        hospitalId: hospital.hospitalId,
        name: hospital.name,
        email: hospital.email,
        district: hospital.district,
        province: hospital.province,
      },
    });
  } catch (error) {
    console.error("Hospital login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const logoutHospital = (req, res) => {
  res.clearCookie("hospital_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
  });
  res.status(200).json({ message: "Logged out successfully" });
};
