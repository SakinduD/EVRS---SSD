import Citizen from "../../models/patientModel.js";
import { checkPassword, INVALID_CREDENTIALS } from "../../helpers/credentials.js";
import jwt from "jsonwebtoken";

export const loginCitizen = async (req, res) => {
  const { citizenId, password } = req.body;

  if (typeof citizenId !== "string" || typeof password !== "string" || !citizenId || !password) {
    return res
      .status(400)
      .json({ message: "Citizen ID and password are required" });
  }

  try {
    const citizen = await Citizen.findOne({ citizenId });
    const isMatch = await checkPassword(password, citizen?.password);

    if (!citizen || !isMatch) {
      return res.status(401).json({ message: INVALID_CREDENTIALS });
    }

    const token = jwt.sign(
      { citizenId: citizen.citizenId, role: "citizen" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("citizen_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Login successful",
      citizen: {
        citizenId: citizen.citizenId,
        firstName: citizen.firstName,
        lastName: citizen.lastName,
      },
    });
  } catch (error) {
    console.error("Citizen login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const logoutCitizen = (req, res) => {
  res.clearCookie("citizen_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
  });
  res.status(200).json({ message: "Logged out successfully" });
};
