import MOH from "../../models/mohModel.js";
import { checkPassword, INVALID_CREDENTIALS } from "../../helpers/credentials.js";
import jwt from "jsonwebtoken";

export const loginMOH = async (req, res) => {
  const { mohId, password } = req.body;

  if (typeof mohId !== "string" || typeof password !== "string" || !mohId || !password) {
    return res
      .status(400)
      .json({ message: "MOH ID and password are required" });
  }

  try {
    const moh = await MOH.findOne({ mohId });
    const isMatch = await checkPassword(password, moh?.password);

    if (!moh || !isMatch) {
      return res.status(401).json({ message: INVALID_CREDENTIALS });
    }

    const token = jwt.sign(
      { mohId: moh.mohId, role: "moh" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("moh_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Login successful",
      moh: {
        mohId: moh.mohId,
        name: moh.name,
        email: moh.email,
        contactNumber: moh.contactNumber,
        district: moh.district,
        province: moh.province,
      },
    });
  } catch (error) {
    console.error("MOH login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const logoutMOH = (req, res) => {
  res.clearCookie("moh_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
  });
  res.status(200).json({ message: "Logged out successfully" });
};
