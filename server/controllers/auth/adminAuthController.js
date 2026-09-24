import Admin from "../../models/adminModel.js";
import { checkPassword, INVALID_CREDENTIALS } from "../../helpers/credentials.js";
import jwt from "jsonwebtoken";
import { isNonEmptyString } from "../../utils/isNonEmptyString.js";

export const loginAdmin = async (req, res) => {
  const { adminId, password } = req.body;

  if (!isNonEmptyString(adminId) || !isNonEmptyString(password)) {
    return res
      .status(400)
      .json({ message: "Admin ID and password are required" });
  }

  try {
    const admin = await Admin.findOne({ adminId });
    const isMatch = await checkPassword(password, admin?.password);

    if (!admin || !isMatch) {
      return res.status(401).json({ message: INVALID_CREDENTIALS });
    }

    const token = jwt.sign(
      { adminId: admin.adminId, role: "admin" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("admin_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Login successful",
      admin: {
        adminId: admin.adminId,
        fullName: admin.fullName,
        role: admin.role,
        email: admin.email,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const logoutAdmin = (req, res) => {
  res.clearCookie("admin_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
  });
  res.status(200).json({ message: "Logged out successfully" });
};
