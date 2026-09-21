import HCP from "../../models/hcpModel.js";
import { checkPassword, INVALID_CREDENTIALS } from "../../helpers/credentials.js";
import jwt from "jsonwebtoken";

export const loginHCP = async (req, res) => {
  const { hcpId, password } = req.body;

  if (typeof hcpId !== "string" || typeof password !== "string" || !hcpId || !password) {
    return res
      .status(400)
      .json({ message: "HCP ID and password are required" });
  }

  try {
    const hcp = await HCP.findOne({ hcpId });
    const isMatch = await checkPassword(password, hcp?.password);

    if (!hcp || !isMatch) {
      return res.status(401).json({ message: INVALID_CREDENTIALS });
    }

    const token = jwt.sign(
      { hcpId: hcp.hcpId, role: "hcp" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("hcp_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Login successful",
      hcp: {
        hcpId: hcp.hcpId,
        fullName: hcp.fullName,
        role: hcp.role,
        email: hcp.email,
      },
    });
  } catch (error) {
    console.error("HCP login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const logoutHCP = (req, res) => {
  res.clearCookie("hcp_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
  });
  res.status(200).json({ message: "Logged out successfully" });
};
