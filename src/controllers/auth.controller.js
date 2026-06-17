const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { jwtConfig } = require("../config/jwt");
const UserSchema = require("../models/auth.model");
const Session = require("../models/session.model");
const emailVerification = require("../utils/emailVerification");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/token.utils");

// ============ SignUp Controller =================
const SignUp = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Check Required Fields
    if (!firstName)
      return res.status(400).json({ message: "Error: First Name Required" });
    if (!lastName)
      return res.status(400).json({ message: "Error: Last Name Required" });
    if (!email)
      return res.status(400).json({ message: "Error: Email Required" });
    if (!password)
      return res.status(400).json({ message: "Error: Password Required" });

    // Check Duplicate Email In Database
    const duplicateEmail = await UserSchema.findOne({ email });
    if (duplicateEmail)
      return res.status(409).json({ message: "Email Already Exists" });

    // Generate OTP Using Crypto
    const otp = crypto.randomInt(100000, 999999).toString();
    const expireOtp = new Date(Date.now() + 5 * 60 * 1000);

    // Hash Password Using Bcrypt
    const hash = await bcrypt.hash(password, 10);
    const user = new UserSchema({
      firstName,
      lastName,
      email,
      password: hash,
      otp,
      expireOtp,
    });

    // Generate New Tokens For SignUp User
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Hash Refresh Token For Security
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

    // Send OTP to User Email
    await emailVerification(email, otp);

    // Set Token To User
    user.accessToken = accessToken;
    user.refreshToken = refreshTokenHash;

    // Save User
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res
      .status(201)
      .json({ message: "User registered successfully", user });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ Login Controller =================
const Login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip;
    const userAgent = req.get("User-Agent");

    const user = await UserSchema.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Compare Password
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Wrong password" });

    // Revoke old sessions (so old tokens become invalid)
    await Session.updateMany(
      { user: user._id, revoked: false },
      { $set: { revoked: true } },
    );

    // Generate New Tokens For Login User
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Hash Refresh Token For Security
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

    // Create Session For User Login
    const session = new Session({
      user: user._id,
      ip,
      revoked: false,
      refreshToken: refreshTokenHash,
      userAgent,
    });
    await session.save();

    // Set New Tokens To User
    user.accessToken = accessToken;
    user.refreshToken = refreshTokenHash;

    // Save User
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ message: "Login successful", user });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

// ============ Refresh Token Controller =================
const RefreshToken = async (req, res) => {
  try {
    let refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!refreshToken && req.headers.authorization) {
      if (req.headers.authorization.startsWith("Bearer ")) {
        refreshToken = req.headers.authorization.split(" ")[1];
      } else {
        refreshToken = req.headers.authorization;
      }
    }

    if (!refreshToken)
      return res.status(401).json({ message: "Refresh Token Is Not Found" });

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, jwtConfig().secret);
    } catch {
      return res
        .status(401)
        .json({ message: "Invalid Or Expired Refresh Token" });
    }

    const user = await UserSchema.findById(decoded.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Find all active login sessions for this user
    const sessions = await Session.find({ user: user._id, revoked: false });

    // Check which session matches this specific refresh token
    let session = null;
    for (const s of sessions) {
      const match = await bcrypt.compare(refreshToken, s.refreshToken);
      if (match) {
        session = s;
        break;
      }
    }

    // If no matching session is found, they were logged out or the token was revoked
    if (!session)
      return res
        .status(404)
        .json({ message: "Invalid Or Expired Refresh Token" });

    // Token Rotation
    const accessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    // Hash the new refresh token
    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);

    // Update the session in the database with the new refresh token
    session.refreshToken = newRefreshTokenHash;
    await session.save();

    // Update the user's latest tokens in their database record
    user.accessToken = accessToken;
    user.refreshToken = newRefreshTokenHash;
    await user.save();

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Access Token Refreshed Successfully",
      accessToken,
    });
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Invalid Or Expired Refresh Token" });
  }
};

// ============ LogOut Controller =================
const LogOut = async (req, res) => {
  try {
    let refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!refreshToken && req.headers.authorization) {
      if (req.headers.authorization.startsWith("Bearer ")) {
        refreshToken = req.headers.authorization.split(" ")[1];
      } else {
        refreshToken = req.headers.authorization;
      }
    }

    if (!refreshToken)
      return res.status(401).json({ message: "Refresh Token Is Required" });

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, jwtConfig().secret);
    } catch {
      return res.status(401).json({ message: "Invalid Refresh Token" });
    }

    const sessions = await Session.find({ user: decoded.id, revoked: false });

    let currentSession = null;
    for (const session of sessions) {
      const match = await bcrypt.compare(refreshToken, session.refreshToken);
      if (match) {
        currentSession = session;
        break;
      }
    }

    if (!currentSession)
      return res.status(404).json({ message: "Session Not Found" });

    currentSession.revoked = true;
    await currentSession.save();

    res.clearCookie("refreshToken");
    return res.status(200).json({ message: "Logout Successful" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ LogOut All Devices Controller =================
const LogOutAll = async (req, res) => {
  try {
    const cookieRefreshToken = req.cookies?.refreshToken;
    const authHeader = req.headers.authorization;
    let userId = null;

    if (cookieRefreshToken) {
      try {
        const decoded = jwt.verify(cookieRefreshToken, jwtConfig().secret);
        if (decoded?.id) userId = decoded.id;
      } catch (_) {}
    }

    if (!userId) {
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Authentication Required" });
      }

      const token = authHeader.split(" ")[1];
      try {
        const decoded = jwt.verify(token, jwtConfig().secret);
        userId = decoded.id;
      } catch {
        return res
          .status(401)
          .json({ message: "Invalid Or Expired Access Token" });
      }
    }

    await Session.updateMany(
      { user: userId, revoked: false },
      { $set: { revoked: true } },
    );

    await UserSchema.findByIdAndUpdate(userId, {
      $set: { accessToken: "", refreshToken: "" },
    });

    res.clearCookie("refreshToken");
    return res
      .status(200)
      .json({ message: "Logout From All Devices Successful" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ Verify OTP Controller =================
const VerifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await UserSchema.findOne({ email });

    if (!user) return res.status(400).json({ message: "User Not Found" });

    if (user.isVerified)
      return res.status(400).json({ message: "User Already Verified" });

    if (user.otp !== otp || user.expireOtp < Date.now()) {
      return res.status(400).json({ message: "Incorrect OTP or Expired OTP" });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.expireOtp = undefined;

    await user.save();

    return res.status(200).json({ message: "Email Verified Successfully" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ Resend OTP Controller =================
const ResendOtp = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await UserSchema.findOne({ email });

    if (!user) return res.status(400).json({ message: "User Not Found" });

    if (user.isVerified)
      return res.status(400).json({ message: "Email Already Verified" });

    if (user.expireOtp && user.expireOtp > Date.now()) {
      return res
        .status(400)
        .json({ message: "Wait 5 minutes before requesting new OTP" });
    }

    const otp = crypto.randomInt(100000, 999999).toString();

    user.otp = otp;
    user.expireOtp = Date.now() + 5 * 60 * 1000;

    await user.save();

    await emailVerification(email, otp, true);

    return res.status(200).json({ message: "New OTP Sent Successfully" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

module.exports = {
  SignUp,
  Login,
  RefreshToken,
  LogOut,
  LogOutAll,
  VerifyOtp,
  ResendOtp,
};
