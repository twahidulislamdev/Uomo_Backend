const nodemailer = require("nodemailer");

const emailVerification = async (email, otp, isResend = false) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // use STARTTLS (upgrade connection to TLS after connecting)
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  try {
    await transporter.sendMail({
      from: '"Prime Store" <twahidulislam2005@gmail.com>',
      to: email,
      subject: isResend
        ? "Your Resend OTP Verification Code"
        : "Your OTP Verification Code",
      html: `
      <div style="max-width:600px;margin:0 auto;font-family:Arial,Helvetica,sans-serif;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">
        <div style="background:#f9fafb;padding:20px;text-align:center;border-bottom:1px solid #e5e7eb">
          <h1 style="color:#111827;margin:0;font-size:22px">
            Prime Store
          </h1>
        </div>

        <div style="padding:20px;color:#374151">
          <h2 style="margin-top:0;color:#111827">OTP Verification</h2>

          <p style="font-size:14px">Hello,</p>

          <p style="font-size:14px">
            Use the following One-Time Password (OTP).  
            This OTP is valid for <strong>5 minutes</strong>.
          </p>

         <!-- OTP Box -->
        <div style="text-align:center;margin:30px 0">
          <span style="
            display:inline-block;
            padding:15px 30px;
            font-size:28px;
            font-weight:bold;
            letter-spacing:6px;
            color:#111827;
            background:#f9fafb;
            border-radius:6px;
            border:2px solid #e5e7eb;
          ">
            ${otp}
          </span>
        </div>
        <p style="font-size:12px;color: #555;text-align:center;">
         Never share this code with anyone.</p>

          <p style="font-size:14px;color:#6b7280;background:#f9fafb;padding:12px;border-radius:4px;text-align:center">
            If you did not request this code, please ignore this email.
          </p>

          <p style="font-size:14px;margin-top:30px">
            Regards,<br />
            <strong>Prime Store Team</strong>
          </p>
        </div>

        <div style="background:#f9fafb;padding:15px;text-align:center;font-size:12px;color:#9ca3af;border-top:1px solid #e5e7eb">
          © ${new Date().getFullYear()} Prime Store. All rights reserved.
        </div>
      </div>
    `,
    });
    return { success: true, message: "Email sent successfully" };
  } catch (error) {
    console.error("Email sending error:", error);
    return { success: false, error: error.message };
  }
};

module.exports = emailVerification;
