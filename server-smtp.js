import nodemailer from "nodemailer";

let cachedTransporter = null;
let customTransporter = null;

export function isSmtpConfigured() {
  if (customTransporter) return true;
  return Boolean(
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
  );
}

export function getSmtpStatus() {
  const host = Boolean(process.env.SMTP_HOST);
  const user = Boolean(process.env.SMTP_USER);
  const pass = Boolean(process.env.SMTP_PASS);
  const configured = isSmtpConfigured();
  const missingVariables = [];
  if (!host) missingVariables.push("SMTP_HOST");
  if (!user) missingVariables.push("SMTP_USER");
  if (!pass) missingVariables.push("SMTP_PASS");

  return {
    configured,
    missingVariables,
    requiredVariables: ["SMTP_HOST", "SMTP_USER", "SMTP_PASS"],
    optionalVariables: ["SMTP_PORT", "SMTP_FROM", "APP_URL"],
  };
}

export function setCustomTransporter(transporter) {
  customTransporter = transporter;
}

export function resetSmtpTransporter() {
  if (cachedTransporter && typeof cachedTransporter.close === "function") {
    try {
      cachedTransporter.close();
    } catch (_) {}
  }
  cachedTransporter = null;
  customTransporter = null;
}

export function isApplicationHost(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  // Filter out development platform/console hosts that do NOT host the app directly
  if (
    h === "localhost" ||
    h === "127.0.0.1" ||
    h.endsWith(".google.com") ||
    h.endsWith(".googleusercontent.com") ||
    h.endsWith(".googletagmanager.com")
  ) {
    return false;
  }
  // Allow Cloud Run hosting domains
  if (h.endsWith(".run.app")) {
    return true;
  }
  // Allow explicitly configured custom production domain
  const envUrl = process.env.APP_URL || process.env.PUBLIC_URL || process.env.BASE_URL;
  if (envUrl) {
    try {
      if (h === new URL(envUrl).hostname.toLowerCase()) {
        return true;
      }
    } catch (_) {}
  }
  return false;
}

export function isOriginAllowed(origin, req = null) {
  if (!origin) return true;
  try {
    const originHost = new URL(origin).hostname.toLowerCase();
    const serverHost = (req?.headers?.["x-forwarded-host"] || req?.headers?.host || "")
      .toLowerCase()
      .split(":")[0];
    if (originHost === serverHost) return true;
    if (originHost === "localhost" || originHost === "127.0.0.1") return true;
    if (
      originHost.endsWith(".run.app") ||
      originHost.endsWith(".google.com") ||
      originHost.endsWith(".googleusercontent.com")
    ) {
      return true;
    }
    const envUrl = process.env.APP_URL || process.env.PUBLIC_URL || process.env.BASE_URL;
    if (envUrl) {
      try {
        if (originHost === new URL(envUrl).hostname.toLowerCase()) {
          return true;
        }
      } catch (_) {}
    }
    return false;
  } catch (_) {
    return false;
  }
}

export function transformAppHost(hostname) {
  if (!hostname || typeof hostname !== "string") return hostname;
  const parts = hostname.trim().split(":");
  let host = parts[0];
  const port = parts[1] ? `:${parts[1]}` : "";
  // Map Google AI Studio private dev host to public shared preview host
  // e.g. ais-dev-*.run.app -> ais-pre-*.run.app
  if (/^ais-dev-/i.test(host)) {
    host = host.replace(/^ais-dev-/i, "ais-pre-");
  }
  return `${host}${port}`;
}

export function sanitizeAppUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return rawUrl;
  let trimmed = rawUrl.trim().replace(/\/+$/, "");
  // Map private ais-dev origin to public ais-pre preview origin
  if (/:\/\/ais-dev-/i.test(trimmed)) {
    trimmed = trimmed.replace(/:\/\/ais-dev-/i, "://ais-pre-");
  }
  return trimmed;
}

export function getBaseUrl(req = null) {
  // 1. Explicit public/shared production URL takes highest precedence if provided
  const publicEnvUrl = process.env.PUBLIC_URL || process.env.SHARED_APP_URL;
  if (publicEnvUrl && typeof publicEnvUrl === "string" && publicEnvUrl.trim().startsWith("http")) {
    return sanitizeAppUrl(publicEnvUrl.trim());
  }

  // 2. If request comes from an allowed application host, use it (transforming private dev host to public preview)
  if (req) {
    const origin = req.headers?.origin;
    if (origin && typeof origin === "string") {
      try {
        const url = new URL(origin);
        if (isApplicationHost(url.hostname)) {
          const safeHost = transformAppHost(url.host);
          return `${url.protocol}//${safeHost}`.replace(/\/+$/, "");
        }
      } catch (_) {}
    }

    const referer = req.headers?.referer;
    if (referer && typeof referer === "string") {
      try {
        const url = new URL(referer);
        if (isApplicationHost(url.hostname)) {
          const safeHost = transformAppHost(url.host);
          return `${url.protocol}//${safeHost}`.replace(/\/+$/, "");
        }
      } catch (_) {}
    }

    const fwdHost = req.headers?.["x-forwarded-host"];
    if (fwdHost && typeof fwdHost === "string") {
      const hostPart = fwdHost.split(",")[0].trim();
      if (isApplicationHost(hostPart.split(":")[0])) {
        const safeHost = transformAppHost(hostPart);
        const proto = req.headers?.["x-forwarded-proto"]?.split(",")[0].trim() || (req.secure ? "https" : "http");
        return `${proto}://${safeHost}`.replace(/\/+$/, "");
      }
    }

    const host = req.headers?.host;
    if (host && typeof host === "string") {
      const hostPart = host.split(":")[0];
      if (isApplicationHost(hostPart)) {
        const safeHost = transformAppHost(host);
        const proto = req.headers?.["x-forwarded-proto"]?.split(",")[0].trim() || (req.secure ? "https" : "http");
        return `${proto}://${safeHost}`.replace(/\/+$/, "");
      }
    }
  }

  // 3. Fallback to APP_URL or BASE_URL from environment (sanitized for public preview)
  const envUrl = process.env.APP_URL || process.env.BASE_URL;
  if (envUrl && typeof envUrl === "string" && envUrl.trim().startsWith("http")) {
    return sanitizeAppUrl(envUrl.trim());
  }

  // 4. Fallback for local testing / CLI
  const port = process.env.PORT || 3000;
  return `http://localhost:${port}`;
}

export function getSmtpTransporter() {
  if (customTransporter) {
    return customTransporter;
  }
  if (!isSmtpConfigured()) {
    return null;
  }
  if (!cachedTransporter) {
    const port = Number(process.env.SMTP_PORT) || 587;
    cachedTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
  }
  return cachedTransporter;
}

export async function verifySmtpConnection() {
  const transporter = getSmtpTransporter();
  if (!transporter) {
    const status = getSmtpStatus();
    return {
      ok: false,
      error: `SMTP service is not configured. Missing required variables: ${status.missingVariables.join(", ")}`,
      missingVariables: status.missingVariables,
    };
  }
  try {
    if (typeof transporter.verify === "function") {
      await transporter.verify();
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message || "Failed to verify SMTP connection." };
  }
}


export async function sendVerificationEmail(toEmail, token, baseUrl = null) {
  const transporter = getSmtpTransporter();
  if (!transporter) {
    throw new Error("SMTP service is not configured.");
  }

  const effectiveBaseUrl = sanitizeAppUrl(baseUrl || getBaseUrl()).replace(/\/+$/, "");
  const verifyUrl = `${effectiveBaseUrl}/?verifyToken=${encodeURIComponent(token)}`;
  const senderEmail = process.env.SMTP_FROM || process.env.SMTP_USER;

  const mailOptions = {
    from: `"CipherCheck Security" <${senderEmail}>`,
    to: toEmail,
    subject: "Verify your CipherCheck account email",
    text: `Welcome to CipherCheck!\n\nPlease verify your email address by visiting this link:\n${verifyUrl}\n\nAlternatively, you can enter this verification code directly in the CipherCheck account window:\n${token}\n\nThis verification link and code expire in 24 hours.\n\nIf you did not create a CipherCheck account, please ignore this email.`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; background: #ffffff; border: 1px solid #e2e8e2; border-radius: 12px; color: #202924;">
        <div style="display: flex; align-items: center; margin-bottom: 20px;">
          <h2 style="margin: 0; color: #176c4b; font-size: 20px; font-weight: 700;">CipherCheck</h2>
        </div>
        <h3 style="margin-top: 0; font-size: 18px; color: #202924;">Verify your email address</h3>
        <p style="font-size: 14px; line-height: 1.6; color: #52605a;">
          Thank you for creating an account. Please click the button below to verify your email address and activate account recovery features:
        </p>
        <div style="margin: 24px 0;">
          <a href="${verifyUrl}" target="_blank" rel="noopener noreferrer" style="display: inline-block; padding: 12px 24px; background: #176c4b; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 600; border-radius: 8px;">Verify Email Address</a>
        </div>
        <p style="font-size: 12px; line-height: 1.5; color: #76817b;">
          Or copy and paste this link into your browser:<br />
          <a href="${verifyUrl}" target="_blank" rel="noopener noreferrer" style="color: #176c4b; word-break: break-all;">${verifyUrl}</a>
        </p>
        <div style="margin-top: 20px; padding: 12px 16px; background: #f4f6f3; border: 1px solid #e2e8e2; border-radius: 8px;">
          <p style="margin: 0 0 6px; font-size: 12px; font-weight: 600; color: #202924;">Verification Token Code:</p>
          <code style="display: block; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #176c4b; word-break: break-all;">${token}</code>
          <p style="margin: 6px 0 0; font-size: 11px; color: #76817b;">You can also paste this code directly into the CipherCheck account window.</p>
        </div>
        <p style="font-size: 12px; line-height: 1.5; color: #76817b; margin-top: 24px; border-top: 1px solid #e2e8e2; padding-top: 16px;">
          This link and token will expire in 24 hours. If you did not create an account, you can safely ignore this email.
        </p>
      </div>
    `,
  };

  return await transporter.sendMail(mailOptions);
}

export async function sendPasswordResetEmail(toEmail, token, baseUrl = null) {
  const transporter = getSmtpTransporter();
  if (!transporter) {
    throw new Error("SMTP service is not configured.");
  }

  const effectiveBaseUrl = sanitizeAppUrl(baseUrl || getBaseUrl()).replace(/\/+$/, "");
  const resetUrl = `${effectiveBaseUrl}/?resetToken=${encodeURIComponent(token)}`;
  const senderEmail = process.env.SMTP_FROM || process.env.SMTP_USER;

  const mailOptions = {
    from: `"CipherCheck Security" <${senderEmail}>`,
    to: toEmail,
    subject: "Reset your CipherCheck password",
    text: `You requested a password reset for your CipherCheck account.\n\nPlease reset your password by visiting this link:\n${resetUrl}\n\nAlternatively, you can enter this reset token directly in the CipherCheck account window:\n${token}\n\nThis reset link and token expire in 1 hour.\n\nIf you did not request this reset, your account is safe and you can ignore this email.`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; background: #ffffff; border: 1px solid #e2e8e2; border-radius: 12px; color: #202924;">
        <div style="display: flex; align-items: center; margin-bottom: 20px;">
          <h2 style="margin: 0; color: #176c4b; font-size: 20px; font-weight: 700;">CipherCheck</h2>
        </div>
        <h3 style="margin-top: 0; font-size: 18px; color: #202924;">Password Reset Request</h3>
        <p style="font-size: 14px; line-height: 1.6; color: #52605a;">
          We received a request to reset your CipherCheck account password. Click the button below to choose a new password:
        </p>
        <div style="margin: 24px 0;">
          <a href="${resetUrl}" target="_blank" rel="noopener noreferrer" style="display: inline-block; padding: 12px 24px; background: #176c4b; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 600; border-radius: 8px;">Reset Password</a>
        </div>
        <p style="font-size: 12px; line-height: 1.5; color: #76817b;">
          Or copy and paste this link into your browser:<br />
          <a href="${resetUrl}" target="_blank" rel="noopener noreferrer" style="color: #176c4b; word-break: break-all;">${resetUrl}</a>
        </p>
        <div style="margin-top: 20px; padding: 12px 16px; background: #f4f6f3; border: 1px solid #e2e8e2; border-radius: 8px;">
          <p style="margin: 0 0 6px; font-size: 12px; font-weight: 600; color: #202924;">Reset Token Code:</p>
          <code style="display: block; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #176c4b; word-break: break-all;">${token}</code>
          <p style="margin: 6px 0 0; font-size: 11px; color: #76817b;">You can also paste this code directly into the CipherCheck reset window.</p>
        </div>
        <p style="font-size: 12px; line-height: 1.5; color: #76817b; margin-top: 24px; border-top: 1px solid #e2e8e2; padding-top: 16px;">
          This link and token expire in 1 hour. If you did not request a password reset, no action is needed and your account remains secure.
        </p>
      </div>
    `,
  };

  return await transporter.sendMail(mailOptions);
}
