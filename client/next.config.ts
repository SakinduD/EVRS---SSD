import type { NextConfig } from "next";

// The API origin the browser is allowed to talk to. Kept in step with
// src/lib/api.ts so connect-src does not have to be edited separately when the
// backend moves.
const apiOrigin = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:5000";

const isDev = process.env.NODE_ENV !== "production";

// Next.js emits inline bootstrap scripts (self.__next_f.push(...)) on every
// page, so script-src needs 'unsafe-inline' unless every response carries a
// nonce. A nonce has to come from middleware, and this app's middleware exists
// to guard routes - widening its matcher to every request to attach a header
// would put the role checks in the path of traffic they were never written for.
// The trade is deliberate: a CSP that is weaker on inline script but still
// blocks framing, plugins, base-tag injection and off-origin form posts is
// worth more than no CSP at all.
//
// 'unsafe-eval' is development only: React Refresh needs it, a production
// build does not.
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob:",
  `connect-src 'self' ${apiOrigin}${isDev ? " ws://localhost:3000" : ""}`,
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

const nextConfig: NextConfig = {
  // Next.js advertises itself in X-Powered-By on every response. A version
  // number is the first thing an attacker looks up against a CVE database.
  poweredByHeader: false,

  async headers() {
    return [
      {
        // Everything, including the static chunks under /_next, which is where
        // most of the missing-header instances were reported.
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          // frame-ancestors above covers modern browsers; this covers the rest.
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), payment=()",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
