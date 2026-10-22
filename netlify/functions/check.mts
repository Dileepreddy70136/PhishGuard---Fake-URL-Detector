// Heuristic checks for potentially deceptive URLs, ported from detector.py.
//
// This function deliberately does not visit or resolve submitted URLs. Its
// output is an indicator for review, not a guarantee that a URL is safe or
// malicious.

import { isIP } from "node:net";

const MAX_URL_LENGTH = 2048;
const MAX_BODY_LENGTH = 16 * 1024;

const SUSPICIOUS_TLDS = new Set([
  "accountant", "cam", "click", "country", "gq", "icu", "link", "loan",
  "ml", "mom", "online", "rest", "top", "work", "zip",
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy", "rebrand.ly",
  "shorturl.at", "t.co", "tiny.cc", "tinyurl.com",
]);

const BRAND_DOMAINS: Record<string, string[]> = {
  amazon: ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in"],
  apple: ["apple.com"],
  facebook: ["facebook.com", "fb.com"],
  google: ["google.com", "google.co.uk", "google.ca", "google.de", "google.co.in"],
  microsoft: ["microsoft.com", "live.com", "outlook.com"],
  netflix: ["netflix.com"],
  paypal: ["paypal.com"],
};

const SENSITIVE_TERMS = [
  "account", "banking", "confirm", "login", "password", "payment",
  "secure", "signin", "update", "verify", "wallet",
];

const REDIRECT_PARAMETERS = new Set(["continue", "dest", "destination", "next", "redirect", "url"]);

class ValidationError extends Error {}

const INVALID_HOST_PORT = "Enter a valid URL with a properly formatted host and port.";

function normalizeUrl(input: unknown) {
  if (typeof input !== "string") throw new ValidationError("Enter a URL as text.");

  const value = input.trim();
  if (!value) throw new ValidationError("Enter a URL to check.");
  if (value.length > MAX_URL_LENGTH) {
    throw new ValidationError(`URLs must be ${MAX_URL_LENGTH} characters or fewer.`);
  }
  if (/[\x00-\x1f\s]/.test(value)) {
    throw new ValidationError("The URL cannot contain spaces or control characters.");
  }

  const hasUriScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
  const looksLikeHostPort = /^[^/:]+:\d+(?:\/|$)/.test(value);
  const candidate =
    value.includes("://") || (hasUriScheme && !looksLikeHostPort) ? value : `https://${value}`;

  const scheme = candidate.slice(0, candidate.indexOf(":")).toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    throw new ValidationError("Only HTTP and HTTPS URLs can be checked.");
  }
  if (!/^https?:\/\//i.test(candidate)) {
    throw new ValidationError("The URL must include a valid hostname.");
  }

  const afterScheme = candidate.slice(scheme.length + 3);
  const netloc = afterScheme.split(/[/?#\\]/, 1)[0];
  if (!netloc) throw new ValidationError("The URL must include a valid hostname.");

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new ValidationError(INVALID_HOST_PORT);
  }

  let hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!hostname) throw new ValidationError("The URL must include a valid hostname.");

  if (!isIP(hostname)) {
    // URL() has already converted any internationalised name to punycode.
    hostname = hostname.replace(/\.+$/, "");
    const labels = hostname.split(".");
    if (
      hostname.length > 253 ||
      !hostname ||
      labels.some(
        (label) =>
          !label ||
          label.length > 63 ||
          label.startsWith("-") ||
          label.endsWith("-") ||
          !/^[a-z0-9-]+$/.test(label),
      )
    ) {
      throw new ValidationError("Enter a valid hostname.");
    }
  }

  return {
    value,
    url,
    hostname,
    port: url.port ? Number(url.port) : null,
    hasCredentials: netloc.includes("@"),
    normalizedUrl: scheme + candidate.slice(scheme.length),
  };
}

export function analyzeUrl(input: unknown) {
  const { value, url, hostname, port, hasCredentials, normalizedUrl } = normalizeUrl(input);
  const labels = hostname.split(".");
  let score = 0;
  const reasons: string[] = [];

  const flag = (points: number, message: string) => {
    score += points;
    reasons.push(message);
  };

  if (hasCredentials) {
    flag(25, "This link has extra text before the website name, which can be used to disguise its destination.");
  }

  if (isIP(hostname)) {
    flag(25, "Instead of a familiar website name, this link uses a string of numbers.");
  } else {
    const hostWithoutWww = hostname.startsWith("www.") ? hostname.slice(4) : hostname;
    const tld = labels[labels.length - 1];
    if (URL_SHORTENERS.has(hostWithoutWww)) {
      flag(20, "This is a shortened link, so it hides where you’ll end up.");
    }
    if (SUSPICIOUS_TLDS.has(tld)) {
      flag(15, `This link ends in .${tld}, an address ending that’s worth checking closely.`);
    }
    if (labels.some((label) => label.includes("xn--"))) {
      flag(20, "Some letters in this website name may be designed to look like other letters.");
    }

    for (const [brand, allowedDomains] of Object.entries(BRAND_DOMAINS)) {
      const containsBrand = labels.slice(0, -1).some((label) => label.includes(brand));
      if (
        containsBrand &&
        !allowedDomains.some((domain) => hostWithoutWww === domain || hostWithoutWww.endsWith(`.${domain}`))
      ) {
        flag(25, `The website name mentions ${brand}, but it doesn’t match that company’s usual web address.`);
        break;
      }
    }
  }

  if (labels.length >= 5) flag(10, "There are a lot of extra sections in this website name.");
  if (hostname.includes("-")) flag(5, "The website name has hyphens, sometimes used to imitate a familiar site.");
  if (url.protocol !== "https:") flag(10, "This link doesn’t use a secure HTTPS connection.");
  if (port !== null && port !== 80 && port !== 443) {
    flag(10, `This link uses an unusual connection setting (${port}).`);
  }

  const searchableUrl = `${hostname}${url.pathname}`.toLowerCase();
  if (SENSITIVE_TERMS.some((term) => searchableUrl.includes(term))) {
    flag(10, "The link uses words like sign-in or verify, which can show up in fake login links.");
  }

  if (value.length > 120) flag(5, "This is a very long link, so it may be harder to tell where it leads.");

  for (const [key, parameterValue] of new URLSearchParams(url.search)) {
    if (REDIRECT_PARAMETERS.has(key.toLowerCase()) && parameterValue.includes("://")) {
      flag(10, "The link contains another web address, which may hide where you’ll end up.");
      break;
    }
  }

  score = Math.min(score, 100);
  const verdict = score >= 40 ? "High risk" : score >= 20 ? "Suspicious" : "No obvious warning signs";

  return {
    verdict,
    score,
    reasons: reasons.length
      ? reasons
      : ["We didn’t spot common warning signs, but it’s still worth checking who sent it."],
    hostname,
    normalized_url: normalizedUrl,
  };
}

const json = (body: unknown, status = 200) => Response.json(body, { status });

export default async (req: Request) => {
  if (req.method !== "POST") return json({ error: "Use POST to check a URL." }, 405);

  const body = await req.text();
  if (body.length > MAX_BODY_LENGTH) return json({ error: "The request body is too large." }, 413);

  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    payload = null;
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return json({ error: "Send a JSON object with a 'url' field." }, 400);
  }

  try {
    return json(analyzeUrl((payload as { url?: unknown }).url));
  } catch (error) {
    if (error instanceof ValidationError) return json({ error: error.message }, 400);
    throw error;
  }
};

export const config = { path: "/api/check" };
