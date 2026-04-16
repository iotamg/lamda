const AUTH_KEY = "ailearn_auth_v1";

export function getAuth() {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    if (!parsed.email) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function setAuth({ email, name }) {
  const next = {
    email: String(email || "").trim(),
    name: String(name || "").trim() || String(email || "").split("@")[0] || "Learner",
    signedInAt: Date.now(),
  };
  localStorage.setItem(AUTH_KEY, JSON.stringify(next));
  return next;
}

export function clearAuth() {
  localStorage.removeItem(AUTH_KEY);
}

export function requireAuth({ redirectTo = "sign-in.html", reason = "" } = {}) {
  const auth = getAuth();
  if (auth) return auth;

  const url = new URL(redirectTo, window.location.href);
  if (reason) url.searchParams.set("reason", reason);
  window.location.replace(url.toString());
  return null;
}

