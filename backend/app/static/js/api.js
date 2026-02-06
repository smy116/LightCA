(() => {
  const originalFetch = window.fetch.bind(window);
  const AUTH_TOKEN_KEY = "lightca.auth.token";

  function getAuthToken() {
    return sessionStorage.getItem(AUTH_TOKEN_KEY) || "";
  }

  function setAuthToken(token) {
    if (token) {
      sessionStorage.setItem(AUTH_TOKEN_KEY, token);
    }
  }

  function clearAuthToken() {
    sessionStorage.removeItem(AUTH_TOKEN_KEY);
  }

  function isApiPath(url) {
    try {
      const parsed = new URL(url, window.location.origin);
      return parsed.pathname.startsWith("/api/");
    } catch {
      return String(url).startsWith("/api/");
    }
  }

  async function apiFetch(url, options = {}) {
    const next = { ...options };
    const headers = new Headers(options.headers || {});
    const token = getAuthToken();

    if (token && !headers.has("Authorization") && isApiPath(url)) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    if (
      next.body &&
      typeof next.body === "object" &&
      !(next.body instanceof FormData) &&
      !(next.body instanceof URLSearchParams) &&
      !headers.has("Content-Type")
    ) {
      headers.set("Content-Type", "application/json");
      next.body = JSON.stringify(next.body);
    }

    if (
      next.body &&
      typeof next.body === "string" &&
      !headers.has("Content-Type")
    ) {
      headers.set("Content-Type", "application/json");
    }

    next.headers = headers;
    const response = await originalFetch(url, next);

    if (response.status === 401 && isApiPath(url)) {
      clearAuthToken();
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }

    return response;
  }

  window.LightCAApi = {
    AUTH_TOKEN_KEY,
    getAuthToken,
    setAuthToken,
    clearAuthToken,
    apiFetch,
  };

  window.apiFetch = apiFetch;

  window.fetch = function patchedFetch(url, options = {}) {
    if (isApiPath(url)) {
      return apiFetch(url, options);
    }
    return originalFetch(url, options);
  };
})();
