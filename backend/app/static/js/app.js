(() => {
  const THEME_KEY = "lightca.theme";
  const SIDEBAR_KEY = "lightca.sidebar.open";

  function getTheme() {
    return localStorage.getItem(THEME_KEY) || "winter";
  }

  function setTheme(theme) {
    const value = theme === "dim" ? "dim" : "winter";
    localStorage.setItem(THEME_KEY, value);
    document.documentElement.setAttribute("data-theme", value);
    return value;
  }

  function toggleTheme() {
    return setTheme(getTheme() === "winter" ? "dim" : "winter");
  }

  function getSidebarOpen() {
    const value = localStorage.getItem(SIDEBAR_KEY);
    if (value === null) return window.innerWidth >= 1024;
    return value === "1";
  }

  function setSidebarOpen(value) {
    const next = Boolean(value);
    localStorage.setItem(SIDEBAR_KEY, next ? "1" : "0");
    return next;
  }

  function notify(message, type = "info") {
    const toast = document.getElementById("global-toast");
    const box = document.getElementById("global-toast-box");
    const msg = document.getElementById("global-toast-message");
    if (!toast || !box || !msg) return;
    msg.textContent = message;
    box.className = `alert alert-${type}`;
    toast.classList.remove("hidden");
    setTimeout(() => toast.classList.add("hidden"), 2500);
  }

  function notifySuccess(message) {
    notify(message, "success");
  }

  function notifyError(message) {
    notify(message, "error");
  }

  function showMessageBox(options = {}) {
    const modal = document.getElementById("global-msgbox");
    const title = document.getElementById("global-msgbox-title");
    const message = document.getElementById("global-msgbox-message");
    const input = document.getElementById("global-msgbox-input");
    const confirmBtn = document.getElementById("global-msgbox-confirm");
    const cancelBtn = document.getElementById("global-msgbox-cancel");

    if (!modal || !title || !message || !confirmBtn || !cancelBtn) {
      if (options.mode === "prompt") {
        return Promise.resolve(window.prompt(options.message || "", options.defaultValue || ""));
      }
      return Promise.resolve(window.confirm(options.message || "Are you sure?"));
    }

    const mode = options.mode || "confirm";
    title.textContent = options.title || (mode === "prompt" ? "请输入" : "请确认");
    message.textContent = options.message || "";
    confirmBtn.textContent = options.confirmText || "确定";
    cancelBtn.textContent = options.cancelText || "取消";
    confirmBtn.className = `btn ${options.confirmClass || "btn-primary"}`;
    cancelBtn.classList.toggle("hidden", mode === "alert");

    if (input) {
      if (mode === "prompt") {
        input.value = options.defaultValue || "";
        input.placeholder = options.placeholder || "";
        input.classList.remove("hidden");
      } else {
        input.value = "";
        input.classList.add("hidden");
      }
    }

    return new Promise((resolve) => {
      let settled = false;

      const cleanup = () => {
        confirmBtn.removeEventListener("click", onConfirm);
        cancelBtn.removeEventListener("click", onCancel);
        modal.removeEventListener("close", onClose);
      };

      const settle = (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      };

      const onConfirm = () => {
        const value = mode === "prompt" ? input.value : true;
        modal.close();
        settle(value);
      };

      const onCancel = () => {
        modal.close();
        settle(mode === "prompt" ? null : false);
      };

      const onClose = () => {
        settle(mode === "prompt" ? null : false);
      };

      confirmBtn.addEventListener("click", onConfirm);
      cancelBtn.addEventListener("click", onCancel);
      modal.addEventListener("close", onClose);
      modal.showModal();
      if (mode === "prompt" && input) {
        input.focus();
        input.select();
      } else {
        confirmBtn.focus();
      }
    });
  }

  function copyText(value) {
    if (!value) return;
    navigator.clipboard.writeText(String(value));
  }

  function logout() {
    if (window.LightCAApi) {
      window.LightCAApi.clearAuthToken();
    }
    window.location.href = "/login";
  }

  function getFilenameFromDisposition(disposition) {
    if (!disposition) return "download.bin";
    const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match?.[1]) {
      return decodeURIComponent(utf8Match[1]);
    }
    const simpleMatch = disposition.match(/filename="?([^";]+)"?/i);
    if (simpleMatch?.[1]) {
      return simpleMatch[1];
    }
    return "download.bin";
  }

  async function downloadWithAuth(url) {
    const response = await apiFetch(url);
    if (!response.ok) {
      throw new Error(`Download failed (${response.status})`);
    }
    const blob = await response.blob();
    const filename = getFilenameFromDisposition(response.headers.get("Content-Disposition"));
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
  }

  function statusBadgeClass(status) {
    const normalized = String(status || "").toLowerCase();
    if (normalized === "valid" || normalized === "success") return "badge-success badge-outline";
    if (normalized === "revoked" || normalized === "error") return "badge-error";
    if (normalized === "expired" || normalized === "warning") return "badge-warning";
    return "badge-info";
  }

  function certificateTypeLabel(type) {
    const normalized = String(type || "").toLowerCase();
    if (normalized === "root") return "根证书";
    if (normalized === "intermediate") return "中间证书";
    if (normalized === "leaf") return "终端证书";
    return type || "未知";
  }

  function certificateStatusLabel(status) {
    const normalized = String(status || "").toLowerCase();
    if (normalized === "valid") return "有效";
    if (normalized === "revoked") return "已吊销";
    if (normalized === "expired") return "已过期";
    return status || "未知";
  }

  async function confirmAction(message, options = {}) {
    const result = await showMessageBox({
      mode: "confirm",
      message: message || "Are you sure?",
      title: options.title || "请确认操作",
      confirmText: options.confirmText || "确定",
      cancelText: options.cancelText || "取消",
      confirmClass: options.confirmClass || "btn-primary",
    });
    return Boolean(result);
  }

  async function promptAction(message, options = {}) {
    return showMessageBox({
      mode: "prompt",
      message: message || "",
      title: options.title || "请输入",
      defaultValue: options.defaultValue || "",
      placeholder: options.placeholder || "",
      confirmText: options.confirmText || "确定",
      cancelText: options.cancelText || "取消",
      confirmClass: options.confirmClass || "btn-primary",
    });
  }

  function requireAuth() {
    if (window.location.pathname === "/login") return;
    if (!window.LightCAApi || !window.LightCAApi.getAuthToken()) {
      window.location.href = "/login";
    }
  }

  function appShell() {
    return {
      sidebarOpen: getSidebarOpen(),
      theme: getTheme(),
      init() {
        this.theme = setTheme(this.theme);
        requireAuth();
      },
      switchTheme() {
        this.theme = toggleTheme();
      },
      toggleSidebar() {
        this.sidebarOpen = setSidebarOpen(!this.sidebarOpen);
      },
      setSidebarState(open) {
        this.sidebarOpen = setSidebarOpen(open);
      },
    };
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-copy-target]");
    if (!button) return;
    const targetId = button.getAttribute("data-copy-target");
    const input = document.getElementById(targetId);
    if (!input) return;
    copyText(input.value);
    notifySuccess("Copied");
  });

  window.LightCAApp = {
    THEME_KEY,
    getTheme,
    setTheme,
    toggleTheme,
    getSidebarOpen,
    setSidebarOpen,
    notify,
    notifySuccess,
    notifyError,
    showMessageBox,
    copyText,
    logout,
    downloadWithAuth,
    statusBadgeClass,
    certificateTypeLabel,
    certificateStatusLabel,
    confirmAction,
    promptAction,
    requireAuth,
    appShell,
  };

  window.appShell = appShell;
  window.notify = notify;
  window.notifySuccess = notifySuccess;
  window.notifyError = notifyError;
  window.copyText = copyText;
  window.logout = logout;
  window.downloadWithAuth = downloadWithAuth;
  window.statusBadgeClass = statusBadgeClass;
  window.certificateTypeLabel = certificateTypeLabel;
  window.certificateStatusLabel = certificateStatusLabel;
  window.confirmAction = confirmAction;
  window.promptAction = promptAction;
})();
