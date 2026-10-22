"use strict";

(() => {
  const form = document.getElementById("login-form");
  const password = document.getElementById("password");
  const toggle = document.getElementById("toggle-password");
  const caps = document.getElementById("caps-warning");
  const submit = document.getElementById("submit-button");
  const status = document.getElementById("login-status");
  const label = document.getElementById("submit-label");
  const connection = document.getElementById("connection-warning");
  const error = document.getElementById("login-error");

  if (!form || !password || !toggle || !caps || !submit || !status) {
    return;
  }

  let submitting = false;
  let resetTimer;

  toggle.hidden = false;

  function hidePassword() {
    password.type = "password";
    toggle.textContent = "Show";
    toggle.setAttribute("aria-label", "Show password");
    toggle.setAttribute("aria-pressed", "false");
  }

  function resetSubmission() {
    window.clearTimeout(resetTimer);

    submitting = false;
    submit.disabled = false;
    form.removeAttribute("aria-busy");

    if (label) {
      label.textContent = "Sign in";
    }

    status.textContent = "";
  }

  function updateConnection() {
    // Offline status does not mean localhost is unreachable.
    if (connection) {
      connection.hidden = navigator.onLine !== false;
    }
  }

  toggle.addEventListener("click", () => {
    const show = password.type === "password";

    password.type = show ? "text" : "password";
    toggle.textContent = show ? "Hide" : "Show";

    toggle.setAttribute(
      "aria-label",
      show ? "Hide password" : "Show password"
    );

    toggle.setAttribute("aria-pressed", String(show));
  });

  function checkCaps(event) {
    caps.hidden = !(
      typeof event.getModifierState === "function" &&
      event.getModifierState("CapsLock")
    );
  }

  password.addEventListener("keydown", checkCaps);
  password.addEventListener("keyup", checkCaps);

  password.addEventListener("blur", () => {
    caps.hidden = true;
  });

  form.addEventListener("submit", (event) => {
    if (submitting) {
      event.preventDefault();
      return;
    }

    if (!form.checkValidity()) {
      event.preventDefault();
      form.reportValidity();
      return;
    }

    submitting = true;

    hidePassword();
    caps.hidden = true;
    submit.disabled = true;
    form.setAttribute("aria-busy", "true");

    if (label) {
      label.textContent = "Signing in…";
    }

    status.textContent = "Checking your credentials…";

    resetTimer = window.setTimeout(() => {
      resetSubmission();

      status.textContent =
        "Still waiting. Check that the NIDS server is running before retrying.";
    }, 15000);
  });

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      hidePassword();
      caps.hidden = true;
    }
  });

  window.addEventListener("pagehide", () => {
    window.clearTimeout(resetTimer);
    hidePassword();
  });

  window.addEventListener("pageshow", () => {
    resetSubmission();
    hidePassword();
    caps.hidden = true;
    updateConnection();

    if (error) {
      error.focus();
    }
  });

  window.addEventListener("online", updateConnection);
  window.addEventListener("offline", updateConnection);

  updateConnection();
})();