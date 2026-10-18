"use strict";

const form = document.getElementById("login-form");
const password = document.getElementById("password");
const toggle = document.getElementById("toggle-password");
const capsWarning = document.getElementById("caps-warning");
const submitButton = document.getElementById("submit-button");
const statusMessage = document.getElementById("login-status");

toggle.hidden = false;

toggle.addEventListener("click", () => {
  const showPassword = password.type === "password";

  password.type = showPassword ? "text" : "password";
  toggle.textContent = showPassword ? "Hide" : "Show";
  toggle.setAttribute(
    "aria-label",
    showPassword ? "Hide password" : "Show password"
  );
  toggle.setAttribute("aria-pressed", String(showPassword));
});

function updateCapsWarning(event) {
  capsWarning.hidden = !event.getModifierState("CapsLock");
}

password.addEventListener("keydown", updateCapsWarning);
password.addEventListener("keyup", updateCapsWarning);

password.addEventListener("blur", () => {
  capsWarning.hidden = true;
});

let resetTimer;

function resetSubmission() {
  clearTimeout(resetTimer);
  submitButton.disabled = false;
  form.removeAttribute("aria-busy");
  statusMessage.textContent = "";
}

form.addEventListener("submit", () => {
  submitButton.disabled = true;
  form.setAttribute("aria-busy", "true");
  statusMessage.textContent = "Signing you in…";

  // Allow another attempt if navigation stalls.
  resetTimer = setTimeout(() => {
    resetSubmission();
    statusMessage.textContent =
      "Still waiting. Check your connection before trying again.";
  }, 15000);
});

window.addEventListener("pageshow", () => {
  resetSubmission();

  password.type = "password";
  toggle.textContent = "Show";
  toggle.setAttribute("aria-label", "Show password");
  toggle.setAttribute("aria-pressed", "false");
  capsWarning.hidden = true;
});
