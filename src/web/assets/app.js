(() => {
  const root = document.documentElement;
  const toggle = document.querySelector("[data-theme-toggle]");
  const media = window.matchMedia("(prefers-color-scheme: dark)");

  function currentTheme() {
    return root.dataset.theme || (media.matches ? "dark" : "light");
  }

  function updateToggle() {
    if (!toggle) return;
    toggle.textContent = currentTheme() === "dark" ? "Light" : "Dark";
  }

  if (toggle) {
    toggle.addEventListener("click", () => {
      const next = currentTheme() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem("vrouter-theme", next);
      } catch {
        // Ignore storage failures; the current page still switches.
      }
      updateToggle();
    });
  }
  updateToggle();

  function openDialog(id) {
    const dialog = document.getElementById(id);
    if (!dialog || typeof dialog.showModal !== "function") return;
    if (!dialog.open) dialog.showModal();
  }

  function openAutoDialogs() {
    for (const dialog of document.querySelectorAll("dialog[data-auto-open]")) {
      if (dialog.open || typeof dialog.showModal !== "function") continue;
      dialog.showModal();
    }
  }

  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const opener = target.closest("[data-dialog-open]");
    if (opener) {
      event.preventDefault();
      openDialog(opener.getAttribute("data-dialog-open"));
      return;
    }

    const closer = target.closest("[data-dialog-close]");
    if (closer) {
      event.preventDefault();
      const dialog = closer.closest("dialog");
      if (dialog) dialog.close();
      return;
    }

    const confirm = target.closest("[data-confirm-open]");
    if (confirm) {
      event.preventDefault();
      const dialog = document.getElementById(confirm.getAttribute("data-confirm-open"));
      if (!dialog) return;
      const form = dialog.querySelector("form");
      if (!form) return;
      for (const input of form.querySelectorAll("[data-confirm-field]")) {
        const field = input.getAttribute("data-confirm-field");
        if (field) input.value = confirm.getAttribute(`data-${field}`) || "";
      }
      const message = dialog.querySelector("[data-confirm-message]");
      if (message) {
        const label = confirm.getAttribute("data-label") || "this rule";
        message.textContent = `Stage removal of ${label}? Nothing changes until you save the draft.`;
      }
      openDialog(dialog.id);
      return;
    }

    if (target instanceof HTMLDialogElement && target === event.target) {
      target.close();
    }
  });

  document.body.addEventListener("htmx:after:swap", openAutoDialogs);
  document.body.addEventListener("htmx:response:error", () => {
    const indicator = document.getElementById("refresh-indicator");
    if (!indicator) return;
    indicator.textContent = "Refresh failed";
    indicator.classList.add("is-visible");
  });
})();
