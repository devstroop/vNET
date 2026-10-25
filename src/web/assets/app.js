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

  document.body.addEventListener("htmx:responseError", () => {
    const indicator = document.getElementById("refresh-indicator");
    if (!indicator) return;
    indicator.textContent = "Refresh failed";
    indicator.classList.add("is-visible");
  });
})();
