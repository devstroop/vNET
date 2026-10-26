(() => {
  try {
    const saved = localStorage.getItem("vnet-theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.dataset.theme = saved;
    }
  } catch {
    // Storage can be disabled; the CSS media query is still a good default.
  }
})();
