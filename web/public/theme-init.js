(() => {
  try {
    const stored = localStorage.getItem('vrouter-theme')
    const dark =
      stored === 'dark' ||
      ((stored === null || stored === 'system') &&
        window.matchMedia('(prefers-color-scheme: dark)').matches)
    document.documentElement.classList.toggle('dark', dark)
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
  } catch {
    // Theme persistence is optional; keep the system default.
  }
})()
