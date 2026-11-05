(function () {
  var t = null;
  try { t = localStorage.getItem("hl-theme"); } catch (e) { /* storage blocked */ }
  if (!t) t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
})();
