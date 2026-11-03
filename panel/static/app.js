/* ShieldWAF panel: no inline scripts are allowed by the CSP, so all behaviour lives here. */
(function () {
  // confirm dialogs: <button data-confirm="Are you sure?">
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-confirm]");
    if (b && !window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
  });

  // live preview of the visitor pages (Pages screen)
  function strip(v) { return v.split("{{SITE}}").join("example.com").replace(/<meta http-equiv="refresh"[^>]*>/gi, ""); }
  function preview(box) {
    var ta = document.getElementById(box.getAttribute("data-src")), frame = document.getElementById(box.getAttribute("data-frame"));
    var v = ta.value;
    if (!v.trim()) { v = document.getElementById(box.getAttribute("data-default")).value; }
    frame.srcdoc = strip(v);
  }
  document.querySelectorAll("[data-preview]").forEach(function (ta) {
    var box = { getAttribute: function (k) { return { "data-src": ta.id, "data-frame": ta.getAttribute("data-frame"), "data-default": ta.getAttribute("data-default") }[k]; } };
    ta.addEventListener("input", function () { preview(box); });
    preview(box);
  });
  document.querySelectorAll("[data-fill]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var ta = document.getElementById(btn.getAttribute("data-fill"));
      ta.value = document.getElementById(btn.getAttribute("data-default")).value;
      ta.dispatchEvent(new Event("input"));
    });
  });

  // show/hide TLS source specific fields
  var src = document.getElementById("tls_source");
  function tlsFields() {
    if (!src) return;
    document.querySelectorAll("[data-tls]").forEach(function (el) {
      el.style.display = el.getAttribute("data-tls").split(" ").indexOf(src.value) >= 0 ? "" : "none";
    });
  }
  if (src) { src.addEventListener("change", tlsFields); tlsFields(); }
})();
