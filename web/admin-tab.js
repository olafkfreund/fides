// Fides portal enhancement: injects an "Integrations" tab into the Settings
// page's tab strip and renders the Go-served /admin console inside it.
//
// The portal is a pre-compiled React SPA (no source in the repo), so this is a
// runtime enhancement served by the Go server from web/. It does NOT modify the
// SPA bundle; it clones the existing tab styling and overlays an iframe of
// /admin. A poll re-injects the tab if React re-renders the strip.
(function () {
  "use strict";
  var BTN_ID = "fides-integrations-tab";
  var FRAME_ID = "fides-admin-frame";
  var BASE = "px-4 py-2 text-xs font-semibold rounded-lg border transition-all";
  var ACTIVE = "bg-primary/10 border-primary/20 text-foreground";
  var INACTIVE = "bg-transparent border-transparent text-muted-foreground hover:text-foreground";

  function onSettings() {
    return Array.prototype.some.call(
      document.querySelectorAll("h1,h2,h3"),
      function (h) { return /Settings Management/i.test(h.textContent || ""); }
    );
  }
  function tabStrip() {
    var b = Array.prototype.find.call(
      document.querySelectorAll("button"),
      function (e) { return /Infrastructure Settings/i.test(e.textContent || ""); }
    );
    return b ? b.parentElement : null;
  }
  function getFrame() {
    var f = document.getElementById(FRAME_ID);
    if (!f) {
      f = document.createElement("iframe");
      f.id = FRAME_ID;
      f.src = "/admin";
      f.title = "Fides Admin Console";
      f.style.cssText = "position:fixed;border:1px solid #262626;border-radius:10px;background:#0a0a0a;z-index:40;display:none";
      document.body.appendChild(f);
      window.addEventListener("resize", position);
      window.addEventListener("scroll", position, true);
    }
    return f;
  }
  function position() {
    var f = document.getElementById(FRAME_ID);
    if (!f || f.style.display === "none") return;
    var s = tabStrip();
    if (!s) { hide(); return; }
    var r = s.getBoundingClientRect();
    f.style.left = r.left + "px";
    f.style.top = (r.bottom + 10) + "px";
    f.style.width = r.width + "px";
    f.style.height = (window.innerHeight - r.bottom - 30) + "px";
  }
  function show() { getFrame().style.display = "block"; position(); }
  function hide() { var f = document.getElementById(FRAME_ID); if (f) f.style.display = "none"; }
  function setActive(on) {
    var b = document.getElementById(BTN_ID);
    if (b) b.className = BASE + " " + (on ? ACTIVE : INACTIVE);
  }
  function ensure() {
    try {
      if (!onSettings()) { hide(); return; }
      var s = tabStrip();
      if (!s) return;
      // Hide our panel when a native settings tab is clicked.
      Array.prototype.forEach.call(s.children, function (c) {
        if (c.id !== BTN_ID && !c.__fidesHook) {
          c.__fidesHook = 1;
          c.addEventListener("click", function () { hide(); setActive(false); });
        }
      });
      var b = document.getElementById(BTN_ID);
      if (!b) {
        b = document.createElement("button");
        b.id = BTN_ID;
        b.type = "button";
        b.textContent = "Integrations";
        b.className = BASE + " " + INACTIVE;
        b.addEventListener("click", function () { setActive(true); show(); });
        s.appendChild(b);
      } else if (b.parentElement !== s) {
        s.appendChild(b); // React recreated the strip — re-attach.
      }
      var f = document.getElementById(FRAME_ID);
      setActive(!!(f && f.style.display === "block"));
    } catch (e) { /* never break the portal */ }
  }
  setInterval(ensure, 700);
  ensure();
})();
