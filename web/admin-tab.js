// Fides portal enhancement: injects Go-served admin pages as tabs in the
// Settings page's tab strip. The portal is a pre-compiled React SPA (no source
// in the repo), so this is a runtime enhancement served by the Go server from
// web/ — it does NOT modify the SPA bundle. It clones the existing tab styling,
// injects our tabs, and renders the target page in a shared same-origin iframe.
// A poll re-injects if React re-renders; everything is try/catch-guarded so it
// can never break the portal.
(function () {
  "use strict";
  var FRAME_ID = "fides-embed-frame";
  var BASE = "px-4 py-2 text-xs font-semibold rounded-lg border transition-all";
  var ACTIVE = "bg-primary/10 border-primary/20 text-foreground";
  var INACTIVE = "bg-transparent border-transparent text-muted-foreground hover:text-foreground";

  // Tabs to inject (order = display order after the native tabs).
  var TABS = [
    { id: "fides-servicenow-tab", label: "ServiceNow", src: "/servicenow" },
    { id: "fides-integrations-tab", label: "Integrations", src: "/admin" }
  ];

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
      f.title = "Fides embedded admin";
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
  function showSrc(src) {
    var f = getFrame();
    if (f.getAttribute("src") !== src) f.setAttribute("src", src);
    f.style.display = "block";
    position();
  }
  function hide() { var f = document.getElementById(FRAME_ID); if (f) f.style.display = "none"; }

  // Which of our tabs (if any) is currently active (frame visible on that src).
  function activeSrc() {
    var f = document.getElementById(FRAME_ID);
    return (f && f.style.display === "block") ? f.getAttribute("src") : null;
  }
  function syncActive() {
    var cur = activeSrc();
    TABS.forEach(function (t) {
      var b = document.getElementById(t.id);
      if (b) b.className = BASE + " " + (cur === t.src ? ACTIVE : INACTIVE);
    });
  }

  function ensure() {
    try {
      if (!onSettings()) { hide(); return; }
      var s = tabStrip();
      if (!s) return;
      var ourIds = TABS.map(function (t) { return t.id; });
      // Native tabs hide our frame when clicked.
      Array.prototype.forEach.call(s.children, function (c) {
        if (ourIds.indexOf(c.id) === -1 && !c.__fidesHook) {
          c.__fidesHook = 1;
          c.addEventListener("click", function () { hide(); syncActive(); });
        }
      });
      // Inject each of our tabs if missing / re-attach if React moved them.
      TABS.forEach(function (t) {
        var b = document.getElementById(t.id);
        if (!b) {
          b = document.createElement("button");
          b.id = t.id;
          b.type = "button";
          b.textContent = t.label;
          b.className = BASE + " " + INACTIVE;
          b.addEventListener("click", function () { showSrc(t.src); syncActive(); });
          s.appendChild(b);
        } else if (b.parentElement !== s) {
          s.appendChild(b);
        }
      });
      syncActive();
    } catch (e) { /* never break the portal */ }
  }
  setInterval(ensure, 700);
  ensure();
})();
