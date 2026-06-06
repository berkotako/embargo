/* global React, ReactDOM, Icon, useStored, useTweaks, TweaksPanel, TweakSection, TweakRadio,
   Dashboard, QuarantineScreen, PolicyEditor, ApprovalsScreen, InspectorScreen, AuditScreen */
(function () {
  const { useState, useEffect, useRef } = React;
  const E = window.EMBARGO;

  const NAV = [
    { id: "dashboard", label: "Dashboard", icon: "dashboard" },
    { id: "quarantine", label: "Quarantine Queue", icon: "queue", count: E.QUEUE.length, hot: true },
    { id: "policy", label: "Policy Editor", icon: "policy" },
    { id: "approvals", label: "Approvals & Exceptions", icon: "approvals", count: E.APPROVALS.filter((a) => a.status === "pending").length },
    { id: "inspector", label: "Package Inspector", icon: "inspector" },
    { id: "audit", label: "Audit Log", icon: "audit" },
  ];
  const TITLES = Object.fromEntries(NAV.map((n) => [n.id, n.label]));
  const ROLES = ["viewer", "approver", "admin"];

  const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
    "role": "admin",
    "density": "comfortable",
    "dataState": "populated"
  }/*EDITMODE-END*/;

  // ---- Toasts ----
  function ToastHost() {
    const [toasts, setToasts] = useState([]);
    useEffect(() => {
      window.embargoToast = (msg, kind) => {
        const id = Math.random().toString(36).slice(2);
        setToasts((t) => [...t, { id, msg, kind }]);
        setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3600);
      };
    }, []);
    const color = (k) => k === "deny" ? "var(--deny)" : k === "hold" ? "var(--hold)" : "var(--allow)";
    return React.createElement("div", { style: { position: "fixed", right: 20, bottom: 20, zIndex: 120, display: "flex", flexDirection: "column", gap: 9 } },
      toasts.map((t) => React.createElement("div", { key: t.id, className: "rise", style: {
        display: "flex", alignItems: "center", gap: 10, background: "var(--panel-2)", border: "1px solid var(--border-2)",
        borderLeft: "3px solid " + color(t.kind), borderRadius: "var(--radius)", padding: "11px 15px",
        boxShadow: "var(--shadow)", fontSize: 12.5, minWidth: 240, maxWidth: 380,
      } },
        React.createElement("span", { style: { color: color(t.kind), display: "inline-flex" } }, React.createElement(Icon, { name: t.kind === "deny" ? "x" : t.kind === "hold" ? "bolt" : "check", size: 16 })),
        React.createElement("span", null, t.msg))));
  }

  // ---- Role switcher ----
  function RoleSwitch({ role, setRole }) {
    const [open, setOpen] = useState(false);
    const ref = useRef(null);
    useEffect(() => {
      function h(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
      document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h);
    }, []);
    const desc = { viewer: "read-only", approver: "approve / deny", admin: "full control" };
    return React.createElement("div", { ref, style: { position: "relative" } },
      React.createElement("div", { className: "role-switch", onClick: () => setOpen(!open) },
        React.createElement("div", { className: "col", style: { lineHeight: 1.15 } },
          React.createElement("span", { className: "role-label" }, "Role"),
          React.createElement("span", { className: "role-val" }, role)),
        React.createElement(Icon, { name: "chevdown", size: 13, style: { color: "var(--text-faint)" } }),
        React.createElement("span", { className: "avatar" }, "HO")),
      open ? React.createElement("div", { className: "menu" },
        React.createElement("div", { style: { padding: "6px 10px 8px", borderBottom: "1px solid var(--border)", marginBottom: 4 } },
          React.createElement("div", { style: { fontSize: 12.5, fontWeight: 600 } }, "Hana Okafor"),
          React.createElement("div", { className: "cell-sub" }, "hana.okafor@mycompany.io")),
        ROLES.map((r) => React.createElement("div", { key: r, className: "menu-item" + (r === role ? " sel" : ""), onClick: () => { setRole(r); setOpen(false); } },
          React.createElement("span", { style: { textTransform: "capitalize" } }, r),
          r === role ? React.createElement(Icon, { name: "check", size: 14 }) : React.createElement("span", { className: "menu-sub" }, desc[r])))) : null);
  }

  function App() {
    const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
    const role = t.role, density = t.density, dataState = t.dataState;

    const [route, setRoute] = useStored("embargo.route", "quarantine");
    const [entering, setEntering] = useState(false);

    // hash sync
    useEffect(() => {
      const fromHash = (location.hash || "").replace("#", "");
      if (fromHash && TITLES[fromHash]) setRoute(fromHash);
    }, []);
    useEffect(() => {
      if (location.hash !== "#" + route) history.replaceState(null, "", "#" + route);
      document.title = "Embargo · " + (TITLES[route] || "");
    }, [route]);

    // brief loading on route entry (unless tweak forces a state)
    useEffect(() => {
      if (dataState !== "populated") return;
      setEntering(true);
      const id = setTimeout(() => setEntering(false), 420);
      return () => clearTimeout(id);
    }, [route, dataState]);

    function nav(id) { setRoute(id); }

    const effState = dataState === "populated" ? (entering ? "loading" : "populated") : dataState;

    let screen;
    if (route === "dashboard") screen = React.createElement(Dashboard, { dataState: effState, onNav: nav });
    else if (route === "quarantine") screen = React.createElement(QuarantineScreen, { role, dataState: effState });
    else if (route === "policy") screen = React.createElement(PolicyEditor, { role });
    else if (route === "approvals") screen = React.createElement(ApprovalsScreen, { role });
    else if (route === "inspector") screen = React.createElement(InspectorScreen, null);
    else if (route === "audit") screen = React.createElement(AuditScreen, null);

    return React.createElement("div", { className: "app", "data-density": density === "compact" ? "compact" : "comfortable", "data-role": role },
      // sidebar
      React.createElement("aside", { className: "sidebar" },
        React.createElement("div", { className: "brand" },
          React.createElement("span", { className: "brand-mark", style: { background: "rgba(77,141,255,.13)", borderRadius: 7, color: "var(--accent-2)" } }, React.createElement(Icon, { name: "shield", size: 17 })),
          React.createElement("div", { className: "col" },
            React.createElement("span", { className: "brand-name" }, "Embargo"),
            React.createElement("span", { className: "brand-tag" }, "dependency firewall"))),
        React.createElement("nav", { className: "nav" },
          React.createElement("div", { className: "nav-label" }, "Operations"),
          NAV.slice(0, 2).map((n) => navItem(n, route, nav)),
          React.createElement("div", { className: "nav-label" }, "Governance"),
          NAV.slice(2).map((n) => navItem(n, route, nav))),
        React.createElement("div", { className: "sidebar-foot" },
          React.createElement("div", { className: "row gap8" }, React.createElement("span", { className: "health-dot" }), "engine online · 4 inspectors"),
          React.createElement("div", null, "v2.4.1 · registry@npmjs.org"))),

      // main
      React.createElement("div", { className: "main" },
        React.createElement("header", { className: "topbar" },
          React.createElement("div", { className: "col", style: { lineHeight: 1.2 } },
            React.createElement("span", { className: "topbar-title" }, TITLES[route]),
            React.createElement("span", { className: "topbar-sub" }, "embargo / " + route)),
          React.createElement("div", { className: "topbar-spacer" }),
          React.createElement("span", { className: "env-pill" }, React.createElement("span", { className: "health-dot" }), "prod-registry"),
          React.createElement("div", { className: "topsearch" },
            React.createElement(Icon, { name: "search", size: 14 }),
            React.createElement("input", { placeholder: "Search packages, advisories…" }),
            React.createElement("kbd", null, "⌘K")),
          React.createElement(RoleSwitch, { role, setRole: (r) => setTweak("role", r) })),
        React.createElement("main", { className: "content", key: route }, screen)),

      React.createElement(ToastHost, null),

      // tweaks
      React.createElement(TweaksPanel, null,
        React.createElement(TweakSection, { label: "Demo controls" }),
        React.createElement(TweakRadio, { label: "Role", value: role, options: ROLES, onChange: (v) => setTweak("role", v) }),
        React.createElement(TweakRadio, { label: "Density", value: density, options: ["compact", "comfortable"], onChange: (v) => setTweak("density", v) }),
        React.createElement(TweakSection, { label: "Data state" }),
        React.createElement(TweakRadio, { label: "State", value: dataState, options: ["populated", "loading", "empty"], onChange: (v) => setTweak("dataState", v) })));
  }

  function navItem(n, route, nav) {
    return React.createElement("div", { key: n.id, className: "nav-item" + (route === n.id ? " active" : ""), onClick: () => nav(n.id) },
      React.createElement("span", { className: "nav-ico" }, React.createElement(Icon, { name: n.icon, size: 17 })),
      React.createElement("span", null, n.label),
      n.count ? React.createElement("span", { className: "nav-count" + (n.hot ? " hot" : "") }, n.count) : null);
  }

  ReactDOM.createRoot(document.getElementById("root")).render(React.createElement(App, null));
})();
