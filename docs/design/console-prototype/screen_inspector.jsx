/* global React, Icon, VerdictBadge, SignalTag, Provenance */
(function () {
  const { useState } = React;
  const E = window.EMBARGO;

  function InspectorScreen() {
    const keys = Object.keys(E.INSPECTOR);
    const [q, setQ] = useState("");
    const [selKey, setSelKey] = useState(keys[0]);
    const matches = keys.filter((k) => k.toLowerCase().includes(q.toLowerCase()));
    const pkg = E.INSPECTOR[selKey];

    return React.createElement("div", { className: "content-pad" },
      React.createElement("div", { className: "page-head" },
        React.createElement("div", null,
          React.createElement("h1", null, "Package Inspector"),
          React.createElement("div", { className: "sub" }, "Full version history, provenance, and pull origin for any package")),
        React.createElement("div", { className: "grow" })),

      React.createElement("div", { className: "topsearch", style: { width: 420, marginBottom: 18 } },
        React.createElement(Icon, { name: "search", size: 15 }),
        React.createElement("input", { placeholder: "search any package — try axios or @mycompany/auth-sdk", value: q, onChange: (e) => setQ(e.target.value) })),

      q && matches.length > 0 && matches[0] !== selKey ? React.createElement("div", { className: "tbl-wrap", style: { marginBottom: 16 } },
        matches.map((k) => React.createElement("div", { key: k, className: "rule-item", onClick: () => { setSelKey(k); setQ(""); } },
          React.createElement("span", { className: "mono", style: { fontSize: 13 } }, k), React.createElement("span", { className: "dim", style: { fontSize: 11, marginLeft: 10 } }, E.INSPECTOR[k].versions.length + " versions")))) : null,

      pkg ? React.createElement(React.Fragment, null,
        React.createElement("div", { className: "panel", style: { marginBottom: 16 } },
          React.createElement("div", { className: "panel-body", style: { paddingBottom: 14 } },
            React.createElement("div", { className: "inspector-head" },
              React.createElement("div", { style: { width: 44, height: 44, borderRadius: 11, background: "var(--panel-3)", display: "grid", placeItems: "center", color: "var(--accent-2)", flex: "0 0 auto" } }, React.createElement(Icon, { name: "package2", size: 22 })),
              React.createElement("div", { className: "grow" },
                React.createElement("div", { style: { fontFamily: "var(--mono)", fontSize: 18 } }, pkg.scope ? React.createElement("span", { className: "dim" }, pkg.scope + "/") : null, pkg.name),
                React.createElement("div", { className: "row gap14", style: { marginTop: 6, fontSize: 12, color: "var(--text-dim)" } },
                  React.createElement("span", null, "latest ", React.createElement("span", { className: "mono", style: { color: "var(--accent-2)" } }, pkg.latest)),
                  React.createElement("span", null, pkg.weekly + " weekly"),
                  React.createElement("span", { className: "mono" }, pkg.repo),
                  React.createElement("span", null, pkg.maintainers.length + " maintainer" + (pkg.maintainers.length > 1 ? "s" : "")))),
              React.createElement("div", { className: "row gap8" },
                React.createElement("button", { className: "btn btn-sm" }, React.createElement(Icon, { name: "history", size: 14 }), "Watch"))))),

        React.createElement("div", { className: "panel" },
          React.createElement("div", { className: "panel-head" }, React.createElement("h2", null, "Version timeline"), React.createElement("span", { className: "ph-sub" }, pkg.versions.length + " resolved versions · newest first")),
          React.createElement("div", { className: "panel-body" },
            React.createElement("div", { className: "timeline" }, pkg.versions.map((v, i) =>
              React.createElement("div", { key: i, className: "tl-node" },
                React.createElement("span", { className: "tl-dot " + v.verdict.toLowerCase() }),
                React.createElement("div", { className: "tl-card" },
                  React.createElement("div", { className: "row between" },
                    React.createElement("div", { className: "row gap10" },
                      React.createElement("span", { className: "tl-ver" }, pkg.name, React.createElement("span", { className: "ver" }, "@" + v.version)),
                      React.createElement(VerdictBadge, { v: v.verdict }),
                      v.exception ? React.createElement("span", { className: "badge badge-accent", style: { fontSize: 9 } }, React.createElement(Icon, { name: "shield", size: 10 }), "exception") : null),
                    React.createElement("span", { className: "tl-time" }, v.date)),
                  React.createElement("div", { className: "tl-meta" },
                    React.createElement("span", { className: "row gap6" }, "provenance ", React.createElement(Provenance, { status: v.provenance })),
                    React.createElement("span", { className: "row gap6" }, React.createElement(Icon, { name: "git", size: 13, style: { color: "var(--text-faint)" } }), v.pulledBy + " · " + v.pipeline)),
                  v.signals.length ? React.createElement("div", { className: "tagrow", style: { marginTop: 9 } }, v.signals.map((s, j) => React.createElement(SignalTag, { key: j, id: s }))) : React.createElement("div", { className: "row gap6", style: { marginTop: 9, fontSize: 11.5, color: "var(--allow)" } }, React.createElement(Icon, { name: "check", size: 13 }), "no signals fired"))))))) ) : null);
  }

  window.InspectorScreen = InspectorScreen;
})();
