/* global React, Icon, Avatar */
(function () {
  const { useState, useMemo } = React;
  const E = window.EMBARGO;

  const ACTION_STYLE = {
    VERDICT_DENY: { color: "var(--deny)", icon: "x" },
    VERDICT_ALLOW: { color: "var(--allow)", icon: "check" },
    VERDICT_HOLD: { color: "var(--hold)", icon: "clock" },
    OVERRIDE_FASTTRACK: { color: "var(--hold)", icon: "bolt" },
    OVERRIDE_REQUEST: { color: "var(--text-dim)", icon: "unlock" },
    EXCEPTION_GRANT: { color: "var(--accent-2)", icon: "shield" },
    POLICY_UPDATE: { color: "var(--accent-2)", icon: "policy" },
    POLICY_EVAL: { color: "var(--text-dim)", icon: "pulse" },
    CONTAINMENT: { color: "var(--deny)", icon: "shield" },
  };

  function csvEscape(s) { return '"' + String(s).replace(/"/g, '""') + '"'; }

  function AuditScreen() {
    const [filter, setFilter] = useState("ALL");
    const actions = useMemo(() => Array.from(new Set(E.AUDIT.map((a) => a.action))), []);
    const rows = filter === "ALL" ? E.AUDIT : E.AUDIT.filter((a) => a.action === filter);

    function exportCsv() {
      const head = ["timestamp", "actor", "role", "action", "target", "detail", "entry_hash"];
      const lines = [head.join(",")].concat(rows.map((r) => [r.ts, r.actor, r.role, r.action, r.target, r.detail, r.hash].map(csvEscape).join(",")));
      const blob = new Blob([lines.join("\n")], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "embargo-audit-" + new Date().toISOString().slice(0, 10) + ".csv";
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      window.embargoToast && window.embargoToast("Exported " + rows.length + " audit entries to CSV", "allow");
    }

    return React.createElement("div", { className: "content-pad" },
      React.createElement("div", { className: "page-head" },
        React.createElement("div", null,
          React.createElement("h1", null, "Audit Log"),
          React.createElement("div", { className: "sub row gap8" },
            React.createElement("span", { className: "row gap6", style: { color: "var(--allow)" } }, React.createElement(Icon, { name: "lock", size: 13 }), "Immutable · hash-chained"),
            React.createElement("span", { className: "faint" }, "·"),
            React.createElement("span", null, "every verdict, override, and policy change"))),
        React.createElement("div", { className: "grow" }),
        React.createElement("button", { className: "btn btn-sm btn-primary", onClick: exportCsv }, React.createElement(Icon, { name: "download", size: 14 }), "Export CSV")),

      React.createElement("div", { className: "toolbar" },
        React.createElement("div", { className: "select", onClick: () => {}, style: { cursor: "default" } },
          React.createElement(Icon, { name: "filter", size: 13 }),
          React.createElement("span", { className: "lbl" }, "Action"),
          React.createElement("select", { value: filter, onChange: (e) => setFilter(e.target.value), style: { background: "none", border: "none", color: "var(--text)", fontFamily: "var(--sans)", fontSize: 12, outline: "none", cursor: "pointer" } },
            React.createElement("option", { value: "ALL" }, "all actions"),
            actions.map((a) => React.createElement("option", { key: a, value: a }, a)))),
        React.createElement("div", { className: "grow" }),
        React.createElement("span", { className: "cell-sub" }, "showing " + rows.length + " of " + E.AUDIT.length + " entries")),

      React.createElement("div", { className: "tbl-wrap" },
        React.createElement("table", { className: "tbl" },
          React.createElement("thead", null, React.createElement("tr", null,
            React.createElement("th", { style: { width: 165 } }, "Timestamp (UTC)"),
            React.createElement("th", { style: { width: 150 } }, "Actor"),
            React.createElement("th", { style: { width: 175 } }, "Action"),
            React.createElement("th", null, "Target"),
            React.createElement("th", null, "Detail"),
            React.createElement("th", { style: { width: 120 } }, "Entry hash"))),
          React.createElement("tbody", null, rows.map((r, i) => {
            const st = ACTION_STYLE[r.action] || { color: "var(--text-dim)", icon: "dot3" };
            return React.createElement("tr", { key: i, className: "audit-row", style: { cursor: "default" } },
              React.createElement("td", null, React.createElement("span", { className: "mono", style: { fontSize: 11 } }, r.ts)),
              React.createElement("td", null, React.createElement("span", { className: "actor" }, React.createElement(Avatar, { userId: r.actor, sm: true }), React.createElement("span", { style: { fontFamily: "var(--sans)", fontSize: 12 } }, r.actor))),
              React.createElement("td", null, React.createElement("span", { className: "audit-action", style: { color: st.color } }, React.createElement(Icon, { name: st.icon, size: 13 }), React.createElement("span", { style: { fontSize: 11 } }, r.action))),
              React.createElement("td", null, React.createElement("span", { className: "mono", style: { fontSize: 11.5, color: "var(--text)" } }, r.target)),
              React.createElement("td", null, React.createElement("span", { style: { fontFamily: "var(--sans)", fontSize: 12, color: "var(--text-2)" } }, r.detail)),
              React.createElement("td", null, React.createElement("span", { className: "row gap6 hashcell" }, React.createElement(Icon, { name: "lock", size: 11, style: { opacity: .6 } }), r.hash)));
          })))),
      React.createElement("div", { className: "row gap8", style: { marginTop: 12, fontSize: 11, color: "var(--text-faint)" } },
        React.createElement(Icon, { name: "fingerprint", size: 14 }),
        React.createElement("span", null, "Each entry hash chains the previous — tampering breaks the chain. Verified through ", React.createElement("span", { className: "mono", style: { color: "var(--allow)" } }, E.AUDIT[0].hash), ".")));
  }

  window.AuditScreen = AuditScreen;
})();
