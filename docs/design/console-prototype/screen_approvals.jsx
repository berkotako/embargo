/* global React, Icon, Avatar, EmptyState */
(function () {
  const { useState, useMemo } = React;
  const E = window.EMBARGO;

  const TYPE = {
    "fast-track": { label: "Fast-track", cls: "badge-hold", icon: "bolt" },
    "exception":  { label: "Exception", cls: "badge-accent", icon: "shield" },
    "override":   { label: "Override", cls: "badge-neutral", icon: "unlock" },
  };

  function expiryInfo(exp) {
    if (!exp) return null;
    // exp like "2026-06-08 09:12Z"
    const now = new Date("2026-06-07T11:20:00Z");
    const d = new Date(exp.replace(" ", "T").replace("Z", "Z"));
    const diff = (d - now) / 36e5;
    if (diff <= 0) return { text: "expired", danger: true };
    if (diff < 24) return { text: "in " + Math.round(diff) + "h", warn: diff < 6 };
    return { text: "in " + Math.round(diff / 24) + "d" };
  }

  function ApprovalsScreen({ role }) {
    const [tab, setTab] = useState("active");
    const canAct = role === "approver" || role === "admin";
    const [decided, setDecided] = useState({});

    const counts = useMemo(() => ({
      active: E.APPROVALS.filter((a) => a.status === "active").length,
      pending: E.APPROVALS.filter((a) => a.status === "pending").length,
      expired: E.APPROVALS.filter((a) => a.status === "expired").length,
    }), []);

    const rows = E.APPROVALS.filter((a) => (decided[a.id] || a.status) === tab);

    function decide(id, action) {
      setDecided((d) => ({ ...d, [id]: action === "grant" ? "active" : "expired" }));
      const a = E.APPROVALS.find((x) => x.id === id);
      window.embargoToast && window.embargoToast((action === "grant" ? "Granted exception for " : "Rejected request for ") + a.pkg, action === "grant" ? "allow" : "deny");
    }

    return React.createElement("div", { className: "content-pad" },
      React.createElement("div", { className: "page-head" },
        React.createElement("div", null,
          React.createElement("h1", null, "Approvals & Exceptions"),
          React.createElement("div", { className: "sub" }, "Time-boxed overrides to policy — every grant carries an expiry")),
        React.createElement("div", { className: "grow" }),
        React.createElement("button", { className: "btn btn-sm" }, React.createElement(Icon, { name: "download", size: 14 }), "Export")),

      React.createElement("div", { className: "toolbar" },
        React.createElement("div", { className: "seg" },
          React.createElement("button", { className: tab === "active" ? "on" : "", onClick: () => setTab("active") }, React.createElement("span", { className: "tdot", style: { width: 6, height: 6, borderRadius: "50%", background: "var(--allow)", display: "inline-block" } }), " Active ", React.createElement("span", { className: "cnt" }, counts.active)),
          React.createElement("button", { className: tab === "pending" ? "on" : "", onClick: () => setTab("pending") }, "Pending ", React.createElement("span", { className: "cnt" }, counts.pending)),
          React.createElement("button", { className: tab === "expired" ? "on" : "", onClick: () => setTab("expired") }, "Expired ", React.createElement("span", { className: "cnt" }, counts.expired)))),

      rows.length === 0
        ? React.createElement("div", { className: "tbl-wrap" }, React.createElement(EmptyState, { icon: tab === "pending" ? "check" : "history", title: tab === "pending" ? "No pending requests" : "Nothing here", body: tab === "pending" ? "All override requests have been actioned." : "No " + tab + " exceptions in this view." }))
        : React.createElement("div", { className: "tbl-wrap" },
            React.createElement("table", { className: "tbl" },
              React.createElement("thead", null, React.createElement("tr", null,
                React.createElement("th", { style: { width: "20%" } }, "Package"),
                React.createElement("th", null, "Type"),
                React.createElement("th", null, "Requested by"),
                React.createElement("th", null, "Justification"),
                React.createElement("th", null, "Approver"),
                React.createElement("th", null, tab === "pending" ? "Requested" : "Expiry"),
                tab === "pending" && canAct ? React.createElement("th", { style: { width: 140 } }, "") : null)),
              React.createElement("tbody", { className: "stagger" }, rows.map((a) => {
                const t = TYPE[a.type];
                const exp = expiryInfo(a.expiry);
                return React.createElement("tr", { key: a.id, style: { cursor: "default" } },
                  React.createElement("td", null, React.createElement("span", { className: "mono", style: { fontSize: 12.5 } }, a.pkg)),
                  React.createElement("td", null, React.createElement("span", { className: "badge " + t.cls }, React.createElement(Icon, { name: t.icon, size: 11 }), t.label)),
                  React.createElement("td", null, React.createElement("span", { className: "actor" }, React.createElement(Avatar, { userId: a.by, sm: true }), React.createElement("span", null, (E.USERS[a.by] || {}).name || a.by))),
                  React.createElement("td", { style: { maxWidth: 280 } }, React.createElement("span", { style: { fontSize: 12, color: "var(--text-2)" } }, a.justification)),
                  React.createElement("td", null, a.approver ? React.createElement("span", { className: "actor" }, React.createElement(Avatar, { userId: a.approver, sm: true }), React.createElement("span", null, (E.USERS[a.approver] || {}).name || a.approver)) : React.createElement("span", { className: "faint mono", style: { fontSize: 11 } }, "—")),
                  React.createElement("td", null,
                    tab === "pending"
                      ? React.createElement("span", { className: "cell-sub" }, "just now")
                      : a.expiry
                        ? React.createElement("span", { className: "row gap8", style: { fontSize: 11.5 } },
                            React.createElement("span", { className: "mono faint" }, a.expiry.slice(5, 16)),
                            exp ? React.createElement("span", { className: "tag " + (exp.danger ? "sev-low" : exp.warn ? "sev-med" : ""), style: { fontSize: 10 } }, React.createElement(Icon, { name: "clock", size: 10 }), exp.text) : null)
                        : React.createElement("span", { className: "faint" }, "—")),
                  tab === "pending" && canAct ? React.createElement("td", null,
                    React.createElement("div", { className: "row gap6" },
                      React.createElement("button", { className: "btn btn-sm btn-allow", onClick: () => decide(a.id, "grant") }, "Grant"),
                      React.createElement("button", { className: "btn btn-sm btn-ghost", onClick: () => decide(a.id, "reject") }, "Reject"))) : (tab === "pending" ? React.createElement("td", null, React.createElement("span", { className: "role-note" }, React.createElement(Icon, { name: "lock", size: 12 }), "approver only")) : null));
              })))));
  }

  window.ApprovalsScreen = ApprovalsScreen;
})();
