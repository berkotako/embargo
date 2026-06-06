/* global React, Icon, VerdictBadge, SignalTag, Provenance, Cooldown, WeightBar, ScoreRing, Drawer, Modal, EmptyState, SkeletonTable, pkgFull, fmtDur */
(function () {
  const { useState, useMemo } = React;
  const E = window.EMBARGO;

  const can = {
    approve: (role) => role === "approver" || role === "admin",
    deny:    (role) => role === "approver" || role === "admin",
    fast:    (role) => role === "admin",
  };

  function PkgCell(item) {
    return React.createElement("span", { className: "cell-pkg" },
      item.scope ? React.createElement("span", { className: "scope" }, item.scope + "/") : null,
      React.createElement("span", null, item.name),
      React.createElement("span", { className: "ver" }, "@" + item.version));
  }

  // ---------- Action modal ----------
  function ActionModal({ mode, item, onClose, onConfirm }) {
    const [reason, setReason] = useState("");
    const [expiry, setExpiry] = useState("24h");
    if (!item) return null;
    const isDeny = mode === "deny";
    const isFast = mode === "fast";
    const title = isDeny ? "Deny package version" : isFast ? "Fast-track override" : "Approve package version";
    const titleIcon = isDeny ? "x" : isFast ? "bolt" : "check";
    const need = !isDeny; // approve & fast-track require justification
    return React.createElement(Modal, { open: !!mode, onClose },
      React.createElement("div", { className: "modal-head" },
        React.createElement("h3", null,
          React.createElement("span", { style: { color: isDeny ? "var(--deny)" : isFast ? "var(--hold)" : "var(--allow)" } },
            React.createElement(Icon, { name: titleIcon, size: 18 })),
          title)),
      React.createElement("div", { className: "modal-body" },
        React.createElement("div", { className: "modal-pkg" }, pkgFull(item) + "@" + item.version),
        isFast ? React.createElement("div", { className: "warn-banner warn", style: { marginTop: 12 } },
          React.createElement(Icon, { name: "alert", size: 16, style: { flex: "0 0 auto", marginTop: 1 } }),
          React.createElement("span", null, "Fast-track bypasses policy and lets this version into builds immediately. The action is logged with your identity and expires automatically.")) : null,
        isDeny ? React.createElement("div", { className: "warn-banner deny", style: { marginTop: 12 } },
          React.createElement(Icon, { name: "alert", size: 16, style: { flex: "0 0 auto", marginTop: 1 } }),
          React.createElement("span", null, "Denying blocks every pipeline requesting this version. ", React.createElement("b", null, item.requesters.reduce((a, r) => a + r.count, 0)), " pending install attempt(s) will fail.")) : null,
        need ? React.createElement(React.Fragment, null,
          React.createElement("label", null, "Justification ", React.createElement("span", { style: { color: "var(--deny)" } }, "*")),
          React.createElement("textarea", { className: "field", placeholder: "Why is this override safe? (linked incident, upstream PR, risk acceptance…)", value: reason, onChange: (e) => setReason(e.target.value), autoFocus: true }),
          React.createElement("label", null, "Expires after"),
          React.createElement("select", { className: "field", value: expiry, onChange: (e) => setExpiry(e.target.value) },
            ["4h", "24h", "72h", "7d", "14d", "30d"].map((x) => React.createElement("option", { key: x, value: x }, x)))
        ) : React.createElement(React.Fragment, null,
          React.createElement("label", null, "Reason (optional)"),
          React.createElement("textarea", { className: "field", placeholder: "Note for the audit log…", value: reason, onChange: (e) => setReason(e.target.value), autoFocus: true }))),
      React.createElement("div", { className: "modal-foot" },
        React.createElement("button", { className: "btn btn-ghost", onClick: onClose }, "Cancel"),
        React.createElement("button", {
          className: "btn " + (isDeny ? "btn-deny" : isFast ? "btn-warn" : "btn-allow"),
          disabled: need && !reason.trim(),
          onClick: () => onConfirm({ reason, expiry }),
        },
          React.createElement(Icon, { name: titleIcon, size: 15 }),
          isDeny ? "Confirm deny" : isFast ? "Fast-track now" : "Approve")));
  }

  // ---------- Detail drawer ----------
  function Detail({ item, role, onAction }) {
    if (!item) return null;
    const total = item.signals.reduce((a, s) => a + s.w, 0);
    return React.createElement(React.Fragment, null,
      React.createElement("div", { className: "drawer-head" },
        React.createElement("div", { className: "dh-top" },
          React.createElement("div", null,
            React.createElement("div", { className: "dh-pkg" },
              item.scope ? React.createElement("span", { className: "dim" }, item.scope + "/") : null,
              item.name, React.createElement("span", { className: "ver" }, "@" + item.version)),
            React.createElement("div", { className: "dh-meta" },
              React.createElement("span", null, "prev ", React.createElement("span", { className: "ver" }, item.prevVersion)),
              React.createElement("span", null, item.unpacked + " · " + item.files + " files"),
              React.createElement("span", null, "by " + item.publisher),
              React.createElement("span", null, "first seen " + item.firstSeen))),
          React.createElement(VerdictBadge, { v: item.verdict, size: "lg" }))),

      React.createElement("div", { className: "drawer-body" },
        // signal breakdown
        React.createElement("div", { className: "dsec" },
          React.createElement("div", { className: "dsec-title" }, "Signal breakdown", React.createElement("span", { className: "ds-line" })),
          React.createElement("div", { className: "score-summary" },
            React.createElement(ScoreRing, { score: item.score, verdict: item.verdict }),
            React.createElement("div", null,
              React.createElement("div", { style: { fontSize: 13 } }, React.createElement("b", null, "Risk score " + item.score), " / 100"),
              React.createElement("div", { className: "dim", style: { fontSize: 12, marginTop: 3 } }, item.reason)),
            item.verdict === "HOLD" ? React.createElement("div", { style: { marginLeft: "auto", textAlign: "right" } },
              React.createElement("div", { className: "dim", style: { fontSize: 10, textTransform: "uppercase", letterSpacing: ".6px" } }, "Cooldown"),
              React.createElement("div", { style: { marginTop: 5 } }, React.createElement(Cooldown, { remaining: item.cooldownRemaining, total: item.cooldownTotal }))) : null),
          item.signals.map((s, i) => {
            const sig = E.SIGNALS[s.id];
            return React.createElement("div", { className: "sig-row", key: i },
              React.createElement("div", null,
                React.createElement("div", { className: "sig-name" },
                  React.createElement("span", { className: "sig-ico", style: { background: sig.sev === "high" ? "rgba(240,86,78,.13)" : sig.sev === "med" ? "rgba(231,181,61,.13)" : "var(--panel-3)", color: sig.sev === "high" ? "var(--deny)" : sig.sev === "med" ? "var(--hold)" : "var(--text-dim)" } },
                    React.createElement(Icon, { name: sig.sev === "high" ? "alert" : sig.sev === "med" ? "pulse" : "clock", size: 14 })),
                  React.createElement("span", null, sig.label)),
                React.createElement("div", { className: "sig-desc", style: { marginLeft: 33 } }, sig.desc)),
              React.createElement(WeightBar, { w: s.w, sev: sig.sev }));
          }),
          React.createElement("div", { className: "row between", style: { marginTop: 10, fontSize: 12 } },
            React.createElement("span", { className: "dim" }, "Weighted total"),
            React.createElement("span", { className: "mono", style: { color: "var(--hold)" } }, "+" + total))),

        // tarball diff
        React.createElement("div", { className: "dsec" },
          React.createElement("div", { className: "dsec-title" }, "Tarball diff vs " + item.prevVersion, React.createElement("span", { className: "ds-line" })),
          React.createElement("div", { className: "diff" },
            item.diff.map((d, i) =>
              React.createElement("div", { key: i, className: "diff-row " + (d.flag ? "danger" : d.t === "add" ? "add" : d.t === "del" ? "del" : "") },
                React.createElement("span", { className: "diff-sign" }, d.t === "add" ? "+" : d.t === "del" ? "−" : "~"),
                React.createElement("span", { className: "diff-path" }, d.path),
                d.note ? React.createElement("span", { className: "diff-size", style: { fontSize: 10 } }, d.note) : null,
                d.flag ? React.createElement("span", { className: "diff-flag" }, d.flag) : null,
                React.createElement("span", { className: "diff-size" }, d.size)))))
          ,

        // provenance + advisory
        React.createElement("div", { className: "dsec" },
          React.createElement("div", { className: "dsec-title" }, "Provenance & attestation", React.createElement("span", { className: "ds-line" })),
          React.createElement("dl", { className: "kv" },
            React.createElement("dt", null, "Build attestation"), React.createElement("dd", null, React.createElement(Provenance, { status: item.provenance })),
            React.createElement("dt", null, "Source registry"), React.createElement("dd", null, item.registry),
            React.createElement("dt", null, "Publisher"), React.createElement("dd", null, item.publisher),
            React.createElement("dt", null, "SLSA level"), React.createElement("dd", null, item.provenance === "ok" ? "L3 (verified)" : item.provenance === "partial" ? "L1 (unverified)" : "none"))),

        item.advisory ? React.createElement("div", { className: "dsec" },
          React.createElement("div", { className: "dsec-title" }, "Security advisory", React.createElement("span", { className: "ds-line" })),
          React.createElement("div", { className: "advisory" },
            React.createElement("span", { className: "adv-ico" }, React.createElement(Icon, { name: "alert", size: 18 })),
            React.createElement("div", null,
              React.createElement("div", { className: "row gap8" },
                React.createElement("span", { className: "adv-id" }, item.advisory.id),
                React.createElement("span", { className: "badge badge-deny", style: { fontSize: 9 } }, item.advisory.severity)),
              React.createElement("div", { className: "adv-title" }, item.advisory.title),
              React.createElement("div", { className: "adv-desc mono", style: { marginTop: 4 } }, "affected " + item.advisory.range)))) : null,

        // requesters
        React.createElement("div", { className: "dsec", style: { borderBottom: "none" } },
          React.createElement("div", { className: "dsec-title" }, "Requested by", React.createElement("span", { className: "ds-line" })),
          item.requesters.map((r, i) =>
            React.createElement("div", { key: i, className: "req-row" },
              React.createElement("span", { className: "req-ico" }, React.createElement(Icon, { name: "git", size: 15 })),
              React.createElement("span", { className: "mono", style: { fontSize: 12 } }, r.repo),
              React.createElement("span", { className: "grow" }),
              React.createElement("span", { className: "cell-sub" }, r.pipeline),
              React.createElement("span", { className: "tag", style: { fontSize: 10 } }, r.count + "×"))))),

      // footer actions
      React.createElement("div", { className: "drawer-foot" },
        can.approve(role)
          ? React.createElement("button", { className: "btn btn-allow grow", onClick: () => onAction("approve") }, React.createElement(Icon, { name: "check", size: 15 }), "Approve")
          : React.createElement("button", { className: "btn grow disabled", title: "Requires approver role" }, React.createElement(Icon, { name: "lock", size: 14 }), "Approve"),
        can.deny(role)
          ? React.createElement("button", { className: "btn btn-deny grow", onClick: () => onAction("deny") }, React.createElement(Icon, { name: "x", size: 15 }), "Deny")
          : React.createElement("button", { className: "btn grow disabled", title: "Requires approver role" }, React.createElement(Icon, { name: "lock", size: 14 }), "Deny"),
        can.fast(role)
          ? React.createElement("button", { className: "btn btn-warn grow", onClick: () => onAction("fast") }, React.createElement(Icon, { name: "bolt", size: 15 }), "Fast-track")
          : React.createElement("button", { className: "btn grow disabled", title: "Requires admin role" }, React.createElement(Icon, { name: "lock", size: 14 }), "Fast-track")));
  }

  // ---------- Main screen ----------
  function QuarantineScreen({ role, dataState }) {
    const [verdict, setVerdict] = useState("ALL");
    const [signalF, setSignalF] = useState("ALL");
    const [scopeF, setScopeF] = useState("ALL");
    const [timeF, setTimeF] = useState("24h");
    const [q, setQ] = useState("");
    const [sort, setSort] = useState({ key: "score", dir: "desc" });
    const [selId, setSelId] = useState(null);
    const [resolved, setResolved] = useState({}); // id -> verdict applied
    const [modal, setModal] = useState(null); // {mode, item}
    const [openMenu, setOpenMenu] = useState(null);

    const rows = useMemo(() => {
      let r = E.QUEUE.filter((x) => !resolved[x.id]);
      if (verdict !== "ALL") r = r.filter((x) => x.verdict === verdict);
      if (signalF !== "ALL") r = r.filter((x) => x.signals.some((s) => s.id === signalF));
      if (scopeF === "internal") r = r.filter((x) => x.scope === "@mycompany");
      else if (scopeF === "public") r = r.filter((x) => !x.scope || x.scope !== "@mycompany");
      if (q.trim()) { const k = q.toLowerCase(); r = r.filter((x) => (pkgFull(x) + "@" + x.version).toLowerCase().includes(k)); }
      r = [...r].sort((a, b) => {
        let d = 0;
        if (sort.key === "score") d = a.score - b.score;
        else if (sort.key === "pkg") d = pkgFull(a).localeCompare(pkgFull(b));
        else if (sort.key === "verdict") d = a.verdict.localeCompare(b.verdict);
        return sort.dir === "asc" ? d : -d;
      });
      return r;
    }, [verdict, signalF, scopeF, q, sort, resolved]);

    const counts = useMemo(() => {
      const live = E.QUEUE.filter((x) => !resolved[x.id]);
      return { all: live.length, HOLD: live.filter((x) => x.verdict === "HOLD").length, DENY: live.filter((x) => x.verdict === "DENY").length };
    }, [resolved]);

    const sel = E.QUEUE.find((x) => x.id === selId) || null;

    function doSort(key) { setSort((s) => ({ key, dir: s.key === key && s.dir === "desc" ? "asc" : "desc" })); }
    function sortInd(key) { return sort.key === key ? React.createElement("span", { className: "sort-ind" }, sort.dir === "desc" ? "↓" : "↑") : null; }

    function applyAction({ reason, expiry }) {
      const it = modal.item, mode = modal.mode;
      const verd = mode === "deny" ? "denied" : mode === "fast" ? "fast-tracked" : "approved";
      setResolved((r) => ({ ...r, [it.id]: verd }));
      setModal(null); setSelId(null);
      window.embargoToast && window.embargoToast(
        (mode === "deny" ? "Denied " : mode === "fast" ? "Fast-tracked " : "Approved ") + pkgFull(it) + "@" + it.version,
        mode === "deny" ? "deny" : mode === "fast" ? "hold" : "allow");
    }

    const signalOpts = Object.keys(E.SIGNALS);

    return React.createElement("div", { className: "content-pad" },
      React.createElement("div", { className: "page-head" },
        React.createElement("div", null,
          React.createElement("h1", null, "Quarantine Queue"),
          React.createElement("div", { className: "sub" }, "Package versions held or denied awaiting operator review")),
        React.createElement("div", { className: "grow" }),
        React.createElement("button", { className: "btn btn-sm" }, React.createElement(Icon, { name: "download", size: 14 }), "Export")),

      // toolbar
      React.createElement("div", { className: "toolbar" },
        React.createElement("div", { className: "seg" },
          React.createElement("button", { className: verdict === "ALL" ? "on" : "", onClick: () => setVerdict("ALL") }, "All ", React.createElement("span", { className: "cnt" }, counts.all)),
          React.createElement("button", { className: "hold " + (verdict === "HOLD" ? "on" : ""), onClick: () => setVerdict("HOLD") }, "Held ", React.createElement("span", { className: "cnt" }, counts.HOLD)),
          React.createElement("button", { className: "deny " + (verdict === "DENY" ? "on" : ""), onClick: () => setVerdict("DENY") }, "Denied ", React.createElement("span", { className: "cnt" }, counts.DENY))),

        React.createElement(FilterSelect, { label: "Signal", value: signalF, onChange: setSignalF,
          options: [["ALL", "any signal"]].concat(signalOpts.map((k) => [k, E.SIGNALS[k].label])), open: openMenu === "sig", setOpen: (o) => setOpenMenu(o ? "sig" : null) }),
        React.createElement(FilterSelect, { label: "Scope", value: scopeF, onChange: setScopeF,
          options: [["ALL", "all scopes"], ["internal", "@mycompany/*"], ["public", "public registry"]], open: openMenu === "scope", setOpen: (o) => setOpenMenu(o ? "scope" : null) }),
        React.createElement(FilterSelect, { label: "Window", value: timeF, onChange: setTimeF,
          options: [["1h", "last hour"], ["24h", "last 24h"], ["7d", "last 7 days"], ["30d", "last 30 days"]], open: openMenu === "time", setOpen: (o) => setOpenMenu(o ? "time" : null) }),

        React.createElement("div", { className: "grow" }),
        React.createElement("div", { className: "filter-input" },
          React.createElement(Icon, { name: "search", size: 14 }),
          React.createElement("input", { placeholder: "filter by name…", value: q, onChange: (e) => setQ(e.target.value) }))),

      dataState === "loading"
        ? React.createElement(SkeletonTable, { rows: 9, cols: 7 })
        : rows.length === 0
          ? React.createElement("div", { className: "tbl-wrap" }, React.createElement(EmptyState, {
              icon: "shield",
              title: dataState === "empty" || counts.all === 0 ? "Queue clear — nothing held" : "No matches",
              body: dataState === "empty" || counts.all === 0
                ? "Every package version evaluated in this window passed policy. New holds and denials will appear here in real time."
                : "No held or denied versions match the current filters. Try widening the verdict, signal, or scope filters." }))
          : React.createElement(React.Fragment, null,
              React.createElement("div", { className: "tbl-meta" },
                React.createElement("span", null, React.createElement("b", null, rows.length), " of ", counts.all, " in queue"),
                React.createElement("span", { className: "faint" }, "·"),
                React.createElement("span", null, "sorted by ", sort.key === "pkg" ? "name" : sort.key, " ", sort.dir)),
              React.createElement("div", { className: "tbl-wrap" },
                React.createElement("table", { className: "tbl" },
                  React.createElement("thead", null, React.createElement("tr", null,
                    React.createElement("th", { className: "sortable", onClick: () => doSort("pkg"), style: { width: "21%" } }, "Package", sortInd("pkg")),
                    React.createElement("th", { className: "sortable", onClick: () => doSort("verdict") }, "Verdict", sortInd("verdict")),
                    React.createElement("th", null, "Reason"),
                    React.createElement("th", null, "Signals"),
                    React.createElement("th", { className: "sortable", onClick: () => doSort("score"), style: { width: 70 } }, "Score", sortInd("score")),
                    React.createElement("th", { style: { width: 120 } }, "Cooldown"),
                    React.createElement("th", { style: { width: 90 } }, "Provenance"))),
                  React.createElement("tbody", { className: "stagger" }, rows.map((item) =>
                    React.createElement("tr", { key: item.id, className: selId === item.id ? "sel" : "", onClick: () => setSelId(item.id) },
                      React.createElement("td", null, PkgCell(item)),
                      React.createElement("td", null, React.createElement(VerdictBadge, { v: item.verdict })),
                      React.createElement("td", { style: { maxWidth: 240 } }, React.createElement("span", { style: { fontSize: 12, color: "var(--text-2)" } }, item.reason)),
                      React.createElement("td", null, React.createElement("div", { className: "tagrow" },
                        item.signals.slice(0, 2).map((s, i) => React.createElement(SignalTag, { key: i, id: s.id })),
                        item.signals.length > 2 ? React.createElement("span", { className: "tag", style: { fontSize: 10 } }, "+" + (item.signals.length - 2)) : null)),
                      React.createElement("td", null, React.createElement("span", { className: "mono", style: { color: item.verdict === "DENY" ? "var(--deny)" : item.verdict === "HOLD" ? "var(--hold)" : "var(--allow)", fontSize: 13 } }, item.score)),
                      React.createElement("td", null, item.verdict === "HOLD" ? React.createElement(Cooldown, { remaining: item.cooldownRemaining, total: item.cooldownTotal }) : React.createElement("span", { className: "faint mono", style: { fontSize: 11 } }, "n/a")),
                      React.createElement("td", null, React.createElement(Provenance, { status: item.provenance, withLabel: false })))))))),

      React.createElement(Drawer, { open: !!sel, onClose: () => setSelId(null) },
        React.createElement(Detail, { item: sel, role, onAction: (mode) => setModal({ mode, item: sel }) })),

      modal ? React.createElement(ActionModal, { mode: modal.mode, item: modal.item, onClose: () => setModal(null), onConfirm: applyAction }) : null);
  }

  // Filter select dropdown
  function FilterSelect({ label, value, onChange, options, open, setOpen }) {
    const cur = options.find((o) => o[0] === value);
    return React.createElement("div", { className: "select", onClick: () => setOpen(!open), style: { position: "relative" } },
      React.createElement(Icon, { name: "filter", size: 13 }),
      React.createElement("span", { className: "lbl" }, label),
      React.createElement("span", { className: "val" }, cur ? cur[1] : value),
      React.createElement(Icon, { name: "chevdown", size: 13 }),
      open ? React.createElement("div", { className: "menu", style: { left: 0, right: "auto", minWidth: 200, maxHeight: 320, overflowY: "auto" }, onClick: (e) => e.stopPropagation() },
        options.map((o) => React.createElement("div", { key: o[0], className: "menu-item" + (o[0] === value ? " sel" : ""), onClick: () => { onChange(o[0]); setOpen(false); } },
          React.createElement("span", null, o[1]), o[0] === value ? React.createElement(Icon, { name: "check", size: 14 }) : null))) : null);
  }

  window.QuarantineScreen = QuarantineScreen;
})();
