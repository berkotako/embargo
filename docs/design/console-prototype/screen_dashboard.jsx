/* global React, Icon, Sparkline, SkeletonTable */
(function () {
  const { useState, useEffect, useRef } = React;
  const E = window.EMBARGO;
  const D = E.DASHBOARD;

  // ---- Stacked area chart (24h: allowed / held / denied) ----
  function TrendChart() {
    const W = 760, H = 220, PADL = 38, PADB = 26, PADT = 14, PADR = 8;
    const n = 24;
    const allowed = D.trend.allowed, held = D.trend.held, denied = D.trend.denied;
    const stacks = allowed.map((a, i) => [a, a + held[i], a + held[i] + denied[i]]);
    const maxY = Math.max(...stacks.map((s) => s[2])) * 1.15;
    const x = (i) => PADL + (i / (n - 1)) * (W - PADL - PADR);
    const y = (v) => PADT + (1 - v / maxY) * (H - PADT - PADB);

    function band(getTop, getBot) {
      let top = "", bot = "";
      for (let i = 0; i < n; i++) { top += (i ? " L " : "M ") + x(i) + " " + y(getTop(i)); }
      for (let i = n - 1; i >= 0; i--) { bot += " L " + x(i) + " " + y(getBot(i)); }
      return top + bot + " Z";
    }
    function line(getTop) {
      let p = "";
      for (let i = 0; i < n; i++) p += (i ? " L " : "M ") + x(i) + " " + y(getTop(i));
      return p;
    }

    const aBand = band((i) => stacks[i][0], () => 0);
    const hBand = band((i) => stacks[i][1], (i) => stacks[i][0]);
    const dBand = band((i) => stacks[i][2], (i) => stacks[i][1]);

    const yTicks = 4;
    return React.createElement("div", { style: { padding: "6px 4px 0" } },
      React.createElement("svg", { viewBox: "0 0 " + W + " " + H, style: { width: "100%", height: "auto", display: "block" } },
        React.createElement("defs", null,
          grad("ga", "#46c46a"), grad("gh", "#e7b53d"), grad("gd", "#f0564e")),
        // gridlines
        Array.from({ length: yTicks + 1 }).map((_, t) => {
          const gv = (maxY / yTicks) * t;
          return React.createElement("g", { key: t },
            React.createElement("line", { x1: PADL, x2: W - PADR, y1: y(gv), y2: y(gv), stroke: "var(--border-soft)", strokeWidth: 1 }),
            React.createElement("text", { x: PADL - 8, y: y(gv) + 3, textAnchor: "end", fill: "var(--text-faint)", fontSize: 9, fontFamily: "var(--mono)" }, Math.round(gv)));
        }),
        // x labels every 4h
        Array.from({ length: 7 }).map((_, t) => {
          const i = t * 4; if (i >= n) return null;
          return React.createElement("text", { key: t, x: x(i), y: H - 8, textAnchor: "middle", fill: "var(--text-faint)", fontSize: 9, fontFamily: "var(--mono)" }, String(i).padStart(2, "0") + ":00");
        }),
        React.createElement("path", { d: aBand, fill: "url(#ga)", className: "bar-grow" }),
        React.createElement("path", { d: hBand, fill: "url(#gh)", className: "bar-grow" }),
        React.createElement("path", { d: dBand, fill: "url(#gd)", className: "bar-grow" }),
        React.createElement("path", { d: line((i) => stacks[i][0]), fill: "none", stroke: "#46c46a", strokeWidth: 1.5, opacity: .9, className: "chart-line-anim" }),
        React.createElement("path", { d: line((i) => stacks[i][1]), fill: "none", stroke: "#e7b53d", strokeWidth: 1.5, opacity: .9, className: "chart-line-anim" }),
        React.createElement("path", { d: line((i) => stacks[i][2]), fill: "none", stroke: "#f0564e", strokeWidth: 1.5, opacity: .9, className: "chart-line-anim" })));
  }
  function grad(id, color) {
    return React.createElement("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 1 },
      React.createElement("stop", { offset: "0%", stopColor: color, stopOpacity: .34 }),
      React.createElement("stop", { offset: "100%", stopColor: color, stopOpacity: .04 }));
  }

  function StatCard({ kind, label, value, delta, spark, onClick }) {
    const color = kind === "allow" ? "var(--allow)" : kind === "hold" ? "var(--hold)" : kind === "deny" ? "var(--deny)" : "var(--accent)";
    const up = delta > 0;
    return React.createElement("div", { className: "stat " + kind, onClick, style: onClick ? { cursor: "pointer" } : null },
      React.createElement("div", { className: "stat-top" },
        React.createElement("span", { className: "stat-label" }, label),
        React.createElement(Sparkline, { data: spark, color })),
      React.createElement("div", { className: "stat-num" }, value.toLocaleString()),
      React.createElement("div", { className: "stat-foot" },
        React.createElement("span", { className: up ? "trend-up" : "trend-down", style: { display: "inline-flex", alignItems: "center", gap: 3 } },
          React.createElement(Icon, { name: up ? "arrowup" : "arrowdown", size: 12 }),
          Math.abs(delta) + (kind === "allow" ? "%" : "")),
        React.createElement("span", { className: "faint" }, "vs prior 24h")));
  }

  function Dashboard({ dataState, onNav }) {
    if (dataState === "loading") {
      return React.createElement("div", { className: "content-pad" },
        React.createElement("div", { className: "page-head" }, React.createElement("div", null, React.createElement("h1", null, "Dashboard"))),
        React.createElement("div", { className: "stat-grid" }, Array.from({ length: 4 }).map((_, i) =>
          React.createElement("div", { key: i, className: "stat" }, React.createElement("div", { className: "skel skel-line", style: { width: "50%" } }), React.createElement("div", { className: "skel", style: { height: 34, width: "40%", margin: "10px 0" } }), React.createElement("div", { className: "skel skel-line", style: { width: "70%" } })))),
        React.createElement("div", { style: { marginTop: 14 } }, React.createElement(SkeletonTable, { rows: 6, cols: 3 })));
    }
    return React.createElement("div", { className: "content-pad" },
      React.createElement("div", { className: "page-head" },
        React.createElement("div", null,
          React.createElement("h1", null, "Dashboard"),
          React.createElement("div", { className: "sub" }, "Registry firewall posture · last 24 hours · ", React.createElement("span", { className: "mono" }, "prod-registry"))),
        React.createElement("div", { className: "grow" }),
        React.createElement("span", { className: "pill" }, React.createElement("span", { className: "health-dot" }), "All inspectors healthy")),

      React.createElement("div", { className: "stat-grid stagger" },
        React.createElement(StatCard, { kind: "hold", label: "Held · 24h", value: D.stats.held.value, delta: D.stats.held.delta, spark: D.stats.held.spark, onClick: () => onNav("quarantine") }),
        React.createElement(StatCard, { kind: "deny", label: "Denied · 24h", value: D.stats.denied.value, delta: D.stats.denied.delta, spark: D.stats.denied.spark, onClick: () => onNav("quarantine") }),
        React.createElement(StatCard, { kind: "allow", label: "Allowed · 24h", value: D.stats.allowed.value, delta: D.stats.allowed.delta, spark: D.stats.allowed.spark }),
        React.createElement(StatCard, { kind: "accent", label: "Pending approvals", value: D.pendingApprovals, delta: 2, spark: [2, 3, 3, 5, 4, 6, 7], onClick: () => onNav("approvals") })),

      React.createElement("div", { className: "dash-grid" },
        // trend chart
        React.createElement("div", { className: "panel" },
          React.createElement("div", { className: "panel-head" },
            React.createElement("h2", null, "Verdict volume"),
            React.createElement("span", { className: "ph-sub" }, "stacked, hourly"),
            React.createElement("div", { className: "grow" }),
            React.createElement("div", { className: "chart-legend" },
              React.createElement("span", { className: "lg" }, React.createElement("i", { style: { background: "var(--allow)" } }), "Allowed"),
              React.createElement("span", { className: "lg" }, React.createElement("i", { style: { background: "var(--hold)" } }), "Held"),
              React.createElement("span", { className: "lg" }, React.createElement("i", { style: { background: "var(--deny)" } }), "Denied"))),
          React.createElement("div", { className: "panel-body", style: { paddingTop: 8 } }, React.createElement(TrendChart, null))),

        // top held
        React.createElement("div", { className: "panel" },
          React.createElement("div", { className: "panel-head" }, React.createElement("h2", null, "Top held packages"), React.createElement("span", { className: "ph-sub" }, "by hold count")),
          React.createElement("div", { className: "panel-body" },
            React.createElement("div", { className: "barlist" },
              D.topHeld.map((p, i) => {
                const max = D.topHeld[0].count;
                return React.createElement("div", { key: i, className: "bl-row" },
                  React.createElement("div", { className: "bl-top", style: { gridColumn: "1/-1" } },
                    React.createElement("span", { className: "bl-name" }, p.name),
                    React.createElement("span", { className: "bl-val" }, p.count + " holds")),
                  React.createElement("div", { className: "bl-track" }, React.createElement("div", { className: "bl-fill", style: { width: (p.count / max) * 100 + "%" } })));
              })))))
        ,

      // containment events — full width
      React.createElement("div", { className: "panel", style: { marginTop: 14 } },
        React.createElement("div", { className: "panel-head" },
          React.createElement("span", { style: { color: "var(--deny)", display: "inline-flex" } }, React.createElement(Icon, { name: "shield", size: 16 })),
          React.createElement("h2", null, "Recent containment events"),
          React.createElement("span", { className: "ph-sub" }, "blocked install-time network egress"),
          React.createElement("div", { className: "grow" }),
          React.createElement("span", { className: "badge badge-deny" }, React.createElement("span", { className: "dot" }), D.containment.length + " contained")),
        React.createElement("div", { className: "panel-body", style: { paddingTop: 4, paddingBottom: 4 } },
          D.containment.map((c, i) =>
            React.createElement("div", { key: i, className: "evt" },
              React.createElement("span", { className: "evt-ico" }, React.createElement(Icon, { name: c.note ? "alert" : "network", size: 15 })),
              React.createElement("div", { className: "evt-body" },
                React.createElement("div", { className: "evt-title" },
                  "Blocked egress from ", React.createElement("b", null, c.pkg),
                  c.host !== "—" ? React.createElement(React.Fragment, null, " to ", React.createElement("b", { style: { color: "var(--deny)" } }, c.host)) : React.createElement("span", null, " — " + c.note)),
                React.createElement("div", { className: "evt-meta" }, c.repo + " · " + c.pipeline + " · " + c.attempts + " attempt" + (c.attempts > 1 ? "s" : "") + " · " + c.time)),
              React.createElement("span", { className: "tag", style: { alignSelf: "center" } }, React.createElement("span", { className: "tdot", style: { background: "var(--deny)" } }), "blocked"))))));
  }

  window.Dashboard = Dashboard;
})();
