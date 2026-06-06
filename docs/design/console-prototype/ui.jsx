/* global React, Icon */
// Shared UI primitives for Embargo. Exported to window.
(function () {
  const { useState, useEffect, useRef } = React;
  const E = window.EMBARGO;

  // ---- helpers ----
  function pkgFull(item) { return (item.scope ? item.scope + "/" : "") + item.name; }
  function fmtDur(s) {
    if (s == null) return "—";
    if (s <= 0) return "ready";
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    if (h >= 1) return h + "h " + String(m).padStart(2, "0") + "m";
    const sec = s % 60;
    return m + "m " + String(sec).padStart(2, "0") + "s";
  }
  function initials(userId) {
    const u = E.USERS[userId];
    if (!u) return "?";
    if (userId === "system") return "⚙";
    return u.name.split(" ").map((x) => x[0]).join("").slice(0, 2).toUpperCase();
  }

  // ---- Verdict badge ----
  function VerdictBadge({ v, size }) {
    const cls = v === "ALLOW" ? "badge-allow" : v === "HOLD" ? "badge-hold" : "badge-deny";
    return React.createElement("span", { className: "badge " + cls, style: size === "lg" ? { fontSize: 12, padding: "4px 11px" } : null },
      React.createElement("span", { className: "dot" }), v);
  }

  // ---- Signal tag ----
  function SignalTag({ id, w }) {
    const s = E.SIGNALS[id];
    if (!s) return null;
    return React.createElement("span", { className: "tag sev-" + s.sev, title: s.desc },
      React.createElement("span", { className: "tdot" }),
      s.label,
      w != null ? React.createElement("span", { style: { opacity: .55, marginLeft: 2 } }, "·" + w) : null
    );
  }

  // ---- Provenance status ----
  function Provenance({ status, withLabel }) {
    const map = {
      ok: { cls: "ok", icon: "check", label: "attested" },
      missing: { cls: "missing", icon: "alert", label: "missing" },
      partial: { cls: "partial", icon: "lock", label: "partial" },
    };
    const m = map[status] || map.missing;
    return React.createElement("span", { className: "prov " + m.cls },
      React.createElement(Icon, { name: m.icon, size: 13 }),
      withLabel === false ? null : React.createElement("span", null, m.label));
  }

  // ---- Live cooldown ----
  function Cooldown({ remaining, total }) {
    const [r, setR] = useState(remaining);
    useEffect(() => {
      setR(remaining);
      if (remaining == null) return;
      const t = setInterval(() => setR((x) => (x == null ? x : Math.max(0, x - 1))), 1000);
      return () => clearInterval(t);
    }, [remaining]);
    if (r == null) return React.createElement("span", { className: "faint mono", style: { fontSize: 11 } }, "—");
    const pct = total ? Math.max(2, Math.round(((total - r) / total) * 100)) : 0;
    return React.createElement("span", { className: "cooldown" },
      React.createElement("span", { className: "cd-bar" },
        React.createElement("span", { className: "cd-fill", style: { width: pct + "%" } })),
      React.createElement("span", { className: r <= 0 ? "" : "", style: { color: r <= 0 ? "var(--allow)" : "var(--hold)" } }, fmtDur(r)));
  }

  // ---- Weight bar (signal breakdown) ----
  function WeightBar({ w, max = 40, sev }) {
    const color = sev === "high" ? "var(--deny)" : sev === "med" ? "var(--hold)" : "var(--accent)";
    return React.createElement("span", { className: "sig-weight" },
      React.createElement("span", { className: "sig-wbar" },
        React.createElement("span", { className: "sig-wfill", style: { width: Math.round((w / max) * 100) + "%", background: color } })),
      React.createElement("span", { className: "sig-wval mono" }, "+" + w));
  }

  // ---- Score ring ----
  function ScoreRing({ score, verdict, size = 56 }) {
    const color = verdict === "DENY" ? "var(--deny)" : verdict === "HOLD" ? "var(--hold)" : "var(--allow)";
    const r = (size - 8) / 2, c = 2 * Math.PI * r;
    const off = c * (1 - score / 100);
    return React.createElement("div", { className: "score-ring", style: { width: size, height: size } },
      React.createElement("svg", { width: size, height: size },
        React.createElement("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--panel-3)", strokeWidth: 5 }),
        React.createElement("circle", {
          cx: size / 2, cy: size / 2, r, fill: "none", stroke: color, strokeWidth: 5,
          strokeLinecap: "round", strokeDasharray: c, strokeDashoffset: off,
          transform: "rotate(-90 " + size / 2 + " " + size / 2 + ")",
          style: { transition: "stroke-dashoffset .8s cubic-bezier(.2,.7,.3,1)" },
        })),
      React.createElement("span", { className: "sr-num", style: { color, fontSize: size > 50 ? 15 : 12 } }, score));
  }

  // ---- Sparkline ----
  function Sparkline({ data, color }) {
    const max = Math.max(...data, 1);
    return React.createElement("span", { className: "spark", style: { color } },
      data.map((d, i) => React.createElement("i", { key: i, style: { height: Math.max(2, (d / max) * 24) + "px" } })));
  }

  // ---- Drawer ----
  function Drawer({ open, onClose, children, width }) {
    useEffect(() => {
      function esc(e) { if (e.key === "Escape") onClose(); }
      if (open) window.addEventListener("keydown", esc);
      return () => window.removeEventListener("keydown", esc);
    }, [open, onClose]);
    return React.createElement(React.Fragment, null,
      React.createElement("div", { className: "drawer-scrim" + (open ? " open" : ""), onClick: onClose }),
      React.createElement("div", { className: "drawer" + (open ? " open" : ""), style: width ? { width } : null }, open ? children : null));
  }

  // ---- Modal ----
  function Modal({ open, onClose, children }) {
    useEffect(() => {
      function esc(e) { if (e.key === "Escape") onClose(); }
      if (open) window.addEventListener("keydown", esc);
      return () => window.removeEventListener("keydown", esc);
    }, [open, onClose]);
    return React.createElement("div", { className: "modal-scrim" + (open ? " open" : ""), onClick: onClose },
      React.createElement("div", { className: "modal", onClick: (e) => e.stopPropagation() }, open ? children : null));
  }

  // ---- Empty state ----
  function EmptyState({ icon = "check", title, body }) {
    return React.createElement("div", { className: "empty" },
      React.createElement("div", { className: "empty-ico" }, React.createElement(Icon, { name: icon, size: 26 })),
      React.createElement("h3", null, title),
      React.createElement("p", null, body));
  }

  // ---- Skeleton table ----
  function SkeletonTable({ rows = 8, cols = 6 }) {
    return React.createElement("div", { className: "tbl-wrap" },
      React.createElement("table", { className: "tbl" },
        React.createElement("tbody", null,
          Array.from({ length: rows }).map((_, r) =>
            React.createElement("tr", { key: r, style: { cursor: "default" } },
              Array.from({ length: cols }).map((_, c) =>
                React.createElement("td", { key: c },
                  React.createElement("div", { className: "skel skel-line", style: { width: (c === 0 ? 70 : 40 + ((r * 7 + c * 13) % 45)) + "%" } }))))))));
  }

  // ---- Avatar ----
  function Avatar({ userId, sm }) {
    const u = E.USERS[userId] || { color: "#5b6478" };
    return React.createElement("span", { className: sm ? "avatar-sm" : "avatar", style: { background: u.color === "#5b6478" ? "var(--panel-3)" : "linear-gradient(135deg," + u.color + ",rgba(0,0,0,.3))" } }, initials(userId));
  }

  // ---- localStorage hook ----
  function useStored(key, initial) {
    const [v, setV] = useState(() => {
      try { const s = localStorage.getItem(key); return s != null ? JSON.parse(s) : initial; } catch (e) { return initial; }
    });
    useEffect(() => { try { localStorage.setItem(key, JSON.stringify(v)); } catch (e) {} }, [key, v]);
    return [v, setV];
  }

  Object.assign(window, {
    VerdictBadge, SignalTag, Provenance, Cooldown, WeightBar, ScoreRing,
    Sparkline, Drawer, Modal, EmptyState, SkeletonTable, Avatar, useStored,
    pkgFull, fmtDur, initials,
  });
})();
