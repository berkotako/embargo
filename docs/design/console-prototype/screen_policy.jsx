/* global React, Icon */
(function () {
  const { useState } = React;
  const E = window.EMBARGO;

  function Spec({ level }) {
    return React.createElement("span", { className: "specificity", title: "Specificity " + level + "/4" },
      [1, 2, 3, 4].map((i) => React.createElement("i", { key: i, className: i <= level ? "on" : "" })));
  }

  function Switch({ on, onChange }) {
    return React.createElement("div", { className: "switch" + (on ? " on" : ""), onClick: () => onChange(!on), role: "switch", "aria-checked": on });
  }

  function DryRun() {
    const d = E.DRYRUN;
    const dHeld = d.after.held - d.before.held;
    const dDeny = d.after.denied - d.before.denied;
    return React.createElement("div", { className: "dryrun" },
      React.createElement("div", { className: "row between" },
        React.createElement("div", { className: "row gap8" },
          React.createElement("span", { style: { color: "var(--accent-2)", display: "inline-flex" } }, React.createElement(Icon, { name: "flask", size: 16 })),
          React.createElement("b", { style: { fontSize: 13 } }, "Dry run"),
          React.createElement("span", { className: "dim", style: { fontSize: 11.5 } }, "replays " + d.evaluated.toLocaleString() + " resolutions from " + d.window)),
        React.createElement("span", { className: "badge badge-accent" }, "draft not saved")),
      React.createElement("div", { className: "dryrun-stat" },
        React.createElement("div", { className: "drs" }, React.createElement("div", { className: "drs-num", style: { color: "var(--allow)" } }, d.after.allowed.toLocaleString()), React.createElement("div", { className: "drs-lbl" }, "would allow"), React.createElement("span", { className: "diffchip down" }, d.after.allowed - d.before.allowed)),
        React.createElement("div", { className: "drs" }, React.createElement("div", { className: "drs-num", style: { color: "var(--hold)" } }, d.after.held), React.createElement("div", { className: "drs-lbl" }, "would hold"), React.createElement("span", { className: "diffchip up" }, "+" + dHeld)),
        React.createElement("div", { className: "drs" }, React.createElement("div", { className: "drs-num", style: { color: "var(--deny)" } }, d.after.denied), React.createElement("div", { className: "drs-lbl" }, "would deny"), React.createElement("span", { className: "diffchip up" }, "+" + dDeny))),
      React.createElement("div", { style: { fontSize: 11, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".6px", margin: "4px 0 8px" } }, "Verdict changes vs. live policy"),
      React.createElement("div", { className: "diff" },
        d.changes.map((c, i) =>
          React.createElement("div", { key: i, className: "diff-row", style: { padding: "7px 11px" } },
            React.createElement("span", { className: "mono", style: { flex: 1, fontSize: 11.5 } }, c.pkg),
            React.createElement("span", { className: "badge badge-" + (c.was === "ALLOW" ? "allow" : c.was === "HOLD" ? "hold" : "deny"), style: { fontSize: 9 } }, c.was),
            React.createElement(Icon, { name: "chevright", size: 13, style: { color: "var(--text-faint)", margin: "0 2px" } }),
            React.createElement("span", { className: "badge badge-" + (c.now === "ALLOW" ? "allow" : c.now === "HOLD" ? "hold" : "deny"), style: { fontSize: 9 } }, c.now),
            React.createElement("span", { className: "dim", style: { flex: 1.4, fontSize: 10.5, textAlign: "right", fontFamily: "var(--sans)" } }, c.why)))));
  }

  function PolicyEditor({ role }) {
    const canEdit = role === "admin";
    const sorted = [...E.POLICIES].sort((a, b) => b.specificity - a.specificity);
    const [selId, setSelId] = useState(sorted[0].id);
    const base = sorted.find((p) => p.id === selId);
    const [draft, setDraft] = useState(base);
    const [showDry, setShowDry] = useState(true);

    React.useEffect(() => { setDraft(base); }, [selId]);

    function up(k, v) { setDraft((d) => ({ ...d, [k]: v })); }

    return React.createElement("div", { className: "content-pad" },
      React.createElement("div", { className: "page-head" },
        React.createElement("div", null,
          React.createElement("h1", null, "Policy Editor"),
          React.createElement("div", { className: "sub" }, "Rules resolve most-specific-wins · the first matching scope decides the verdict")),
        React.createElement("div", { className: "grow" }),
        canEdit ? React.createElement(React.Fragment, null,
          React.createElement("button", { className: "btn btn-sm" }, React.createElement(Icon, { name: "plus", size: 14 }), "New rule"),
          React.createElement("button", { className: "btn btn-sm btn-primary" }, React.createElement(Icon, { name: "check", size: 14 }), "Save policy"))
          : React.createElement("span", { className: "role-note" }, React.createElement(Icon, { name: "lock", size: 13 }), "Read-only — admin role required to edit")),

      React.createElement("div", { className: "policy-layout" },
        // rule list
        React.createElement("div", { className: "panel" },
          React.createElement("div", { className: "panel-head" }, React.createElement("h2", null, "Resolution order"), React.createElement("span", { className: "ph-sub" }, "specific → broad")),
          React.createElement("div", null, sorted.map((p, i) =>
            React.createElement("div", { key: p.id, className: "rule-item" + (p.id === selId ? " active" : ""), onClick: () => setSelId(p.id) },
              React.createElement("div", { className: "rule-spec mono" }, "#" + (i + 1)),
              React.createElement("div", { className: "rule-scope" }, p.scope.length > 26 ? p.scope.slice(0, 26) + "…" : p.scope),
              React.createElement("div", { className: "rule-meta" },
                React.createElement(Spec, { level: p.specificity }),
                React.createElement("span", null, p.cooldownHours === 0 ? "no cooldown" : p.cooldownHours + "h cooldown"),
                p.requireProvenance ? React.createElement("span", { style: { color: "var(--allow)" } }, "prov required") : null,
                !p.enabled ? React.createElement("span", { style: { color: "var(--text-faint)" } }, "disabled") : null))))),

        // editor
        React.createElement("div", { className: "col gap14" },
          React.createElement("div", { className: "panel" },
            React.createElement("div", { className: "panel-head" },
              React.createElement("h2", null, "Rule settings"),
              React.createElement("div", { className: "grow" }),
              React.createElement("span", { className: "cell-sub" }, "edited " + base.edited + " · " + base.author)),
            React.createElement("div", { className: "panel-body col gap16" },
              React.createElement("div", { className: "form-grid" },
                React.createElement("div", { className: "form-row", style: { gridColumn: "1/-1" } },
                  React.createElement("label", null, "Scope pattern"),
                  React.createElement("input", { className: "field mono", value: draft.scope, disabled: !canEdit, onChange: (e) => up("scope", e.target.value) }),
                  React.createElement("span", { className: "hint" }, "Glob over package names. ", React.createElement("span", { className: "mono" }, "@scope/*"), " matches one segment, ", React.createElement("span", { className: "mono" }, "**"), " matches all.")),
                React.createElement("div", { className: "form-row" },
                  React.createElement("label", null, "Cooldown (hours)"),
                  React.createElement("input", { className: "field mono", type: "number", value: draft.cooldownHours, disabled: !canEdit, onChange: (e) => up("cooldownHours", +e.target.value) }),
                  React.createElement("span", { className: "hint" }, "Hold new versions until this age. 0 = allow immediately.")),
                React.createElement("div", { className: "form-row" },
                  React.createElement("label", null, "On advisory / typosquat"),
                  React.createElement("select", { className: "field", disabled: !canEdit, defaultValue: "deny" },
                    React.createElement("option", { value: "deny" }, "Deny immediately"),
                    React.createElement("option", { value: "hold" }, "Hold for review")),
                  React.createElement("span", { className: "hint" }, "Hard signals override the cooldown.")))
              ,
              React.createElement("div", null,
                React.createElement("div", { className: "toggle-row" },
                  React.createElement("div", null, React.createElement("div", { className: "tr-label" }, "Require provenance"), React.createElement("div", { className: "tr-sub" }, "Deny versions without a verified SLSA build attestation")),
                  React.createElement(Switch, { on: draft.requireProvenance, onChange: (v) => canEdit && up("requireProvenance", v) })),
                React.createElement("div", { className: "toggle-row" },
                  React.createElement("div", null, React.createElement("div", { className: "tr-label" }, "Rule enabled"), React.createElement("div", { className: "tr-sub" }, "Disabled rules are skipped during resolution")),
                  React.createElement(Switch, { on: draft.enabled, onChange: (v) => canEdit && up("enabled", v) }))),
              React.createElement("div", { className: "form-row" },
                React.createElement("label", null, "Fast-track allow-list"),
                React.createElement("div", { className: "row wrap gap6", style: { minHeight: 30 } },
                  draft.fastTrack.length ? draft.fastTrack.map((f, i) =>
                    React.createElement("span", { key: i, className: "tag", style: { fontSize: 11 } }, React.createElement(Icon, { name: "bolt", size: 11, style: { color: "var(--hold)" } }), f,
                      canEdit ? React.createElement("span", { style: { cursor: "pointer", opacity: .6 }, onClick: () => up("fastTrack", draft.fastTrack.filter((_, j) => j !== i)) }, "×") : null))
                    : React.createElement("span", { className: "faint", style: { fontSize: 11.5 } }, "No packages exempted"),
                  canEdit ? React.createElement("button", { className: "btn btn-sm btn-ghost" }, React.createElement(Icon, { name: "plus", size: 13 }), "Add") : null),
                React.createElement("span", { className: "hint" }, "These packages skip cooldown and provenance checks under this rule.")))),

          React.createElement("div", { className: "panel" },
            React.createElement("div", { className: "panel-head" },
              React.createElement("h2", null, "Impact preview"),
              React.createElement("div", { className: "grow" }),
              React.createElement("button", { className: "btn btn-sm", onClick: () => setShowDry(!showDry) }, React.createElement(Icon, { name: showDry ? "chevdown" : "chevright", size: 13 }), showDry ? "Hide" : "Run dry run")),
            showDry ? React.createElement("div", { className: "panel-body", style: { paddingTop: 6 } }, React.createElement(DryRun, null)) : null))));
  }

  window.PolicyEditor = PolicyEditor;
})();
