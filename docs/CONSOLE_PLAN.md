# Console Implementation Plan

Implementation plan for the **Embargo Console** — the web admin UI (`/console` per the repo
layout). This is the handoff plan from the design-review session; the build itself is intended to
be carried out in a follow-up (Sonnet) session. Read this top to bottom before starting.

> Part of the wider build plan. See `docs/PROJECT_PLAN.md` for how the console fits with the engine,
> gateway, policy, admission, and sandbox components, and `docs/plans/` for those sub-plans. The
> console reads/writes the engine's admin API (`docs/plans/engine.md`); its `data/api.ts` stub seam
> is the swap point for that integration.

## 0. Source of truth

The design was delivered as a Claude Design handoff bundle. Its files are committed verbatim in
this repo as the **pixel-perfect reference** — port from them, do not re-invent:

```
docs/design/console-prototype/
  Embargo Console.html        # HTML shell: load order of scripts, fonts, root mount
  styles.css                  # THE visual system — port this nearly verbatim (see §3)
  data.jsx                    # mock dataset → window.EMBARGO (source for typed data layer, §5)
  icons.jsx                   # line-icon set (name → SVG path) — port as <Icon/> (§4)
  ui.jsx                      # shared primitives (badges, drawer, modal, score ring, etc.)
  app.jsx                     # app shell: sidebar, topbar, routing, role switch, toasts
  screen_quarantine.jsx       # HERO screen — table + drawer + action modals
  screen_dashboard.jsx        # stat cards + stacked-area chart + top-held + containment
  screen_policy.jsx           # most-specific-wins rules + dry-run impact preview
  screen_approvals.jsx        # active/pending/expired tabs
  screen_inspector.jsx        # package search + version timeline
  screen_audit.jsx            # hash-chained log + CSV export
  tweaks-panel.jsx            # design-tool scaffold (see §7 — adapt, don't copy wholesale)
  screenshots/*.png           # visual ground truth for each screen
  DESIGN-CHAT.md              # the design conversation — WHERE THE INTENT LIVES, read it
  HANDOFF-README.md           # the design tool's notes to the implementing agent
```

The prototype is an in-browser React 18 (UMD) + Babel-standalone app: each `.jsx` file hangs its
components off `window`, and `data.jsx` defines `window.EMBARGO`. We are **not** keeping that
delivery mechanism — we are rebuilding it as a real Vite + React + TypeScript app — but the
component structure, CSS, and data shapes all carry over directly.

## 1. Decisions (locked with the user)

- **Stack:** Vite + React 18 + TypeScript (strict), living in `/console`. Matches `CLAUDE.md`
  ("Console — React + TS"). ESLint + Prettier clean before commit (project convention).
- **Data:** Mock dataset ported to a typed module, **behind a typed data-access layer with stubbed
  async fetch functions** so wiring to the future Rust engine/gateway API is a drop-in later. No
  backend exists yet (engine/gateway are not built); the console is a self-contained frontend demo.
- **Scope:** Build all six screens. Quarantine Queue is the hero (richest interactions).
- **Aesthetic (fixed by the design):** cool blue-slate dark, IBM Plex Sans + Mono, three-state
  verdict color system everywhere, azure accent. Do not introduce new colors/fonts.

## 2. Target directory structure

```
/console
  index.html                 # Vite entry; loads IBM Plex fonts (preconnect + css2 link)
  package.json
  tsconfig.json              # strict: true
  vite.config.ts
  .eslintrc.cjs  .prettierrc
  src/
    main.tsx                 # ReactDOM.createRoot → <App/>
    App.tsx                  # shell: layout grid, sidebar, topbar, routing, role/density/state
    styles/
      global.css             # ported from prototype styles.css (verbatim; see §3)
    types.ts                 # all domain types (Verdict, Signal, QueueItem, Policy, ...) §5
    data/
      mock.ts                # the demo dataset, typed (port of data.jsx)
      api.ts                 # data-access layer: async stubs returning mock data (§5)
      hooks.ts               # useQueue(), useDashboard(), ... thin wrappers w/ loading state
    lib/
      format.ts              # fmtDur, pkgFull, initials, csvEscape (port of ui.jsx helpers)
      useStored.ts           # localStorage-backed state hook
    components/
      Icon.tsx               # name→path icon (port of icons.jsx)
      VerdictBadge.tsx  SignalTag.tsx  Provenance.tsx  Cooldown.tsx
      WeightBar.tsx  ScoreRing.tsx  Sparkline.tsx
      Drawer.tsx  Modal.tsx  EmptyState.tsx  SkeletonTable.tsx  Avatar.tsx
      Toast.tsx              # toast host + a useToast() context (replaces window.embargoToast)
      RoleSwitch.tsx  Sidebar.tsx  Topbar.tsx
      DemoControls.tsx       # role/density/data-state panel (replaces tweaks-panel, §7)
    screens/
      Dashboard.tsx  Quarantine.tsx  Policy.tsx
      Approvals.tsx  Inspector.tsx  Audit.tsx
```

## 3. Visual system (`styles.css` → `global.css`)

Port `docs/design/console-prototype/styles.css` **almost verbatim** into
`console/src/styles/global.css`. It is the entire design system and is already correct. Key points:

- Keep the full `:root` token block (canvas, ink, verdict, accent, severity, radii, shadows, fonts,
  `--sidebar-w`, `--topbar-h`, `--row-h`). Do **not** restyle to a CSS-in-JS system; the prototype's
  class-based CSS is the contract.
- Keep verdict colors exact: `--allow:#46c46a`, `--hold:#e7b53d`, `--deny:#f0564e`,
  `--accent:#4d8dff`.
- Density is driven by `[data-density="compact"]` on the app root — keep that selector approach.
- **Animation gotcha (from the design chat):** entrance animations are deliberately
  **transform-only** (no `opacity:0` keyframe starts) so content stays visible even when the tab is
  backgrounded or `prefers-reduced-motion` is set. The chart fills are static, only the stroke
  `draw` animates. Preserve this — do not "fix" it back to opacity fades.
- `index.html` must keep the font loading: `preconnect` to fonts.gstatic + the
  `IBM+Plex+Sans:wght@400;450;500;550;600;700` and `IBM+Plex+Mono:wght@400;500;600` `css2` link.
- A handful of inline styles live in the JSX (mostly one-off layout). Port them as inline `style={}`
  objects or promote to classes — match the rendered result, that's what matters.

## 4. Components / primitives (`ui.jsx` + `icons.jsx`)

Convert each `window.*` primitive into a typed function component. Direct mapping:

| Prototype (`ui.jsx`) | New component | Notes |
|---|---|---|
| `Icon` (icons.jsx) | `Icon.tsx` | `name: IconName` union, `size`, `stroke`, `fill`. Port the `P` path map verbatim. |
| `VerdictBadge` | `VerdictBadge.tsx` | `v: Verdict`, optional `size:"lg"`. |
| `SignalTag` | `SignalTag.tsx` | looks up `SIGNALS[id]`, severity class, `title` tooltip, optional weight. |
| `Provenance` | `Provenance.tsx` | status ∈ ok/missing/partial; icon + label. |
| `Cooldown` | `Cooldown.tsx` | **live ticking** via `setInterval` 1s; bar fill = `(total-r)/total`. Keep the timer + cleanup. |
| `WeightBar` | `WeightBar.tsx` | width = `w/max`; color by severity. |
| `ScoreRing` | `ScoreRing.tsx` | SVG ring, `strokeDashoffset` transition; color by verdict. |
| `Sparkline` | `Sparkline.tsx` | bar heights normalized to max. |
| `Drawer` | `Drawer.tsx` | scrim + slide-in; Esc closes; `open` prop; render children only when open. |
| `Modal` | `Modal.tsx` | scrim + scale-in; Esc + scrim-click close; stopPropagation on inner. |
| `EmptyState` / `SkeletonTable` | same | as-is. |
| `Avatar` | `Avatar.tsx` | gradient by user color; `initials()`; `sm` variant. |
| `useStored` | `lib/useStored.ts` | localStorage-backed `useState`. |
| `pkgFull/fmtDur/initials` | `lib/format.ts` | pure helpers. |

`window.embargoToast` → replace with a `ToastProvider` + `useToast()` hook (context), same 3.6s
auto-dismiss, same three kinds (allow/hold/deny) and left-border colors.

## 5. Types + data layer

### 5a. `types.ts`
Derive types from `data.jsx` shapes. At minimum:

```ts
type Verdict = "ALLOW" | "HOLD" | "DENY";
type Severity = "high" | "med" | "low";
type Provenance = "ok" | "missing" | "partial";
type Role = "viewer" | "approver" | "admin";

interface SignalDef { label: string; sev: Severity; desc: string }
interface QueueSignal { id: string; w: number }
interface DiffEntry { t: "add"|"del"|"mod"; path: string; size: string; flag?: string; note?: string }
interface Requester { repo: string; pipeline: string; count: number }
interface Advisory { id: string; title: string; severity: string; range: string }
interface QueueItem {
  id: string; scope: string | null; name: string; version: string;
  verdict: Verdict; score: number; reason: string; signals: QueueSignal[];
  cooldownRemaining: number | null; cooldownTotal: number | null;
  provenance: Provenance; firstSeen: string; firstSeenAbs: string;
  registry: string; publisher: string; unpacked: string; files: number;
  prevVersion: string; requesters: Requester[]; diff: DiffEntry[]; advisory: Advisory | null;
}
// + Dashboard, Policy, DryRun, Approval, InspectorPackage, AuditEntry, User
```
(Full shapes are all present in `data.jsx` — transcribe each.)

### 5b. `data/mock.ts`
Port the entire `window.EMBARGO` object (SIGNALS, QUEUE, DASHBOARD, POLICIES, DRYRUN, APPROVALS,
INSPECTOR, AUDIT, USERS) as typed constants. Keep the `series()` generator for the dashboard
sparkline/trend data. Keep all the realistic dummy data exactly (axios, chalk, node-ipc,
event-stream, @mycompany/*, GHSA ids, etc.) — it's what makes the demo read as real.

### 5c. `data/api.ts` (the stubbed access layer)
Wrap every dataset behind an async function that today resolves the mock, tomorrow hits the engine:

```ts
const LATENCY = 180; // ms, simulates the brief route-entry loading state
const delay = <T>(v: T) => new Promise<T>(r => setTimeout(() => r(v), LATENCY));
export const api = {
  getQueue: () => delay(mock.QUEUE),
  getDashboard: () => delay(mock.DASHBOARD),
  getPolicies: () => delay(mock.POLICIES),
  getDryRun: () => delay(mock.DRYRUN),
  getApprovals: () => delay(mock.APPROVALS),
  inspectPackage: (key: string) => delay(mock.INSPECTOR[key] ?? null),
  getAudit: () => delay(mock.AUDIT),
  // mutations are local-only for now (resolve optimistically):
  decideQueueItem: (id, action, opts) => delay({ id, action, ...opts }),
  decideApproval: (id, action) => delay({ id, action }),
};
```
`data/hooks.ts` exposes `useQueue()` etc. that call these and surface `{data, loading}` so screens
get a real loading state. This is the seam that makes the future API swap a one-file change.

## 6. Screens (behaviors to preserve)

Each screen is a near-direct port; the interaction details below are the parts that must survive.

1. **Quarantine Queue** (`screen_quarantine.jsx` → `Quarantine.tsx`) — the hero.
   - Toolbar: verdict segmented filter (All/Held/Denied with live counts), Signal / Scope / Window
     filter dropdowns, name search.
   - Sortable table (pkg / verdict / score), sticky header, row → opens **detail drawer**.
   - Drawer: score ring + risk score + reason, **weighted signal breakdown** (icon by severity,
     description, weight bar, weighted total), **tarball diff** (add/del/mod rows, `danger` highlight
     for flagged entries like INSTALL SCRIPT / NATIVE BUILD / NETWORK / OBFUSCATED), provenance &
     SLSA level KV, security advisory block (when present), requesters list.
   - Footer actions Approve / Deny / Fast-track, **role-gated** (approve/deny = approver+admin,
     fast-track = admin only; otherwise show locked disabled button).
   - Action modals: Approve & Fast-track require justification + expiry; Deny shows an impact
     warning (counts pending install attempts) and needs no justification. Confirming removes the
     row from the queue and fires a toast.
   - Data states: `loading` → SkeletonTable; empty/filtered-empty → EmptyState ("Queue clear —
     nothing held" vs "No matches").

2. **Dashboard** (`screen_dashboard.jsx`).
   - Four stat cards (Held / Denied / Allowed / Pending approvals) with verdict colors, sparkline,
     delta vs prior 24h; Held/Denied/Pending cards navigate to their screens on click.
   - **Stacked-area trend chart** (24h, allowed/held/denied) hand-built in SVG — port the band/line
     path math exactly; gradients + animated stroke draw, static fills.
   - Top-held packages bar list; full-width **containment events** feed (blocked install-time
     egress) with the per-event icon/host/pipeline detail.
   - Loading variant: skeleton stat cards + skeleton table.

3. **Policy Editor** (`screen_policy.jsx`).
   - Left: rules in **most-specific-wins order** (sorted by specificity desc), with `#n` rank,
     specificity dots, cooldown/provenance/disabled meta. Right: rule settings form (scope glob,
     cooldown hours, advisory/typosquat action, require-provenance + enabled toggles, fast-track
     allow-list chips) + collapsible **Dry-run impact preview** (would-allow/hold/deny counts with
     diff chips + per-package verdict-change list). Edit controls are admin-only (read-only note
     otherwise).

4. **Approvals & Exceptions** (`screen_approvals.jsx`).
   - Active / Pending / Expired tabs with counts. Table: package, type badge (fast-track /
     exception / override), requester avatar, justification, approver, expiry countdown (or
     "Requested" for pending). Pending rows get Grant/Reject for approver+admin (locked note for
     viewer). Deciding moves the row + fires a toast. Expiry coloring via `expiryInfo()` relative to
     the fixed "now" (2026-06-07T11:20Z).

5. **Package Inspector** (`screen_inspector.jsx`).
   - Search box (filters INSPECTOR keys), package header (latest, weekly downloads, repo,
     maintainers), **version timeline** (vertical, dot colored by verdict) with per-version
     provenance, pull origin (pipeline), fired signals (or "no signals fired"), and an `exception`
     badge where applicable.

6. **Audit Log** (`screen_audit.jsx`).
   - Action filter `<select>`, immutable hash-chained table (timestamp, actor avatar, action w/
     colored icon, target, detail, entry hash). **Working CSV export** (Blob download) + a
     hash-chain footer note. Keep the "Immutable · hash-chained" framing — this is the compliance
     surface.

## 7. App shell + cross-cutting (`app.jsx` → `App.tsx`)

- **Layout:** CSS grid `var(--sidebar-w) 1fr`. Sidebar (brand mark, Operations/Governance nav
  groups with counts + a "hot" amber count on Quarantine, footer health line). Topbar (title +
  breadcrumb, env pill `prod-registry`, ⌘K search field, RoleSwitch with avatar).
- **Routing:** keep simple hash routing (`#dashboard` … `#audit`) + `useStored("embargo.route")`,
  syncing `document.title`. No router library needed. Default route = `quarantine` (the hero).
- **Role / density / data-state:** in the prototype these come from the design tool's Tweaks panel.
  Replace with an in-app **DemoControls** panel (small floating panel or a topbar menu) exposing:
  Role (viewer/approver/admin, default **admin**), Density (comfortable/compact), Data state
  (populated/loading/empty). The topbar RoleSwitch and DemoControls must stay in sync (single source
  of truth in `App` state, persisted via `useStored`). **Do not port `tweaks-panel.jsx` verbatim** —
  it speaks a postMessage protocol to the design host that doesn't exist here; reimplement just the
  three controls with the same defaults.
- **Route-entry loading:** brief (~180–420ms) loading state on route change when data-state is
  `populated`, so skeletons are visible — mirror the prototype's `entering` behavior (and let the
  api-layer latency drive it).
- **Toasts:** ToastProvider at the root.

## 8. Tooling / project setup

- `npm create vite@latest console -- --template react-ts` (or hand-write the equivalent).
- `tsconfig.json` strict mode on. No `any` without a `// reason` comment (project convention).
- Add ESLint + Prettier; ensure `npm run lint` and `npm run build` are clean before commit.
- **Update `CLAUDE.md`** "Build / test / run" Console line once scripts exist, e.g.
  `cd console && npm ci && npm run dev` (already stubbed there) and add `npm run build` / `npm run lint`.
- Conventional Commits, scope `console`, e.g. `feat(console): scaffold Vite React TS app shell`.

## 9. Suggested build order (for the implementer)

1. Scaffold Vite+TS app in `/console`; wire `index.html` fonts + mount; drop in `global.css`.
2. `types.ts` + `data/mock.ts` (typed dataset) + `data/api.ts` + `data/hooks.ts`.
3. `lib/` helpers + `Icon.tsx` + all primitives in `components/` (§4).
4. App shell: `Sidebar`, `Topbar`, `RoleSwitch`, routing, `ToastProvider`, `DemoControls`.
5. Screens, hero first: **Quarantine** (table → drawer → modals → role gating → toasts), then
   Dashboard, Policy, Approvals, Inspector, Audit.
6. Pass over states: loading skeletons, empty states, role-gated disabled controls; verify against
   `screenshots/`.
7. `npm run build` + `npm run lint` clean; update `CLAUDE.md`; commit.

## 10. Fidelity checklist (verify against `screenshots/`)

- [ ] Verdict colors exact and used consistently (badges, scores, chart, timeline dots).
- [ ] IBM Plex Mono on all technical values (package names, versions, hashes, paths); Sans on chrome.
- [ ] Dense tables, sticky headers, hover + selected row states.
- [ ] Drawer slides; modals scale-in; Esc + scrim close.
- [ ] Live cooldown timers tick; score rings animate; chart stroke draws (fills static).
- [ ] Role switch gates actions (viewer read-only; approver approve/deny; admin adds fast-track).
- [ ] Density toggle reflows row heights/padding; data-state simulator shows loading/empty.
- [ ] Audit CSV actually downloads.

## 11. Out of scope (this pass)

- Real backend / engine / gateway integration (only the `api.ts` seam is stubbed for it).
- Auth / SSO / real RBAC (role switcher is a demo control).
- Persistence of actions across reload beyond what `useStored` covers (actions are optimistic/local).
- Docker/Helm packaging of the console.
