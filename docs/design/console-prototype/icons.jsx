/* global React */
// Minimal functional line-icon set. <Icon name="..." /> — inherits currentColor.
(function () {
  const P = {
    dashboard: "M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z",
    shield:    "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z",
    queue:     "M4 6h16M4 12h16M4 18h10",
    policy:    "M5 3h9l5 5v13H5zM14 3v5h5M8 13h8M8 17h5",
    approvals: "M9 12l2 2 4-4M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    inspector: "M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-5-5",
    audit:     "M8 4h9l3 3v13H6V4zM8 9h6M8 13h8M8 17h5",
    search:    "M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-5-5",
    filter:    "M3 5h18l-7 8v6l-4 2v-8z",
    chevdown:  "M6 9l6 6 6-6",
    chevright: "M9 6l6 6-6 6",
    close:     "M6 6l12 12M18 6L6 18",
    check:     "M5 12l4 4 10-10",
    x:         "M6 6l12 12M18 6L6 18",
    bolt:      "M13 2L4 14h7l-1 8 9-12h-7z",
    clock:     "M12 7v5l3 2M12 3a9 9 0 100 18 9 9 0 000-18z",
    alert:     "M12 9v4m0 4h.01M10.3 4.3L2.5 18a2 2 0 001.7 3h15.6a2 2 0 001.7-3L13.7 4.3a2 2 0 00-3.4 0z",
    lock:      "M6 10V8a6 6 0 1112 0v2M5 10h14v11H5zM12 15v3",
    unlock:    "M7 10V8a5 5 0 019.6-2M5 10h14v11H5zM12 15v3",
    box:       "M21 8l-9-5-9 5 9 5zM3 8v8l9 5 9-5V8M12 13v8",
    network:   "M12 7a2 2 0 100-4 2 2 0 000 4zM5 21a2 2 0 100-4 2 2 0 000 4zM19 21a2 2 0 100-4 2 2 0 000 4zM12 7v4M12 11l-6 6M12 11l6 6",
    download:  "M12 3v12m0 0l-4-4m4 4l4-4M5 21h14",
    plus:      "M12 5v14M5 12h14",
    dot3:      "M5 12h.01M12 12h.01M19 12h.01",
    pulse:     "M3 12h4l2-7 4 14 2-7h6",
    git:       "M6 3v12a3 3 0 003 3h0a3 3 0 003-3V9a3 3 0 013-3M6 3a2 2 0 100 4 2 2 0 000-4zM18 6a2 2 0 100-4 2 2 0 000 4zM9 21a2 2 0 100-4 2 2 0 000 4z",
    file:      "M7 3h8l4 4v14H7zM14 3v5h5",
    diff:      "M5 7h8M9 3v8M5 17h12M5 21h12",
    fingerprint: "M12 4a8 8 0 00-8 8M20 12a8 8 0 00-3-6.2M8 20a8 8 0 01-1-8 5 5 0 0110 0c0 2-1 4-1 4M12 12v3a3 3 0 01-1 2",
    history:   "M3 12a9 9 0 109-9 9 9 0 00-7 3.3M3 4v3.3h3.3M12 8v4l3 2",
    cog:       "M12 9a3 3 0 100 6 3 3 0 000-6zM19 12l2-1-1-3-2 .5a7 7 0 00-1.3-1.3L17 4l-3-1-1 2a7 7 0 00-1.8 0L10 3 7 4l.3 2.2A7 7 0 006 7.5L4 7 3 10l2 1a7 7 0 000 1.8L3 14l1 3 2.2-.3a7 7 0 001.3 1.3L7 20l3 1 1-2a7 7 0 001.8 0l1 2 3-1-.3-2.2a7 7 0 001.3-1.3L20 17l1-3z",
    layers:    "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5",
    flask:     "M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3",
    arrowup:   "M12 19V5M5 12l7-7 7 7",
    arrowdown: "M12 5v14M5 12l7 7 7-7",
    play:      "M6 4l14 8-14 8z",
    eye:       "M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z M12 9a3 3 0 100 6 3 3 0 000-6z",
    package2:  "M3 8l9-5 9 5v8l-9 5-9-5zM3 8l9 5 9-5M12 13v8",
  };

  function Icon({ name, size = 16, stroke = 1.7, fill = false, style, className }) {
    const d = P[name] || P.dot3;
    return React.createElement("svg", {
      width: size, height: size, viewBox: "0 0 24 24",
      fill: fill ? "currentColor" : "none",
      stroke: fill ? "none" : "currentColor",
      strokeWidth: stroke, strokeLinecap: "round", strokeLinejoin: "round",
      style, className,
    }, React.createElement("path", { d }));
  }

  window.Icon = Icon;
})();
