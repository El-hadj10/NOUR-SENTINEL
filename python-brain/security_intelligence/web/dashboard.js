"use strict";

/* Le jeton arrive dans le fragment (#t=…), reste dans la mémoire de l'onglet et
   est envoyé en en-tête : jamais dans l'URL d'une requête, jamais journalisé. */
const TOKEN = (() => {
  const match = /(?:^|[#&])t=([^&]+)/.exec(window.location.hash || "");
  const stored = window.sessionStorage.getItem("nour-token");
  const token = match ? decodeURIComponent(match[1]) : stored;

  if (token) {
    window.sessionStorage.setItem("nour-token", token);
  }

  if (match) {
    window.history.replaceState(null, "", window.location.pathname);
  }

  return token;
})();

const OPTIONS = [
  { id: "inventory", label: "Inventaire local", hint: "OS, paquets, services, sockets — aucun réseau" },
  { id: "full-local", label: "Audit local complet", hint: "Inventaire, SSH/PAM, journald, Docker" },
  { id: "discover", label: "Voisins ARP", hint: "Lecture passive, aucune sonde" },
  { id: "scan", label: "Sondes bornées", hint: "Une IPv4 ARP choisie, 32 ports max" },
  { id: "fingerprint", label: "Empreinte de service", hint: "Une bannière SSH ou un HEAD HTTP" },
  { id: "tls", label: "Audit TLS", hint: "Négociation 1.2/1.3 et certificat" },
  { id: "cve", label: "Recherche CVE", hint: "OSV/KEV/EPSS, appel externe explicite" },
];

const FIELDS = {
  inventory: [],
  "full-local": [],
  discover: [],
  scan: ["target", "protocol", "profile", "confirm"],
  fingerprint: ["target", "port", "protocol", "profile"],
  tls: ["target", "port", "profile"],
  cve: ["package", "version"],
};

const PROTOCOLS = {
  scan: [
    ["both", "TCP + UDP"],
    ["tcp", "TCP"],
    ["udp", "UDP"],
  ],
  fingerprint: [
    ["http", "HTTP (HEAD)"],
    ["ssh", "SSH (bannière)"],
  ],
};

const state = {
  meta: null,
  selected: null,
  busy: false,
  lastReport: null,
  waves: { history: [], pulses: [] },
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);

  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;

  return node;
}

function setStatus(kind, text) {
  $("dot").className = `dot ${kind}`;
  $("status-text").textContent = text;
}

async function api(path, options = {}) {
  const headers = Object.assign({ "X-Nour-Token": TOKEN || "" }, options.headers || {});
  const response = await fetch(path, Object.assign({}, options, { headers }));

  if (response.status === 401) {
    throw new Error("jeton de session refusé : relancez ./lancer-nour-sentinel.sh --intel dashboard");
  }

  return response;
}

/* ---------------- ondes ---------------- */

const canvas = $("waves");
const context = canvas.getContext("2d");

function drawWave(values, hue, baseline, amplitude, time) {
  if (values.length < 2) return;

  const width = canvas.clientWidth;
  const step = width / (values.length - 1);
  const points = values.map((value, index) => {
    const idle = 0.045 * Math.sin(index / 5 + time / 900);
    return [index * step, baseline - (value + idle) * amplitude];
  });

  context.beginPath();
  context.moveTo(points[0][0], points[0][1]);

  for (let index = 1; index < points.length; index += 1) {
    const previous = points[index - 1];
    const current = points[index];
    const middle = (previous[0] + current[0]) / 2;
    context.quadraticCurveTo(previous[0], previous[1], middle, (previous[1] + current[1]) / 2);
  }

  const stroke = context.createLinearGradient(0, 0, width, 0);
  stroke.addColorStop(0, `hsla(${hue}, 100%, 68%, 0.25)`);
  stroke.addColorStop(0.5, `hsla(${hue}, 100%, 72%, 1)`);
  stroke.addColorStop(1, `hsla(${(hue + 90) % 360}, 100%, 70%, 0.3)`);

  context.strokeStyle = stroke;
  context.lineWidth = 2.2;
  context.shadowColor = `hsla(${hue}, 100%, 65%, 0.85)`;
  context.shadowBlur = 16;
  context.stroke();
  context.shadowBlur = 0;

  const fill = context.createLinearGradient(0, baseline - amplitude, 0, baseline + amplitude * 1.4);
  fill.addColorStop(0, `hsla(${hue}, 100%, 65%, 0.22)`);
  fill.addColorStop(1, "hsla(0, 0%, 0%, 0)");
  context.fillStyle = fill;
  context.lineTo(points[points.length - 1][0], baseline + amplitude);
  context.lineTo(points[0][0], baseline + amplitude);
  context.closePath();
  context.fill();
}

function drawFrame(time) {
  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(canvas.clientWidth, 320);
  const height = Math.max(canvas.clientHeight, 160);

  if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(height * dpr)) {
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
  }

  context.setTransform(dpr, 0, 0, dpr, 0, 0);
  context.clearRect(0, 0, width, height);

  context.strokeStyle = "rgba(255, 255, 255, 0.05)";
  context.lineWidth = 1;

  for (let row = 1; row < 4; row += 1) {
    const y = (height / 4) * row;
    context.beginPath();
    context.moveTo(0, y);
    context.lineTo(width, y);
    context.stroke();
  }

  const history = state.waves.history.slice(-160);
  const peak = Math.max(1, ...history.map((sample) => Math.max(sample.rx, sample.tx)));
  const hue = (time / 45) % 360;

  drawWave(history.map((s) => s.rx / peak), hue, height * 0.5, height * 0.34, time);
  drawWave(history.map((s) => s.tx / peak), (hue + 150) % 360, height * 0.5, height * 0.26, time);
  drawPulses(time, width, height);

  requestAnimationFrame(drawFrame);
}

function drawPulses(time, width, height) {
  state.waves.pulses = state.waves.pulses.filter((stamp) => time - stamp < 2600);

  state.waves.pulses.forEach((stamp) => {
    const progress = (time - stamp) / 2600;
    const radius = 18 + progress * Math.min(width, height) * 0.55;
    context.beginPath();
    context.arc(width / 2, height * 0.5, radius, 0, Math.PI * 2);
    context.strokeStyle = `hsla(${(180 + progress * 140) % 360}, 100%, 70%, ${0.5 * (1 - progress)})`;
    context.lineWidth = 2;
    context.stroke();
  });
}

function formatRate(value) {
  if (value >= 1048576) return `${(value / 1048576).toFixed(1)} M`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} k`;
  return Math.round(value).toString();
}

async function pollWaves() {
  try {
    const response = await api("/api/waves");

    if (!response.ok) return;

    const sample = await response.json();
    state.waves.history = sample.history || [];

    $("rx").textContent = formatRate(sample.rx_bps);
    $("tx").textContent = formatRate(sample.tx_bps);
    $("pps").textContent = Math.round((sample.rx_pps || 0) + (sample.tx_pps || 0)).toString();

    const ifaces = $("ifaces");
    ifaces.replaceChildren();

    /* Triées par trafic réel : sinon les interfaces virtuelles (docker, veth,
       bridges) occupent les premières places et masquent celle qui bouge. */
    const active = (sample.interfaces || [])
      .filter((item) => item.name !== "lo" && item.rx_bps + item.tx_bps > 0)
      .sort((left, right) => right.rx_bps + right.tx_bps - (left.rx_bps + left.tx_bps))
      .slice(0, 6);

    active.forEach((item) => {
      const chip = el("span", "iface");
      chip.append(
        el("b", null, item.name),
        ` ↓${formatRate(item.rx_bps)} ↑${formatRate(item.tx_bps)}`,
      );
      ifaces.append(chip);
    });

    if (!active.length) {
      ifaces.append(el("span", "iface idle-note", "aucune interface active hors boucle locale"));
    }

    if (!sample.available) {
      setStatus("err", "compteurs réseau illisibles (/proc/net/dev)");
    }
  } catch (error) {
    setStatus("err", error.message);
  }
}

/* ---------------- rapport ---------------- */

function formatValue(value) {
  if (value === null || value === undefined) return "—";

  if (typeof value === "object") {
    const parts = Array.isArray(value)
      ? value.map(formatValue)
      : Object.entries(value).map(([key, item]) => `${key} ${formatValue(item)}`);

    return parts.length ? parts.join(" · ") : "—";
  }

  return String(value);
}

function summaryCard(label, value, extra) {
  const card = el("div", extra ? `kv ${extra}` : "kv");
  card.append(el("span", null, label), el("b", null, formatValue(value)));
  return card;
}

function renderFindings(findings) {
  const container = el("div", "findings");

  findings.forEach((finding) => {
    const severity = String(finding.severity || "info").toLowerCase();
    const card = el("div", `finding ${severity}`);
    const head = el("div", "finding-head");

    head.append(el("b", null, finding.check || finding.finding_id || "constat"));
    head.append(el("span", `badge ${severity}`, finding.severity || "info"));

    if (finding.confidence) head.append(el("span", "badge", `confiance ${finding.confidence}`));
    if (finding.priority) head.append(el("span", "badge", finding.priority));
    if (finding.status) head.append(el("span", "badge", finding.status));

    card.append(head);

    if (finding.observation) card.append(el("p", null, finding.observation));
    if (finding.evidence) card.append(el("code", null, finding.evidence));
    if (finding.recommendation) card.append(el("p", null, finding.recommendation));

    container.append(card);
  });

  return container;
}

function renderTable(rows, columns) {
  const table = el("table", "grid");
  const head = el("tr");

  columns.forEach((column) => head.append(el("th", null, column.label)));

  const thead = el("thead");
  thead.append(head);
  table.append(thead);

  const body = el("tbody");

  rows.forEach((row) => {
    const line = el("tr");

    columns.forEach((column) => {
      const cell = el("td", column.className ? column.className(row) : null, column.value(row));
      line.append(cell);
    });

    body.append(line);
  });

  table.append(body);

  return table;
}

function renderReport(report) {
  const container = $("report");
  container.replaceChildren();

  const mode = report.mode || "rapport";
  $("report-mode").textContent = mode;
  $("report-mode").className = "chip";

  const summary = el("div", "summary");
  summary.append(
    summaryCard("mode", mode),
    summaryCard("hôte", report.host || "—"),
    summaryCard("généré", report.generated_at || "—"),
    summaryCard("constats", report.findings_count ?? (report.findings || []).length),
    summaryCard("version lab", report.lab_version || report.version || "—"),
  );

  if (report.report_path) summary.append(summaryCard("rapport", report.report_path, "wide"));
  if (report.environment) summary.append(summaryCard("environnement", report.environment));

  container.append(summary);

  if (report.risk_summary) {
    const risk = el("div", "risk");

    Object.entries(report.risk_summary).forEach(([key, value]) => {
      const text = formatValue(value);

      if (text === "—") return;

      risk.append(el("span", "chip", `${key}: ${text}`));
    });

    container.append(risk);
  }

  if (report.mode === "network_scan") {
    container.append(el("h3", "section-title", `cible ${report.target}`));

    Object.entries(report.protocols || {}).forEach(([protocol, results]) => {
      container.append(el("h3", "section-title", protocol.toUpperCase()));
      container.append(
        renderTable(results, [
          { label: "port", value: (row) => row.port },
          {
            label: "état",
            value: (row) => row.state,
            className: (row) => `state-${String(row.state).replace(/[^a-z_]/g, "")}`,
          },
        ]),
      );
    });

    if (report.limits) {
      const limits = el("ul", "list");

      Object.entries(report.limits).forEach(([key, value]) => {
        limits.append(el("li", null, `${key} : ${value}`));
      });

      container.append(el("h3", "section-title", "limites appliquées"), limits);
    }

    if (report.udp_note) container.append(el("p", "empty", report.udp_note));
  }

  if (report.mode === "network_discovery") {
    container.append(el("h3", "section-title", `${report.neighbor_count ?? 0} voisin(s) — sondes actives : ${report.active_probes ? "oui" : "non"}`));

    if ((report.neighbors || []).length) {
      container.append(
        renderTable(report.neighbors, [
          { label: "ip", value: (row) => row.ip },
          { label: "interface", value: (row) => row.interface },
        ]),
      );
    } else {
      container.append(el("p", "empty", "Aucun voisin IPv4 complet dans la table ARP."));
    }
  }

  if (report.inventory) {
    const inventory = report.inventory;
    const strip = el("div", "summary");

    strip.append(
      summaryCard("paquets", inventory.package_count ?? 0),
      summaryCard("produits", (inventory.products || []).length),
      summaryCard("services", (inventory.services || []).length),
      summaryCard("écoutes", (inventory.listeners || []).length),
    );

    if (inventory.host && inventory.host.os_id) {
      strip.append(summaryCard("système", `${inventory.host.os_id} ${inventory.host.os_version || ""}`.trim()));
    }

    container.append(el("h3", "section-title", "inventaire"), strip);
  }

  if ((report.findings || []).length) {
    container.append(el("h3", "section-title", `${report.findings.length} constat(s)`));
    container.append(renderFindings(report.findings));
  }

  if ((report.errors || []).length) {
    const errors = el("ul", "list");
    report.errors.forEach((error) => errors.append(el("li", null, String(error))));
    container.append(el("h3", "section-title", "erreurs explicites"), errors);
  }

  if ((report.limits || []).length) {
    const limits = el("ul", "list");
    report.limits.forEach((limit) => limits.append(el("li", null, String(limit))));
    container.append(el("h3", "section-title", "limites connues"), limits);
  }

  const raw = el("details", "raw");
  raw.append(el("summary", null, "JSON brut"));
  raw.append(el("pre", null, JSON.stringify(report, null, 2)));
  container.append(raw);
}

/* ---------------- formulaire ---------------- */

function showFields(option) {
  const visible = new Set(FIELDS[option] || []);

  document.querySelectorAll("#params [data-for]").forEach((node) => {
    node.classList.toggle("visible", visible.has(node.dataset.for));
  });

  const protocol = $("protocol");

  if (PROTOCOLS[option]) {
    protocol.replaceChildren();

    PROTOCOLS[option].forEach(([value, label]) => {
      const choice = el("option", null, label);
      choice.value = value;
      protocol.append(choice);
    });
  }
}

function selectOption(option) {
  state.selected = option;

  document.querySelectorAll(".option").forEach((button) => {
    button.classList.toggle("active", button.dataset.option === option);
  });

  showFields(option);

  if (state.meta && state.meta.profiles) {
    const profile = state.meta.profiles[$("profile").value];
    $("profile-hint").textContent = profile
      ? `${profile.description} (${profile.tcp_ports} TCP / ${profile.udp_ports} UDP)`
      : "";
  }

  $("target").placeholder =
    state.meta && state.meta.authorized_targets.length
      ? state.meta.authorized_targets.join(", ")
      : "192.168.1.1";
}

async function runSelected() {
  if (!state.selected || state.busy) return;

  const option = state.selected;
  const payload = { option, profile: $("profile").value };

  if (FIELDS[option].includes("target")) payload.target = $("target").value.trim();
  if (FIELDS[option].includes("port")) payload.port = Number($("port").value);
  if (FIELDS[option].includes("protocol")) payload.protocol = $("protocol").value;
  if (option === "scan") payload.confirm = $("confirm").checked;
  if (option === "cve") {
    payload.online = true;
    payload.package = $("package").value.trim();
    payload.version = $("version").value.trim();
  }

  if (FIELDS[option].includes("target") && !payload.target) {
    setStatus("err", "cible requise");
    return;
  }

  if (option === "scan" && !payload.confirm) {
    setStatus("err", "confirmation d'autorisation requise");
    return;
  }

  state.busy = true;
  state.waves.pulses.push(performance.now());
  $("run").disabled = true;
  setStatus("busy", `${option} en cours…`);

  try {
    const response = await api("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();

    if (!response.ok || !body.ok) {
      const container = $("report");
      container.replaceChildren(el("p", "notice", body.error || `échec ${response.status}`));
      $("report-mode").textContent = `${option} refusé`;
      setStatus("err", body.error || `échec ${response.status}`);
      return;
    }

    state.lastReport = body.report;
    renderReport(body.report);
    setStatus("live", `${option} terminé · ${body.report.findings_count ?? 0} constat(s)`);
  } catch (error) {
    setStatus("err", error.message);
  } finally {
    state.busy = false;
    $("run").disabled = false;
    state.waves.pulses.push(performance.now());
  }
}

/* ---------------- démarrage ---------------- */

function renderOptions() {
  const container = $("options");
  container.replaceChildren();

  OPTIONS.forEach((option) => {
    const button = el("button", "option");
    button.type = "button";
    button.dataset.option = option.id;
    button.append(el("span", null, option.label), el("small", null, option.hint));
    button.addEventListener("click", () => selectOption(option.id));
    container.append(button);
  });
}

function renderProfiles(meta) {
  const select = $("profile");
  select.replaceChildren();

  Object.entries(meta.profiles).forEach(([name, profile]) => {
    const choice = el("option", null, `${name} — ${profile.concurrency} sonde(s), ×${profile.timeout_factor}`);
    choice.value = name;
    select.append(choice);
  });

  select.value = meta.default_profile;
  select.addEventListener("change", () => {
    const profile = meta.profiles[select.value];
    $("profile-hint").textContent = `${profile.description} (${profile.tcp_ports} TCP / ${profile.udp_ports} UDP)`;
  });
}

async function boot() {
  if (!TOKEN) {
    setStatus("err", "jeton absent : ouvrez l'URL affichée par le lanceur");
    $("report").replaceChildren(
      el("p", "notice", "Aucun jeton de session. Relancez ./lancer-nour-sentinel.sh --intel dashboard et ouvrez l'URL complète affichée dans le terminal.")
    );
    return;
  }

  renderOptions();
  requestAnimationFrame(drawFrame);

  try {
    const response = await api("/api/meta");
    const meta = await response.json();
    state.meta = meta;

    $("versions").textContent = `lab ${meta.version} · moteur ${meta.core_version} · protocole ${meta.protocol_version}`;
    renderProfiles(meta);
    selectOption("inventory");
    setStatus("live", "prêt · 127.0.0.1 uniquement");
  } catch (error) {
    setStatus("err", error.message);
    return;
  }

  $("run").addEventListener("click", runSelected);
  $("params").addEventListener("submit", (event) => {
    event.preventDefault();
    runSelected();
  });

  $("copy").addEventListener("click", async () => {
    if (!state.lastReport) return;

    try {
      await navigator.clipboard.writeText(JSON.stringify(state.lastReport, null, 2));
      $("copy").textContent = "copié";
      window.setTimeout(() => { $("copy").textContent = "copier JSON"; }, 1600);
    } catch (error) {
      setStatus("err", "copie refusée par le navigateur");
    }
  });

  $("clear").addEventListener("click", () => {
    state.lastReport = null;
    $("report").replaceChildren(el("p", "empty", "Rapport effacé. Sélectionnez une option puis lancez-la."));
    $("report-mode").textContent = "aucune option exécutée";
    setStatus("live", "prêt");
  });

  pollWaves();
  window.setInterval(pollWaves, 900);
}

boot();
