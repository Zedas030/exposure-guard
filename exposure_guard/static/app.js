"use strict";
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (iso) => { if (!iso) return "-"; const d = new Date(iso); return isNaN(d) ? esc(iso) : d.toLocaleString(); };
const ago = (iso) => { if (!iso) return "never"; const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 120) return Math.round(s) + " s ago"; if (s < 7200) return Math.round(s / 60) + " min ago";
  if (s < 172800) return (s / 3600).toFixed(1) + " h ago"; return (s / 86400).toFixed(1) + " d ago"; };
const STATE = { ok: "OK", attention: "Findings to review", degraded: "Degraded - a check fails",
  unknown: "Unknown - external view missing", alert: "ALERT - critical change" };
let FINDINGS = [], FILTER = "attention";

async function getJSON(u) { const r = await fetch(u, { cache: "no-store" }); if (!r.ok) throw new Error(u + " " + r.status); return r.json(); }

function card(k, v, s, cls) { return `<div class="card"><div class="k">${esc(k)}</div><div class="v ${cls || ""}">${v}</div><div class="s">${s || ""}</div></div>`; }

function renderStatus(st) {
  const b = $("#banner");
  if (["alert", "unknown", "degraded"].includes(st.state)) {
    b.hidden = false; b.className = "banner " + st.state;
    b.textContent = st.state === "unknown" ? `External view not current: ${st.external_stale || "check failing"} - this is NOT an all-clear.`
      : st.state === "alert" ? `${st.critical_open} critical change(s) need attention.`
      : `Failing checks: ${st.broken_sources.join(", ")} - results may be incomplete.`;
  } else { b.hidden = true; }
  const s = st.open_by_severity;
  const ext = st.external || {}, last = ext.last || {};
  const openExt = last.open ? Object.values(last.open).reduce((a, x) => a + x.length, 0) : "?";
  $("#cards").innerHTML =
    card("State", `<span class="st-${st.state}">${esc(STATE[st.state])}</span>`, `updated ${ago(st.generated)}`) +
    card("Open findings", `${st.open_total}`, `${s.critical} critical · ${s.high} high · ${s.medium} medium · ${st.baseline} baseline · ${st.acknowledged} ack`) +
    card("External scan", st.external_last_scan ? ago(st.external_last_scan) : "never", `${esc(st.external_last_profile || "")} · ${openExt} open port(s)`) +
    card("Public IPv4", esc(st.public_ipv4 || "-"), ext.seen_v4 ? `probe sees ${esc(ext.seen_v4.addr)}${ext.seen_v4.matches_router ? "" : " (MISMATCH)"}` : "") +
    card("IPv6 prefix", esc(st.public_ipv6_prefix || "-"), ext.seen_v6 ? `probe sees ${esc(ext.seen_v6.addr)}` : "") +
    card("LAN devices", `${st.devices}`, "router host list + neighbours");
  const rows = Object.values(st.health).sort((a, b) => a.source.localeCompare(b.source)).map((h) =>
    `<tr><td>${esc(h.source)}</td><td class="${h.failures ? "st-alert" : "st-ok"}">${h.failures ? "failing x" + h.failures : "ok"}</td>
     <td>${ago(h.last_success)}</td><td>${esc(h.last_error || "")}</td></tr>`).join("");
  $("#health").innerHTML = `<div class="tbl"><table><tr><th>Check</th><th>State</th><th>Last success</th><th>Last error</th></tr>${rows}</table></div>`;
  const fr = st.fritz || {}, dev = fr.device || {}, ra = fr.remote_access || {};
  const maps = (fr.port_mappings || []).map((m) => `<tr><td>${esc(m.origin)}</td><td>${m.external_port}/${esc(m.protocol)}</td>
    <td>${esc(m.internal_client)}:${m.internal_port}</td><td>${esc(m.description)}</td></tr>`).join("");
  $("#router").innerHTML = fr.device ? `<p>${esc(dev.model)} · FRITZ!OS ${esc(dev.firmware)}${dev.update_available ? " · <b>update available</b>" : ""}<br>
    Remote access: ${ra.enabled ? "on, port " + esc(ra.port) : "off"} · MyFRITZ!: ${(fr.myfritz || {}).enabled ? "on" : "off"} ·
    UPnP: ${(fr.upnp || {}).enabled ? "on" : "off"}<br><span class="s">read ${ago(fr.at)}</span></p>
    ${maps ? `<div class="tbl"><table><tr><th>Origin</th><th>External</th><th>Internal</th><th>Description</th></tr>${maps}</table></div>` : `<p class="empty">No IPv4 port forwardings.</p>`}`
    : `<p class="empty">No router data yet.</p>`;
  const opens = last.open ? Object.entries(last.open).map(([a, ps]) => `<tr><td>${esc(a)}</td><td>${ps.map(esc).join("<br>")}</td></tr>`).join("") : "";
  const probe = ext.probe || {};
  $("#external").innerHTML = last.run_id ? `<p>Last result <code>${esc(last.run_id)}</code> (${last.ok ? "complete" : "INCOMPLETE"}), ${last.targets} targets.
    Last full TCP scan: ${ext.last_full ? fmt(ext.last_full.finished) : "none yet"}.<br>
    Probe ${esc(probe.probe_version || "?")}, contacted ${ago(probe.fetched)}.</p>
    ${opens ? `<div class="tbl"><table><tr><th>Address</th><th>Open</th></tr>${opens}</table></div>` : `<p>No open port on any target.</p>`}
    ${(last.errors || []).length ? `<p class="st-alert">${last.errors.map(esc).join("<br>")}</p>` : ""}`
    : `<p class="empty">No external result yet${st.external_stale ? " - " + esc(st.external_stale) : ""}.</p>`;
  $("#reports").innerHTML = (st.reports || []).length ? "<ul>" + st.reports.map((r) =>
    `<li><a href="/reports/${encodeURIComponent(r)}.html">${esc(r)}</a> · <a href="/reports/${encodeURIComponent(r)}.md">md</a></li>`).join("") + "</ul>"
    : `<p class="empty">No report yet (the initial report is written after the first complete external scan).</p>`;
  const ui = st.ui || {};
  if (ui.home_url) { const h = $("#home"); h.hidden = false; h.href = ui.home_url; h.textContent = ui.home_label || "Home"; }
  $("#foot").textContent = `Exposure Guard ${st.version} · read-only · metrics at /metrics`;
}

function renderFindings() {
  const sel = FINDINGS.filter((f) => FILTER === "all" ? true : FILTER === "acked" ? !!f.ack
    : FILTER === "baseline" ? f.baseline && !f.ack : !f.ack && !f.baseline);
  $("#findings").innerHTML = sel.length ? sel.map((f) => `<div class="f">
    <div class="t"><span class="sev ${f.severity}">${f.severity}</span>${esc(f.title)}
      ${f.ack ? `<span class="tag">ack: ${esc(f.ack.reason || "")}</span>` : ""}${f.baseline ? `<span class="tag">baseline</span>` : ""}</div>
    <div class="m">${esc(f.message)}</div><div class="a">→ ${esc(f.action)}</div>
    <div class="a"><code>${esc(f.id)}</code> · first seen ${fmt(f.first_seen)} · source ${esc(f.source)}</div></div>`).join("")
    : `<p class="empty">Nothing here.</p>`;
}

async function load() {
  try {
    const [st, fs] = await Promise.all([getJSON("/api/status"), getJSON("/api/findings")]);
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    FINDINGS = fs.sort((a, b) => order[a.severity] - order[b.severity] || a.id.localeCompare(b.id));
    renderStatus(st); renderFindings();
  } catch (e) {
    const b = $("#banner"); b.hidden = false; b.className = "banner unknown"; b.textContent = "Cannot load status: " + e.message;
  }
}

document.querySelectorAll(".seg button").forEach((btn) => btn.addEventListener("click", () => {
  document.querySelectorAll(".seg button").forEach((x) => x.classList.toggle("on", x === btn));
  FILTER = btn.dataset.filter; renderFindings();
}));
$("#theme").addEventListener("click", () => {
  const t = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("hl-theme", t); } catch (e) { /* ignore */ }
});
load();
let timer = setInterval(load, 60000);
document.addEventListener("visibilitychange", () => { clearInterval(timer); if (!document.hidden) { load(); timer = setInterval(load, 60000); } });
