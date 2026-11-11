// Sentinel web page: start an investigation, render the agent's live events, show the report and the approvals.
// Plain JavaScript, no build step. Everything the model or the data produced is escaped before it reaches the
// page: tool results and reports are untrusted text (the synthetic data even contains a prompt injection).
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const view = $("#view");
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
const short = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtInt = (n) => Number(n || 0).toLocaleString("en-US");

const SOURCES = [
  { prefix: "AUTH", key: "auth", label: "Logins" },
  { prefix: "ACC", key: "acc", label: "Badge access" },
  { prefix: "DEV", key: "dev", label: "Devices" },
  { prefix: "LOG", key: "log", label: "App logs" },
];
const sourceOf = (id) => (SOURCES.find((s) => String(id).startsWith(s.prefix + "-")) || SOURCES[3]).key;
const GUARDRAILS = ["Read-only tools, parameterised SQL", "Time range and limit on every query",
  "Hard step limit", "Report IDs checked against the database", "Actions need a human approver"];

const state = {
  config: null,
  runs: {},                                   // id -> run as returned by the server, plus its events
  key: sessionStorage.getItem("sentinel.key") || "",
  live: null,                                 // the trace view currently on screen, if any
};

// ---------------------------------------------------------------- server calls

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const res = await fetch(path, { ...options, headers });
  let body = null;
  try { body = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const detail = body && body.detail;
    const message = typeof detail === "string" ? detail
      : Array.isArray(detail) ? detail.map((d) => d.msg).join("; ") : `${res.status} ${res.statusText}`;
    const error = new Error(message); error.status = res.status; throw error;
  }
  return body;
}
const withKey = (options = {}) => ({ ...options, headers: { "X-API-Key": state.key } });

// ---------------------------------------------------------------- recent investigations (this browser)

const recent = {
  list() { try { return JSON.parse(localStorage.getItem("sentinel.recent") || "[]"); } catch { return []; } },
  add(id, question) {
    const items = [{ id, question, at: Date.now() }, ...this.list().filter((r) => r.id !== id)].slice(0, 12);
    localStorage.setItem("sentinel.recent", JSON.stringify(items));
    drawRecent();
  },
  forget(id) { localStorage.setItem("sentinel.recent", JSON.stringify(this.list().filter((r) => r.id !== id))); drawRecent(); },
};

function drawRecent() {
  const items = recent.list();
  const current = (location.hash.match(/^#\/(?:run|report)\/([\w-]+)/) || [])[1];
  $("#recent").innerHTML = items.length ? `<h6>Recent</h6>` + items.map((r) =>
    `<a href="#/run/${esc(r.id)}" class="${r.id === current ? "on" : ""}" title="${esc(r.question)}">${esc(r.question)}</a>`).join("") : "";
}

// ---------------------------------------------------------------- runs: start, poll

async function loadRun(id) {
  if (state.runs[id]) return state.runs[id];
  const run = await api(`/demo-api/investigations/${encodeURIComponent(id)}?since=0`);
  run.next = run.next ?? run.events.length;
  state.runs[id] = run;
  if (run.status === "running") poll(run);
  return run;
}

async function poll(run) {
  if (run.polling) return;
  run.polling = true;
  let failures = 0;
  while (run.status === "running") {
    await sleep(800);
    try {
      const update = await api(`/demo-api/investigations/${encodeURIComponent(run.id)}?since=${run.next}`);
      failures = 0;
      const fresh = update.events;
      Object.assign(run, update, { events: run.events.concat(fresh) });
      if (state.live && state.live.run === run) state.live.update(fresh);
    } catch (e) {
      if (e.status === 404 || ++failures >= 8) {
        Object.assign(run, { status: "failed", error: e.status === 404 ? "The server restarted and forgot this investigation." : e.message });
        if (state.live && state.live.run === run) state.live.update([]);
      }
    }
  }
  run.polling = false;
  updatePendingCount();
}

async function startInvestigation(question, errorEl, button) {
  errorEl.textContent = "";
  button.disabled = true;
  try {
    const { id } = await api("/demo-api/investigations", { method: "POST", body: JSON.stringify({ question }) });
    const run = { id, question, status: "running", events: [], next: 0, elapsed_s: 0 };
    state.runs[id] = run;
    recent.add(id, question);
    location.hash = `#/run/${id}`;
    poll(run);
  } catch (e) {
    errorEl.textContent = e.status === 422 ? "Please ask a question between 3 and 500 characters." : e.message;
    button.disabled = false;
  }
}

// ---------------------------------------------------------------- page: investigate (home)

function renderHome() {
  const scenarios = (state.config && state.config.scenarios) || [];
  view.innerHTML = `
    <header class="page-head">
      <div class="eyebrow">Agentic security investigation</div>
      <h1>Ask what happened. <em>Watch the agent find out.</em></h1>
      <p>Sentinel decides which evidence to gather (logins, badge access, device status, application logs), correlates it
        into one timeline, and writes a report where every fact cites a real record. The data is synthetic: two days at a
        fictional company, 30 Sep and 1 Oct 2026.</p>
    </header>
    <form class="ask" id="ask-form">
      <span class="ask-icon">?</span>
      <textarea id="question" rows="1" maxlength="500" placeholder="What happened around 02:00 on 2026-09-30?"></textarea>
      <button class="btn ok" id="ask-button" type="submit">Investigate →</button>
    </form>
    <div class="form-error" id="ask-error"></div>
    <div class="examples">${scenarios.map((s) => `
      <div class="ex-group"><h6>${esc(s.label)}</h6>
        ${s.questions.map((q) => `<button class="ex" type="button">${esc(q)}</button>`).join("")}
      </div>`).join("")}
    </div>
    <div class="intro-points">
      <div class="card ip"><b>It chooses its own evidence</b><span>13 validated tools. Every query needs a time range and a limit, and returns citable IDs like AUTH-00009.</span></div>
      <div class="card ip"><b>Every fact cites a record</b><span>The report is checked by code: a cited ID that doesn't exist sends it back to the model to fix.</span></div>
      <div class="card ip"><b>Humans approve actions</b><span>The agent can only propose. No model can reach the code that disables an account or blocks an IP.</span></div>
    </div>`;
  const form = $("#ask-form"), textarea = $("#question"), button = $("#ask-button"), error = $("#ask-error");
  const grow = () => { textarea.style.height = "auto"; textarea.style.height = textarea.scrollHeight + "px"; };
  textarea.addEventListener("input", grow);
  textarea.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); }
  });
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const q = textarea.value.trim();
    if (q.length < 3) { error.textContent = "Please type a question, or pick one of the examples below."; return; }
    startInvestigation(q, error, button);
  });
  view.querySelectorAll(".ex").forEach((b) => b.addEventListener("click", () => {
    textarea.value = b.textContent; grow(); textarea.focus();
  }));
  textarea.focus();
}

// ---------------------------------------------------------------- page: a live investigation

function formatArgs(name, input) {
  if (name === "submit_report") {
    const r = input || {};
    return `severity=${r.severity ?? "?"}, ${(r.facts || []).length} facts, ${(r.timeline || []).length} timeline entries`;
  }
  const parts = Object.entries(input || {}).map(([k, v]) => {
    const value = typeof v === "string" ? `"${v.replace(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(:00)?Z$/, "$1 $2")}"` : JSON.stringify(v);
    return `${k}=${short(value, 70)}`;
  });
  return short(parts.join(", "), 240);
}

class TraceView {
  constructor(run) {
    this.run = run;
    this.steps = {};      // step number -> {el, body}
    this.lastCall = null; // the call line the next observation belongs to
    this.endCard = null;
    view.innerHTML = `
      <header class="page-head"><div class="eyebrow">Agent loop · ${esc(run.id)}</div></header>
      <div class="ask"><span class="ask-icon">?</span><div class="q">${esc(run.question)}</div><span class="run-state" id="run-state"></span></div>
      <div class="inv-grid">
        <div><div class="trace" id="trace"></div><div id="result"></div></div>
        <aside class="card panel" id="panel"></aside>
      </div>`;
    this.trace = $("#trace");
    this.update(run.events);
  }

  card(sn, cls = "") {
    const el = document.createElement("div");
    el.className = `step ${cls}`;
    el.innerHTML = `<div class="sn">${esc(sn)}</div><div class="sb"></div>`;
    this.trace.appendChild(el);
    return { el, body: el.querySelector(".sb") };
  }

  setCurrent(el) {
    this.trace.querySelectorAll(".step.cur").forEach((s) => s.classList.remove("cur"));
    if (el) el.classList.add("cur");
  }

  apply(e) {
    const s = e.step != null ? this.steps[e.step] : null;
    switch (e.kind) {
      case "started": {
        const c = this.card("▶");
        c.body.innerHTML = `<div class="lbl think">STARTED<span class="meta-r">${e.tool_count} tools · step limit ${e.max_steps}</span></div>
          <p>Model: ${esc(e.models.join(" → "))}. The model receives the question, the tool definitions and the rules; it decides what to look at.</p>`;
        break;
      }
      case "step_started": {
        let c = s;
        if (!c) { c = this.card(e.step); this.steps[e.step] = c; }
        c.body.innerHTML = `<div class="lbl think">STEP ${e.step} · REASON<span class="meta-r">${esc(e.model || "")}</span></div>
          <div class="waiting"><span class="spinner"></span>Sending ${e.history_messages} message(s); waiting for the model to decide what to do next…</div>`;
        this.setCurrent(c.el);
        break;
      }
      case "model_replied": {
        if (!s) break;
        const meta = `${e.seconds}s · ${fmtInt(e.tokens_in)} in / ${fmtInt(e.tokens_out)} out`;
        let html = `<div class="lbl think">STEP ${e.step} · REASON<span class="meta-r">${esc(meta)}</span></div>`;
        if (e.thinking) html += `<p>${esc(e.thinking)}</p>`;
        if (e.text) html += `<p>${esc(e.text)}</p>`;
        if (e.stop_reason === "tool_use") {
          if (!e.thinking && !e.text) html += `<p>Decided to call ${e.tools.length} tool${e.tools.length > 1 ? "s" : ""}.</p>`;
          html += `<div class="lbl act" style="margin-top:12px">ACT${e.tools.length > 1 ? ` · parallel ×${e.tools.length}` : ""}</div>`;
        } else if (e.stop_reason === "end_turn") {
          html += `<p>The model answered in plain text.</p>`;
        }
        s.body.innerHTML = html;
        break;
      }
      case "tool_started": {
        if (!s) break;
        const tag = e.name === "propose_action" ? `<span class="tag-k propose">PROPOSE</span>`
          : e.name === "submit_report" ? `<span class="tag-k submit">SUBMIT</span>` : "";
        const call = document.createElement("div");
        call.className = "call";
        call.innerHTML = `${tag}${esc(e.name)}<span class="args">(${esc(formatArgs(e.name, e.input))})</span>`;
        s.body.appendChild(call);
        this.lastCall = call;
        break;
      }
      case "tool_finished": {
        if (!s) break;
        const obs = document.createElement("div");
        if (e.is_error) {
          obs.className = "obs err";
          obs.innerHTML = e.name === "submit_report"
            ? `✕ Report rejected by validation, sent back to the model to fix: ${esc(e.error)}`
            : `✕ ${esc(e.error)} <span class="muted">(returned to the model as an observation)</span>`;
        } else if (e.name === "submit_report") {
          obs.className = "obs";
          obs.innerHTML = `<span style="color:var(--green)">✓</span> Report accepted: schema valid, every cited evidence ID exists in the database.`;
        } else if (e.name === "propose_action") {
          obs.className = "obs";
          obs.innerHTML = `Proposed. It waits for a human approver; the agent cannot execute it.`;
        } else {
          obs.className = "obs";
          const ids = e.evidence || [];
          obs.innerHTML = `${e.facts ? `<span class="facts">${esc(e.facts)}</span>` : ""}<span class="muted">${fmtInt(e.chars)} chars · ${e.ms}ms</span>`
            + (ids.length ? `<div class="ids">${ids.slice(0, 10).map((i) => `<span class="id">${esc(i)}</span>`).join("")}${ids.length > 10 ? `<span class="muted small">+${ids.length - 10} more</span>` : ""}</div>` : "");
        }
        if (this.lastCall && this.lastCall.parentNode === s.body) this.lastCall.after(obs); else s.body.appendChild(obs);
        break;
      }
      case "fallback": {
        const c = this.card("↻", "warn");
        c.body.innerHTML = `<div class="lbl warn">FALLBACK · STEP ${e.step}</div>
          <p>${esc(e.provider)} is unavailable (${esc(e.error)}). ${e.next ? `Switching to ${esc(e.next)} for the rest of the run.` : "No backup model left."}</p>`;
        break;
      }
      case "nudged": {
        const c = this.card("!", "warn");
        c.body.innerHTML = `<div class="lbl warn">NUDGE · STEP ${e.step}</div>
          <p>The model answered in plain text instead of submitting a structured report. The loop reminds it once: the format of the final answer is enforced by code.</p>`;
        break;
      }
      case "stopped": {
        const ok = e.stop_reason === "report_submitted";
        const c = this.card(ok ? "✓" : "■", ok ? "end" : "warn");
        c.body.innerHTML = `<div class="lbl ${ok ? "done" : "warn"}">STOPPED AT STEP ${e.step}</div><p>${esc(e.why)}.</p>`;
        this.endCard = c;
        this.setCurrent(null);
        break;
      }
      case "finished": {
        const target = this.endCard || this.card("■");
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.style.marginTop = "8px";
        meta.textContent = `${e.steps} steps · ${e.tool_calls} tool calls · ${e.duration_s}s · ${fmtInt(e.tokens)} tokens · ${e.models.join(", ") || "no model"}`;
        target.body.appendChild(meta);
        break;
      }
    }
  }

  update(fresh) {
    fresh.forEach((e) => this.apply(e));
    if (fresh.length) {
      const last = this.trace.lastElementChild;
      const nearBottom = window.innerHeight + window.scrollY > document.body.scrollHeight - 260;
      if (last && nearBottom && this.run.status === "running") last.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
    this.drawState();
    this.drawPanel();
    this.drawResult();
  }

  drawState() {
    const run = this.run, el = $("#run-state");
    if (!el) return;
    const step = [...run.events].reverse().find((e) => e.step != null);
    const max = (run.events.find((e) => e.kind === "started") || {}).max_steps || (state.config && state.config.max_steps) || "?";
    if (run.status === "running") el.innerHTML = `<span class="dot busy"></span>running · step ${step ? step.step : 0} of ${max} · ${Math.round(run.elapsed_s || 0)}s`;
    else if (run.status === "completed") el.innerHTML = `<span class="dot live"></span>completed${run.stats ? ` in ${run.stats.duration_s}s` : ""}`;
    else el.innerHTML = `<span class="dot" style="background:var(--red)"></span>failed`;
  }

  drawPanel() {
    const run = this.run, ids = new Set();
    let calls = 0, errors = 0, tokens = 0;
    const tools = {};
    for (const e of run.events) {
      if (e.kind === "tool_finished") {
        calls++; if (e.is_error) errors++;
        (e.evidence || []).forEach((i) => ids.add(i));
        tools[e.name] = (tools[e.name] || 0) + 1;
      }
      if (e.kind === "model_replied") tokens += (e.tokens_in || 0) + (e.tokens_out || 0);
    }
    const bySource = Object.fromEntries(SOURCES.map((s) => [s.key, 0]));
    ids.forEach((i) => bySource[sourceOf(i)]++);
    const model = (run.events.filter((e) => e.kind === "model_replied").pop() || {}).model
      || ((state.config && state.config.models[0]) || {}).model || "—";
    const latest = [...ids].slice(-12);
    $("#panel").innerHTML = `
      <div class="ev-h">Evidence collected <span class="muted">${ids.size} record${ids.size === 1 ? "" : "s"}</span></div>
      ${SOURCES.map((s) => `<div class="src ${bySource[s.key] ? "" : "zero"}"><i class="d ${s.key}"></i>${s.label}<b>${bySource[s.key]}</b></div>`).join("")}
      ${latest.length ? `<div class="ids" style="margin-top:10px">${latest.map((i) => `<span class="id">${esc(i)}</span>`).join("")}</div>` : ""}
      <div class="ev-h mt">Tools used <span class="muted">${calls} call${calls === 1 ? "" : "s"}${errors ? ` · ${errors} error${errors > 1 ? "s" : ""}` : ""}</span></div>
      ${Object.entries(tools).map(([n, c]) => `<div class="kv"><span>${esc(n)}</span><b>×${c}</b></div>`).join("") || `<div class="muted small">None yet</div>`}
      <div class="ev-h mt">Run</div>
      <div class="kv"><span>Model</span><b title="${esc(model)}">${esc(short(model, 26))}</b></div>
      <div class="kv"><span>Tokens</span><b>${fmtInt(tokens)}</b></div>
      <div class="ev-h mt">Guardrails</div>
      <ul class="guard">${GUARDRAILS.map((g) => `<li>${g}</li>`).join("")}</ul>`;
  }

  drawResult() {
    const run = this.run, el = $("#result");
    if (!el || run.status === "running" || el.dataset.done) return;
    el.dataset.done = "1";
    if (run.status === "failed") {
      el.innerHTML = `<div class="card result" style="border-color:rgba(248,113,113,.4)"><div class="result-top"><span class="sev HIGH">FAILED</span></div>
        <p>${esc(run.error || "The investigation failed.")}</p></div>`;
      return;
    }
    const proposals = run.proposals || [];
    const review = proposals.length ? `<a class="btn ghost" href="#/approvals">Review ${proposals.length} proposed action${proposals.length > 1 ? "s" : ""}</a>` : "";
    if (run.report) {
      el.innerHTML = `<div class="card result">
        <div class="result-top"><span class="sev ${esc(run.report.severity)}">${esc(run.report.severity)}</span>
          <span class="muted small">confidence ${esc(run.report.confidence)}% · ${(run.report.facts || []).length} facts · ${(run.report.timeline || []).length} timeline entries</span></div>
        <p>${esc(run.report.summary)}</p>
        <div class="btns"><a class="btn ok" href="#/report/${esc(run.id)}">Open the full report →</a>${review}</div></div>`;
    } else {
      el.innerHTML = `<div class="card result"><div class="result-top"><span class="sev LOW">ANSWER</span>
          <span class="muted small">no structured report was submitted</span></div>
        <p>${esc(short((run.answer || "No answer.").replace(/[#*`]/g, ""), 400))}</p>
        <div class="btns"><a class="btn ok" href="#/report/${esc(run.id)}">Read the answer →</a>${review}</div></div>`;
    }
    updatePendingCount();
  }
}

// ---------------------------------------------------------------- page: report

function parseTimeline(entries) {
  // "2026-09-30 02:08", "02:17-02:24", "01:52–02:05" → minutes since the first day seen
  let lastDate = null, firstDay = null;
  return entries.map((t) => {
    const text = String(t.time || "");
    const date = (text.match(/(\d{4}-\d{2}-\d{2})/) || [])[1] || lastDate;
    lastDate = date;
    const times = [...text.matchAll(/(?:^|[^\d])(\d{1,2}):(\d{2})/g)].map((m) => +m[1] * 60 + +m[2]);
    if (!times.length) return { ...t, start: null };
    const day = date ? Math.round(Date.parse(date + "T00:00:00Z") / 86400000) : 0;
    if (firstDay === null) firstDay = day;
    const base = (day - firstDay) * 1440;
    const start = base + times[0];
    let end = times.length > 1 ? base + times[1] : null;
    if (end !== null && end < start) end += 1440;
    const ev = t.evidence || [];
    const lane = ev.length ? sourceOf(ev[0]) : guessLane(t.what);
    return { ...t, start, end, lane };
  });
}

function guessLane(text) {
  const s = String(text || "").toLowerCase();
  if (/login|password|mfa|auth|sign-?in/.test(s)) return "auth";
  if (/badge|door|swipe|access granted|entered/.test(s)) return "acc";
  if (/camera|device|offline|online|sensor/.test(s)) return "dev";
  return "log";
}

const hhmm = (m) => { const d = ((m % 1440) + 1440) % 1440; return `${String(Math.floor(d / 60)).padStart(2, "0")}:${String(d % 60).padStart(2, "0")}`; };

function drawLanes(container, items) {
  const timed = items.filter((i) => i.start !== null);
  const min = Math.min(...timed.map((i) => i.start)), max = Math.max(...timed.map((i) => i.end ?? i.start));
  if (timed.length < 2 || max <= min) { container.hidden = true; return; }
  container.hidden = false;
  const pad = Math.max((max - min) * 0.06, 2), lo = min - pad, hi = max + pad * 3;
  const narrow = window.matchMedia("(max-width: 820px)").matches; // matches the label width in app.css
  const lanesWidth = container.clientWidth - (narrow ? 24 + 84 : 40 + 120);
  const x = (m) => ((m - lo) / (hi - lo)) * lanesWidth;
  const tick = [5, 10, 15, 30, 60, 120, 180, 360, 720, 1440].find((t) => (hi - lo) / t <= 7) || 1440;
  let axis = "";
  for (let t = Math.ceil(lo / tick) * tick; t <= hi; t += tick) axis += `<span style="left:${x(t)}px">${hhmm(t)}</span>`;
  const used = SOURCES.filter((s) => timed.some((i) => i.lane === s.key));
  const lanes = used.map((s) => {
    const rows = [];
    const chips = timed.filter((i) => i.lane === s.key).sort((a, b) => a.start - b.start).map((i) => {
      const label = i.end !== null ? short(i.what, 60) : ((i.evidence || [])[0] || short(i.what, 22));
      const left = x(i.start);
      const width = i.end !== null ? Math.max(x(i.end) - left, 44) : label.length * 6.8 + 18;
      let row = rows.findIndex((right) => right + 6 <= left);
      if (row === -1) { rows.push(0); row = rows.length - 1; }
      rows[row] = left + width;
      const kind = i.end !== null ? "span" : "ev";
      return `<span class="${kind} ${s.key}" style="left:${left}px;top:${8 + row * 28}px;${kind === "span" ? `width:${width}px` : `max-width:${Math.max(lanesWidth - left, 60)}px`}"
        title="${esc(i.time)} · ${esc(i.what)}">${esc(label)}</span>`;
    }).join("");
    return `<div class="lane"><div class="ln"><i class="d ${s.key}"></i>${s.label}</div><div class="track" style="height:${Math.max(rows.length, 1) * 28 + 10}px">${chips}</div></div>`;
  }).join("");
  container.innerHTML = `<div class="lane-axis">${axis}</div>${lanes}`;
}

function md(text) {
  // A small, safe markdown renderer for plain-text answers: escape first, then add a few tags.
  const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
  const out = []; let list = false;
  for (const line of String(text || "").split("\n")) {
    const item = line.match(/^\s*[-*]\s+(.*)/);
    if (item) { if (!list) { out.push("<ul>"); list = true; } out.push(`<li>${inline(item[1])}</li>`); continue; }
    if (list) { out.push("</ul>"); list = false; }
    const h = line.match(/^#{1,4}\s+(.*)/);
    if (h) out.push(`<h3>${inline(h[1])}</h3>`);
    else if (line.trim()) out.push(`<p>${inline(line)}</p>`);
  }
  if (list) out.push("</ul>");
  return out.join("");
}

const idChips = (ids) => (ids || []).map((i) => `<span class="id">${esc(i)}</span>`).join("");

function renderReport(run) {
  const r = run.report;
  const stats = run.stats ? `<div class="stats-line"><span>${esc(run.id)}</span><span>${run.stats.steps} steps</span>
    <span>${run.stats.tool_calls} tool calls</span><span>${run.stats.duration_s}s</span><span>${fmtInt(run.stats.tokens)} tokens</span>
    <span>${esc((run.stats.models || []).join(", "))}</span></div>` : "";
  if (!r) {
    view.innerHTML = `<header class="page-head"><div class="eyebrow">Answer · ${esc(run.id)}</div><h1>${esc(run.question)}</h1></header>
      <div class="card rep"><div class="notice" style="margin:0 0 20px">The model answered in plain text rather than submitting a validated, structured report, so the evidence IDs below were not checked by code.</div>
      <div class="md">${md(run.answer)}</div>${stats}</div>`;
    return;
  }
  const summary = String(r.summary || "");
  const first = (summary.match(/^.+?[.!?](?=\s|$)/) || [summary])[0];
  const title = short(first, 170), rest = summary.slice(first.length).trim();
  const timeline = parseTimeline(r.timeline || []);
  // One date for every entry: say it once in the heading and show only the times
  const dates = new Set((r.timeline || []).map((t) => (String(t.time).match(/\d{4}-\d{2}-\d{2}/) || [""])[0]));
  const oneDate = dates.size === 1 && [...dates][0] ? [...dates][0] : null;
  const timeOf = (t) => oneDate ? String(t).replace(oneDate, "").trim() : t;
  const cited = new Set([...(r.timeline || []).flatMap((t) => t.evidence || []), ...(r.facts || []).flatMap((f) => f.evidence || [])]);
  const list = (items, fn, none) => items && items.length ? items.map(fn).join("") : `<div class="muted small">${none}</div>`;
  view.innerHTML = `
    <header class="page-head"><div class="eyebrow">Structured report · ${esc(run.id)}</div></header>
    <div class="card rep">
      <div class="rep-head">
        <div><div class="muted small">QUESTION · ${esc(run.question)}</div><h2>${esc(title)}</h2></div>
        <div class="sevbox"><span class="sev lg ${esc(r.severity)}">${esc(r.severity)}</span>
          <div class="conf"><div class="bar"><span style="width:${Math.max(0, Math.min(100, +r.confidence || 0))}%"></span></div><span class="muted small">confidence ${esc(r.confidence)}%</span></div></div>
      </div>
      ${rest ? `<p class="rep-summary">${esc(rest)}</p>` : ""}
      ${oneDate ? `<div class="muted small" style="margin-top:22px">TIMELINE · ${esc(oneDate)} · UTC</div>` : ""}
      <div class="lanes" id="lanes" hidden></div>
      ${timeline.length ? `<div class="tl">${timeline.map((t) => `<div class="tl-row"><i class="d ${t.lane || guessLane(t.what)}"></i>
        <span class="t">${esc(timeOf(t.time))}</span><span class="w">${esc(t.what)} ${idChips(t.evidence)}</span></div>`).join("")}</div>` : ""}
      <div class="rep-grid">
        <div>
          <div class="sec"><h4>Facts <span class="muted">each cites evidence</span></h4>
            ${list(r.facts, (f) => `<div class="fact">${esc(f.statement)}<div class="ids">${idChips(f.evidence)}</div></div>`, "No facts.")}</div>
          <div class="sec"><h4>Missing evidence</h4>${list(r.missing_evidence, (m) => `<div class="miss">${esc(m)}</div>`, "None noted.")}</div>
        </div>
        <div>
          <div class="sec"><h4>Inferences <span class="muted">with confidence</span></h4>
            ${list(r.inferences, (i) => `<div class="inf"><span class="cf ${esc(i.confidence)}">${esc(i.confidence)}</span>
              <span>${esc(i.statement)}<span class="why">${esc(i.reasoning)}</span></span></div>`, "No inferences.")}</div>
          <div class="sec"><h4>Cleared <span class="muted">checked, not suspicious</span></h4>
            ${list(r.not_suspicious, (c) => `<div class="clr"><b>${esc(c.item)}</b>: ${esc(c.reason)}</div>`, "Nothing cleared.")}</div>
          <div class="sec"><h4>Recommended actions <span class="muted">for human approval</span></h4>
            ${list(r.recommended_actions, (a) => `<div class="rec"><span class="a">${esc(a.action)}</span><span><span class="tg">${esc(a.target)}</span> · ${esc(a.reason)}</span></div>`, "None.")}</div>
          <div class="sec valid"><h4>Validated by code before acceptance</h4>
            <div class="vrow"><span class="ok">✓</span>Schema matches <b>IncidentReport</b></div>
            <div class="vrow"><span class="ok">✓</span>Every fact cites at least one evidence ID</div>
            <div class="vrow"><span class="ok">✓</span>All ${cited.size} cited IDs exist in the database</div></div>
        </div>
      </div>
      ${stats}
    </div>`;
  const lanes = $("#lanes");
  const draw = () => drawLanes(lanes, timeline);
  draw();
  state.redraw = draw;
}

async function showReport(id) {
  if (!id) {
    const done = recent.list().map((r) => state.runs[r.id]).find((r) => r && r.status === "completed");
    id = done ? done.id : (recent.list()[0] || {}).id;
    if (!id) {
      view.innerHTML = emptyState("No report yet", "Run an investigation and its report will appear here.", `<a class="btn ok" href="#/">Start an investigation</a>`);
      return;
    }
  }
  const run = await loadRun(id);
  if (run.status === "running") {
    view.innerHTML = emptyState("Still investigating", "The agent is still gathering evidence. The report appears when it has finished.", `<a class="btn ok" href="#/run/${esc(id)}">Watch it live</a>`);
    return;
  }
  if (run.status === "failed") {
    view.innerHTML = emptyState("The investigation failed", run.error || "", `<a class="btn ok" href="#/">Try again</a>`);
    return;
  }
  renderReport(run);
}

function emptyState(title, text, actions = "") {
  return `<div class="card empty"><h3>${esc(title)}</h3><p>${esc(text)}</p>${actions}</div>`;
}

// ---------------------------------------------------------------- page: approvals

async function renderApprovals(message = "") {
  view.innerHTML = `<header class="page-head"><div class="eyebrow">Human in the loop</div>
      <h1>The agent proposes. <em>A human approves.</em></h1>
      <p>No model can reach the code that executes an action. An approver decides through the API, nobody can approve what their own
        investigation proposed, and every step lands in the audit log.</p></header>
    <div class="card appr" id="appr"><div class="waiting"><span class="spinner"></span>Loading…</div></div>`;
  const box = $("#appr");
  let actions = [], audit = null, signedIn = false, problem = message;
  if (state.key) {
    try {
      actions = await api("/actions", withKey());
      signedIn = true;
      try { audit = await api("/audit?limit=30", withKey()); } catch { audit = null; } // analysts can't read it
    } catch (e) {
      problem = e.status === 401 ? "That API key was not accepted. Showing this browser's investigations instead." : e.message;
    }
  }
  if (!signedIn) {
    const runs = await Promise.all(recent.list().map(async (r) => {
      try { return state.runs[r.id] && state.runs[r.id].status !== "running" ? state.runs[r.id]
        : await api(`/demo-api/investigations/${encodeURIComponent(r.id)}?since=1000000`); } catch { return null; }
    }));
    actions = runs.filter(Boolean).flatMap((run) => (run.proposals || []).map((p) => ({ ...p, investigation_id: run.id })));
  }
  const rows = actions.map((a) => {
    const pending = a.status === "pending";
    const buttons = pending ? `<div class="acts">
        <button class="btn ok sm" data-act="approve" data-id="${a.id}" ${signedIn ? "" : "disabled title=\"Needs an approver key\""}>Approve</button>
        <button class="btn ghost sm" data-act="reject" data-id="${a.id}" ${signedIn ? "" : "disabled title=\"Needs an approver key\""}>Reject</button></div>`
      : `<span class="muted small">${esc(a.decided_by ? `by ${a.decided_by}` : "")}</span>`;
    return `<tr><td><span class="a">${esc(a.action_type)}</span></td><td class="tg">${esc(a.target)}</td>
      <td>${esc(a.justification)}<div class="ids">${idChips(a.evidence)}</div>${a.execution_result ? `<div class="muted small">→ ${esc(a.execution_result)}</div>` : ""}</td>
      <td class="inv"><a href="#/run/${esc(a.investigation_id)}">${esc(a.investigation_id)}</a></td>
      <td><span class="st ${esc(a.status)}">${esc(a.status)}</span></td><td>${buttons}</td></tr>`;
  }).join("");
  box.innerHTML = `
    ${actions.length ? `<div class="table-wrap"><table><thead><tr><th>Action</th><th>Target</th><th>Reason given by the agent</th><th>Investigation</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`
      : `<div class="empty" style="padding:30px"><h3>No proposed actions yet</h3><p>When an investigation finds something worth acting on, such as a compromised account, the agent proposes actions here for a human to decide.</p><a class="btn ok" href="#/">Start an investigation</a></div>`}
    ${problem ? `<div class="notice bad"><b>Not done.</b> ${esc(problem)}</div>` : ""}
    ${signedIn ? `<div class="notice"><b>Separation of duties.</b> You can't approve an action proposed by an investigation you started. The executor re-checks the status itself before running anything.</div>`
      : `<div class="notice"><b>Approving needs an approver key.</b> Without an API key that has the approver role, proposals stay pending:
          by design, nothing on this page can execute an action. The public demo has no approver keys. <button class="linkish" style="color:#c7d2fe;text-decoration:underline" id="appr-sign-in">Sign in with a key</button></div>`}
    ${audit && audit.length ? `<div class="audit"><div class="ev-h">Audit log</div>${audit.map((l) => `<div class="al">
        <span class="t">${esc(new Date(l.at).toISOString().replace("T", " ").slice(0, 19))}</span><span class="who">${esc(l.actor)}</span>
        <span>${esc(l.event)}${l.action_id ? ` · action ${esc(l.action_id)}` : ""}${l.details && l.details.note ? ` · ${esc(l.details.note)}` : ""}</span></div>`).join("")}</div>` : ""}`;
  const signIn = $("#appr-sign-in");
  if (signIn) signIn.addEventListener("click", openKeyDialog);
  box.querySelectorAll("button[data-act]").forEach((b) => b.addEventListener("click", async () => {
    box.querySelectorAll("button[data-act]").forEach((x) => (x.disabled = true));
    let note = "";
    try { await api(`/actions/${b.dataset.id}/${b.dataset.act}`, { method: "POST", body: JSON.stringify({ note: null }), headers: { "X-API-Key": state.key } }); }
    catch (e) { note = e.message; }
    renderApprovals(note);
  }));
  const pending = actions.filter((a) => a.status === "pending").length;
  setPending(pending);
}

function setPending(n) {
  const pill = $("#pending-count");
  pill.hidden = !n;
  pill.textContent = n;
}

function updatePendingCount() {
  const n = Object.values(state.runs).flatMap((r) => r.proposals || []).filter((p) => p.status === "pending").length;
  if (n) setPending(n);
}

// ---------------------------------------------------------------- page: how it works

function renderHow() {
  const repo = state.config && state.config.repo_url;
  view.innerHTML = `
    <header class="page-head"><div class="eyebrow">Architecture</div>
      <h1>The agent decides what should happen. <em>Deterministic software decides what can.</em></h1>
      <p>The same tools are served over HTTP and as an MCP server. Synthetic scenarios with hidden answer keys and decoys measure the agent.</p></header>
    <div class="flow">
      <div class="node user">Analyst<small>HTTP · API key + role</small></div><div class="arrow">→</div>
      <div class="node core"><div class="core-t">Sentinel</div>
        <div class="chips"><span>FastAPI</span><span>Hand-written agent loop</span><span>Narrated traces</span></div>
        <div class="chips"><span>LLM: Claude</span><span>Fallback: Ollama</span><span>Demo: free hosted model</span></div>
        <div class="core-tools"><b>13 tools</b> · 11 read-only including RAG · propose_action · submit_report</div>
        <div class="chips" style="margin:0"><span>Postgres: logs · logins · badges · devices · users</span><span>Qdrant · bge-small embeddings</span></div></div>
      <div class="arrow">←</div><div class="node user">Approver<small>approve / reject</small></div>
    </div>
    <div class="flow2">
      <div class="node mcp">Claude Desktop · Cursor<small>the same tools over MCP (stdio)</small></div>
      <div class="node exec">Executor<small>unreachable by any model · every step audited</small></div>
    </div>
    <h3 class="sec-title">Design principles</h3>
    <div class="principles">
      <div class="card pr"><b>Tools built for a model</b><span>Every tool needs a time range and a limit, reports truncation, returns citable evidence IDs and validates every argument.</span></div>
      <div class="card pr"><b>Output validated by code</b><span>The agent must finish with submit_report. The schema and every cited ID are checked; a report with an invented ID goes back to the model.</span></div>
      <div class="card pr"><b>Untrusted data stays data</b><span>Tool results are treated as data, never instructions. A planted prompt injection in a login's user agent tests it.</span></div>
      <div class="card pr"><b>Model fallback, never for refusals</b><span>Claude first, a local model if Claude is unavailable. A model that declines is never routed around.</span></div>
    </div>
    <h3 class="sec-title">Evaluation scenarios</h3>
    <div class="grid3">
      <div class="card sc"><div class="sc-h"><span class="sev HIGH">INCIDENT</span>INC-001</div>
        <p>A security incident overnight on 30 Sep, spread across logins, badge access, a device and the application logs. One record carries a prompt injection.</p>
        <div class="sc-f">Tests: correlation across 4 sources, injection resistance</div></div>
      <div class="card sc"><div class="sc-h"><span class="sev MEDIUM">OUTAGE</span>INC-002</div>
        <p>Users get 504 errors on the afternoon of 1 Oct. The cause is in the data, next to unrelated errors that look similar.</p>
        <div class="sc-f">Tests: operational root cause, correlation vs coincidence</div></div>
      <div class="card sc"><div class="sc-h"><span class="sev NONE">BENIGN</span>BENIGN-001</div>
        <p>A quiet night with unusual but innocent activity: someone working late, a flaky camera, internet noise.</p>
        <div class="sc-f">Tests: saying "no incident" without false alarms</div></div>
    </div>
    <h3 class="sec-title">Built with</h3>
    <div class="stack"><b>Python 3.12</b><b>FastAPI</b><b>SQLAlchemy</b><b>Postgres</b><b>Qdrant</b><b>Pydantic</b><b>MCP</b><b>Docker</b><b>pytest</b></div>
    <div style="margin-top:30px;display:flex;gap:10px;flex-wrap:wrap">
      ${repo ? `<a class="btn ok" href="${esc(repo)}" target="_blank" rel="noopener">Read the code ↗</a>` : ""}
      <a class="btn ghost" href="/docs" target="_blank" rel="noopener">API documentation ↗</a>
    </div>`;
}

// ---------------------------------------------------------------- router, sidebar, key

async function route() {
  state.live = null;
  state.redraw = null;
  const hash = location.hash || "#/";
  const [, page, id] = hash.match(/^#\/([\w-]*)\/?([\w-]*)/) || [];
  const nav = { "": "investigate", run: "investigate", report: "report", approvals: "approvals", how: "how" }[page] || "investigate";
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("on", a.dataset.nav === nav));
  drawRecent();
  window.scrollTo(0, 0);
  try {
    if (page === "run" && id) {
      const run = await loadRun(id);
      state.live = new TraceView(run);
    } else if (page === "report") await showReport(id);
    else if (page === "approvals") await renderApprovals();
    else if (page === "how") renderHow();
    else renderHome();
  } catch (e) {
    if (e.status === 404 && id) recent.forget(id);
    view.innerHTML = emptyState(e.status === 404 ? "Investigation not found" : "Something went wrong",
      e.status === 404 ? "This server no longer has that investigation (it restarted, or it was started elsewhere)." : e.message,
      `<a class="btn ok" href="#/">Start a new investigation</a>`);
  }
}

function openKeyDialog() {
  if (state.key) { // already signed in: sign out
    state.key = ""; sessionStorage.removeItem("sentinel.key"); drawKeyButton();
    if (location.hash.startsWith("#/approvals")) renderApprovals();
    return;
  }
  const dialog = $("#key-dialog");
  $("#key-input").value = "";
  dialog.showModal();
}

function drawKeyButton() {
  $("#key-button").textContent = state.key ? "Signed in with a key · sign out" : "Approver sign-in";
}

$("#key-button").addEventListener("click", openKeyDialog);
$("#key-dialog").addEventListener("close", () => {
  const dialog = $("#key-dialog"), value = $("#key-input").value.trim();
  if (dialog.returnValue === "save" && value) {
    state.key = value; sessionStorage.setItem("sentinel.key", value); drawKeyButton();
    if (location.hash.startsWith("#/approvals")) renderApprovals(); else location.hash = "#/approvals";
  }
});
window.addEventListener("hashchange", route);
let resizeTimer;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => state.redraw && state.redraw(), 120); });

(async function init() {
  drawKeyButton();
  try {
    state.config = await api("/demo-api/config");
    const m = state.config.models[0];
    $("#model-info").innerHTML = `<span class="dot live"></span><span>${m ? `${esc(m.name)} · <span class="muted">${esc(short(m.model || "default", 28))}</span>` : "no model configured"}</span>`;
    if (state.config.repo_url) { const a = $("#repo-link"); a.href = state.config.repo_url; a.hidden = false; }
  } catch {
    $("#model-info").innerHTML = `<span class="dot" style="background:var(--red)"></span><span>server unreachable</span>`;
  }
  route();
})();
