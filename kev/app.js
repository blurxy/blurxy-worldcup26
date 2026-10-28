// KEV Watch: CISA's Known Exploited Vulnerabilities catalog as an operations board.
// Data: CISA's own GitHub mirror (CORS-enabled), falling back to the bundled snapshot. EPSS from FIRST for visible rows only.
// Every string from a feed is escaped where it enters HTML (esc), vendors travel through attributes URI-encoded,
// and only well-formed http(s) URLs without credentials become links.
(() => {
  'use strict';
  const MIRROR = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
  const SNAPSHOT = 'data/kev-snapshot.json';
  const EPSS_API = 'https://api.first.org/data/v1/epss?cve=';
  const PAGE = 100, SOON = 14, RECENT = 30, KIOSK_PAGE_MS = 15000, EPSS_RETRY_MS = 300000;
  const MIN_PLAUSIBLE = 1000, STALE_DAYS = 21;   // a "live" catalog smaller or older than this is flagged, not trusted silently
  const AUTO_REFRESH_MS = 300000, FOCUS_REFRESH_MS = 120000;   // stay live: re-fetch every 5 min, and on tab focus if idle >2 min

  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const enc = s => esc(encodeURIComponent(s)), dec = s => { try { return decodeURIComponent(s); } catch { return s; } };
  const store = {
    get(k, d, ok = () => true) { try { const v = localStorage.getItem(k); if (v == null) return d; const p = JSON.parse(v); return ok(p) ? p : d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage blocked: lasts for this visit only */ } },
  };
  const isPlain = o => !!o && typeof o === 'object' && !Array.isArray(o);

  // ---------- dates: KEV dates are bare YYYY-MM-DD, counted from the visitor's local midnight ----------
  const DAY = /^\d{4}-\d{2}-\d{2}$/, CVE = /^CVE-\d{4}-\d{4,}$/;
  const parseDay = s => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
  const ymd = t => `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')}`;
  const validDay = s => { if (!DAY.test(s)) return false; const y = +s.slice(0, 4); return y >= 1990 && y <= 2100 && ymd(parseDay(s)) === s; };
  const today = () => { const n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate()); };
  const daysFrom = s => Math.round((parseDay(s) - today()) / 86400000);
  const fmt = s => parseDay(s).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  const fmtDay = s => parseDay(s).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
  const rel = n => n === 0 ? 'today' : n > 0 ? `in ${n} day${n === 1 ? '' : 's'}` : `${-n} day${n === -1 ? '' : 's'} ago`;
  const urgency = d => d.daysDue < 0 ? 'over' : d.daysDue === 0 ? 'u0' : d.daysDue <= 3 ? 'u1' : d.daysDue <= SOON ? 'u2' : '';
  const countdown = n => n === 0 ? 'TODAY' : n > 0 ? `${n}d` : `+${-n}d`;

  let DATA = [], META = {}, BY = new Map(), daysFor = '';
  const follows = new Set(store.get('kev-follows', [], Array.isArray).filter(v => typeof v === 'string'));
  const state = { view: 'due', q: '', vendor: '' };
  let shown = PAGE;

  const VIEWS = [
    ['due', 'Due soon', d => d.daysDue >= 0, (a, b) => a.dueDate.localeCompare(b.dueDate) || b.dateAdded.localeCompare(a.dateAdded)],
    ['added', 'Just added', d => d.daysAdded >= -RECENT, (a, b) => b.dateAdded.localeCompare(a.dateAdded) || a.cveID.localeCompare(b.cveID)],
    ['rw', 'Ransomware', d => d.rw, (a, b) => b.dateAdded.localeCompare(a.dateAdded)],
    ['ft', 'Forensic triage', d => d.ft, (a, b) => b.dateAdded.localeCompare(a.dateAdded)],
    ['follow', '★ Following', d => follows.has(d.vendorProject), (a, b) => b.dateAdded.localeCompare(a.dateAdded)],
    ['all', 'All', () => true, (a, b) => b.dateAdded.localeCompare(a.dateAdded) || b.cveID.localeCompare(a.cveID)],
  ];

  // Day counts are recomputed whenever the local date has changed, so countdowns never go stale past midnight.
  function refreshDays() {
    const t = ymd(today()); if (t === daysFor) return; daysFor = t;
    DATA.forEach(d => { d.daysDue = daysFrom(d.dueDate); d.daysAdded = daysFrom(d.dateAdded); });
  }

  // ---------- load ----------
  const clean = s => s.replace(/\s+/g, ' ').trim();
  function normalize(v) {
    if (!isPlain(v)) return null;
    const s = k => (typeof v[k] === 'string' ? v[k] : '');
    const d = {
      cveID: s('cveID').trim(), vendorProject: clean(s('vendorProject')) || '(unknown vendor)', product: clean(s('product')) || '(unknown product)',
      vulnerabilityName: clean(s('vulnerabilityName')) || '(unnamed)', dateAdded: s('dateAdded'), dueDate: s('dueDate'),
      shortDescription: s('shortDescription'), requiredAction: s('requiredAction'), notes: s('notes'),
      rw: s('knownRansomwareCampaignUse') === 'Known', ft: s('forensicTriage') === 'Yes',
      cwes: Array.isArray(v.cwes) ? v.cwes.filter(c => typeof c === 'string' && /^CWE-\d+$/.test(c)) : [],
    };
    if (!CVE.test(d.cveID) || !validDay(d.dateAdded) || !validDay(d.dueDate)) return null;
    d.k = [d.cveID, d.vendorProject, d.product, d.vulnerabilityName, d.shortDescription].join(' ').toLowerCase();
    return d;
  }
  const reason = e => {
    const m = (e && e.message) || '';
    if (/abort|timed out/i.test(m)) return 'timed out';
    if (/^HTTP \d+/.test(m)) return m;
    if (/json|unexpected token|format|vulnerabilities/i.test(m)) return 'returned data that is not the catalog';
    return 'network error';
  };
  async function getJSON(url, opts, ms) {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), ms);
    try { const r = await fetch(url, { ...opts, signal: ctl.signal }); if (!r.ok) throw new Error('HTTP ' + r.status); return await r.json(); }
    catch (e) { throw new Error(e && e.name === 'AbortError' ? 'timed out' : (e && e.message) || 'unreachable'); }
    finally { clearTimeout(t); }
  }
  const catalog = j => { if (!isPlain(j) || !Array.isArray(j.vulnerabilities)) throw new Error('unexpected format'); return j; };
  function setStatus(kind, html) { const s = $('status'); s.className = 'status' + (kind ? ' ' + kind : ''); s.innerHTML = html; }
  function setPill(text, cls) { $('srcpill').textContent = text; $('srcpill').className = 'pill' + (cls ? ' ' + cls : ''); }
  let loading = false, lastLoad = 0;
  async function load() {
    if (loading) return; loading = true;
    try {
      let json = null, src = 'live', why = '';
      try { json = catalog(await getJSON(MIRROR, { cache: 'no-cache' }, 5000)); }
      catch (e) {
        why = reason(e);
        if (DATA.length && META.src === 'live') {   // a failed refresh never replaces good live data with an older snapshot
          const s = $('status'); s.querySelector('.refail')?.remove();
          s.insertAdjacentHTML('beforeend', `<span class="refail">refresh at ${esc(new Date().toLocaleTimeString(undefined, { timeStyle: 'short' }))} failed (${esc(why)}); still showing the earlier live copy</span>`);
          return;
        }
        src = 'snapshot';
        try { json = catalog(await getJSON(SNAPSHOT, {}, 10000)); }
        catch {
          setPill('offline'); $('controls').hidden = true; $('listhead').hidden = true; $('list').innerHTML = '';
          setStatus('err', 'The catalog could not be loaded from the CISA mirror or the bundled snapshot. <button class="tbtn" id="retry">Try again</button> <span>Or read it at cisa.gov.</span>');
          $('retry').addEventListener('click', () => { setStatus('', 'Loading the catalog…'); setPill('loading'); load(); });
          return;
        }
      }
      const seen = new Set(), rows = [];
      for (const v of json.vulnerabilities) { const d = normalize(v); if (d && !seen.has(d.cveID)) { seen.add(d.cveID); rows.push(d); } }
      DATA = rows; daysFor = ''; refreshDays();
      BY = new Map(DATA.map(d => [d.cveID, d]));
      META = { version: String(json.catalogVersion || '?').slice(0, 40), released: String(json.dateReleased || ''), src, why, dropped: json.vulnerabilities.length - DATA.length };
      const rd = META.released ? new Date(META.released) : null, ok = rd && !isNaN(rd);
      const when = ok ? rd.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '';
      const ageDays = ok ? Math.floor((Date.now() - rd) / 86400000) : null;
      const doubt = src === 'live' && (DATA.length < MIN_PLAUSIBLE || ageDays === null || ageDays > STALE_DAYS);
      setPill(src === 'live' ? (doubt ? 'live?' : 'live') : 'snapshot', src === 'live' && !doubt ? 'live' : 'snap');
      const base = `<span>Catalog ${esc(META.version)}</span>${when ? `<span class="rel">released ${esc(when)}</span>` : ''}<span>${DATA.length.toLocaleString()} entries</span>`
        + (META.dropped ? `<span>${META.dropped.toLocaleString()} malformed or duplicate entries skipped</span>` : '');
      if (src === 'snapshot') setStatus('warn', `${base}<span>The live CISA mirror could not be used (${esc(why)}), so this is the bundled snapshot: newer entries may be missing.</span>`);
      else if (doubt) setStatus('warn', `${base}<span>This live copy looks ${DATA.length < MIN_PLAUSIBLE ? 'incomplete' : 'out of date'}; check cisa.gov before relying on it.</span>`);
      else setStatus('', `${base}<span class="src">loaded live from CISA's mirror</span>`);
      $('controls').hidden = false; $('listhead').hidden = false;
      buildVendors(); render();
    } finally { loading = false; lastLoad = Date.now(); }
  }
  function buildVendors() {
    const counts = new Map(); DATA.forEach(d => counts.set(d.vendorProject, (counts.get(d.vendorProject) || 0) + 1));
    const opts = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    $('vendor').innerHTML = '<option value="">All vendors</option>' + opts.map(([v, c]) => `<option value="${enc(v)}">${esc(v.length > 60 ? v.slice(0, 57) + '…' : v)} (${c})</option>`).join('');
    $('vendor').value = state.vendor ? encodeURIComponent(state.vendor) : '';
  }

  // ---------- list ----------
  const matches = d => { const words = state.q.toLowerCase().split(/\s+/).filter(Boolean); return (!state.vendor || d.vendorProject === state.vendor) && words.every(w => d.k.includes(w)); };
  function filtered() { const view = VIEWS.find(v => v[0] === state.view) || VIEWS[0]; return DATA.filter(d => view[2](d) && matches(d)).sort(view[3]); }
  function chips() {
    $('views').innerHTML = VIEWS.map(([k, label, f]) => `<button class="chip" data-view="${k}" aria-pressed="${k === state.view}">${esc(label)} <span class="ct">${DATA.filter(d => f(d) && matches(d)).length.toLocaleString()}</span></button>`).join('');
    $('viewActs').innerHTML = state.view === 'follow' && follows.size ? '<button class="act" id="icsAll">Export upcoming fix-by dates (.ics)</button>' : '';
  }
  const pct = p => { const v = p * 100; if (v > 0 && v < 0.01) return '<0.01%'; return (v < 9.995 ? v.toFixed(2) : v.toFixed(1)) + '%'; };
  function epssText(cve) {
    const e = EPSS[cve];
    if (e) return `EPSS ${pct(e[0])} · p${Math.round(e[1] * 100)}`;
    return epssDown ? '' : (e === null ? 'EPSS none' : 'EPSS …');
  }
  function row(d) {
    const u = urgency(d), fol = follows.has(d.vendorProject), vp = `${d.vendorProject} · ${d.product}`;
    const tags = (d.rw ? '<span class="tag rw">Ransomware</span>' : '') + (d.ft ? '<span class="tag ft">Forensic triage</span>' : '') + d.cwes.slice(0, 3).map(c => `<span class="tag">${esc(c)}</span>`).join('');
    return `<li class="row ${u}">
      <div class="cd" aria-hidden="true"><b>${esc(countdown(d.daysDue))}</b><small>${esc(fmt(d.dueDate))}</small></div>
      <button class="open" data-cve="${esc(d.cveID)}" aria-haspopup="dialog">
        <span class="sr">${esc(d.daysDue < 0 ? 'Past due ' + rel(d.daysDue) + ', ' : 'Due ' + rel(d.daysDue) + ', ')}</span>
        <span class="l1"><span class="cve">${esc(d.cveID)}</span><span class="vp" title="${esc(vp)}">${esc(vp)}</span></span>
        <span class="vname">${esc(d.vulnerabilityName)}</span>
        ${tags ? `<span class="tags">${tags}</span>` : ''}
      </button>
      <div class="side">
        <span>Added ${esc(fmt(d.dateAdded))}</span>
        <span data-epss="${esc(d.cveID)}">${esc(epssText(d.cveID))}</span>
        <button class="star" data-vendor="${enc(d.vendorProject)}" aria-pressed="${fol}" aria-label="Follow ${esc(d.vendorProject)}" title="${fol ? 'Unfollow' : 'Follow'} ${esc(d.vendorProject)}">★</button>
      </div></li>`;
  }
  function dayHead(d, n) {
    const label = d.daysDue === 0 ? 'Today' : d.daysDue === 1 ? 'Tomorrow' : `In ${d.daysDue} days`;
    return `<li class="dayhead${d.daysDue <= 3 ? ' urgent' : ''}"><b>${esc(label)}</b><span>${esc(fmtDay(d.dueDate))}</span><span class="n">${n} due</span></li>`;
  }
  let LIST = [];
  function rowsHTML(from, to) {
    const page = LIST.slice(from, to);
    if (state.view !== 'due') return page.map(row).join('');
    const perDay = new Map(); LIST.forEach(d => perDay.set(d.dueDate, (perDay.get(d.dueDate) || 0) + 1));
    let html = '';
    page.forEach((d, i) => { const prev = from + i > 0 ? LIST[from + i - 1] : null; if (!prev || prev.dueDate !== d.dueDate) html += dayHead(d, perDay.get(d.dueDate)); html += row(d); });
    return html;
  }
  function render(focusFrom, appendFrom) {
    refreshDays(); chips();
    const view = VIEWS.find(v => v[0] === state.view), filters = state.q || state.vendor;
    if (appendFrom == null) LIST = filtered();
    $('count').textContent = `${LIST.length.toLocaleString()} ${LIST.length === 1 ? 'entry' : 'entries'} · ${view[1].replace('★ ', '')}${state.vendor ? ' · ' + state.vendor : ''}${state.q ? ` · matching "${state.q}"` : ''}`;
    if (!LIST.length) {
      const hint = state.view === 'follow' && !follows.size ? 'You are not following any vendor yet: use ★ on any row.' : 'No entries match.';
      $('list').innerHTML = `<li class="empty">${esc(hint)}${filters ? ' <button class="tbtn" id="reset">Clear search and vendor</button>' : ''}</li>`;
    } else if (appendFrom != null) $('list').insertAdjacentHTML('beforeend', rowsHTML(appendFrom, shown));   // Show more appends; it never rebuilds
    else $('list').innerHTML = rowsHTML(0, shown);
    $('more').hidden = LIST.length <= shown;
    $('more').textContent = `Show ${Math.min(PAGE, LIST.length - shown)} more of ${(LIST.length - shown).toLocaleString()}`;
    if (focusFrom != null) $('list').querySelectorAll('.open')[focusFrom]?.focus();
    loadEpss(LIST.slice(appendFrom ?? 0, shown).map(d => d.cveID));
  }

  // ---------- EPSS (visible rows only, cached per local day, never fetched twice at once) ----------
  const epssKey = () => 'kev-epss-' + ymd(today());
  const validEpss = o => isPlain(o) && Object.values(o).every(v => v === null || (Array.isArray(v) && v.length === 2 && v.every(n => typeof n === 'number')));
  let epssDay = epssKey(), EPSS = store.get(epssDay, {}, validEpss), epssDown = 0;
  const inflight = new Set();
  try { for (let i = localStorage.length - 1; i >= 0; i--) { const k = localStorage.key(i); if (k && k.startsWith('kev-epss-') && k !== epssDay) localStorage.removeItem(k); } } catch { /* ignore */ }
  const num01 = x => { const n = typeof x === 'number' ? x : (typeof x === 'string' && /^\s*\d*\.?\d+(e-?\d+)?\s*$/i.test(x) ? Number(x) : NaN); return Number.isFinite(n) && n >= 0 && n <= 1 ? n : null; };
  function paintEpss() { document.querySelectorAll('[data-epss]').forEach(el => { el.textContent = epssText(el.dataset.epss); }); }
  async function loadEpss(cves) {
    if (epssKey() !== epssDay) { epssDay = epssKey(); EPSS = {}; }   // a new day means new scores
    if (epssDown && Date.now() - epssDown > EPSS_RETRY_MS) { epssDown = 0; $('status').querySelector('.epssnote')?.remove(); }
    paintEpss();
    const need = cves.filter(c => !(c in EPSS) && !inflight.has(c)); if (!need.length || epssDown) return;
    for (let i = 0; i < need.length; i += 100) {
      const chunk = need.slice(i, i + 100); chunk.forEach(c => inflight.add(c));
      try {
        const j = await getJSON(EPSS_API + chunk.join(','), {}, 10000);
        if (!isPlain(j) || !Array.isArray(j.data) || (chunk.length > 5 && !j.data.length)) throw new Error('unexpected EPSS response');
        const got = new Map();
        j.data.forEach(x => { if (!isPlain(x)) return; const p = num01(x.epss), q = num01(x.percentile); if (typeof x.cve === 'string' && p !== null && q !== null) got.set(x.cve, [p, q]); });
        chunk.forEach(c => { EPSS[c] = got.has(c) ? got.get(c) : null; });
      } catch {
        epssDown = Date.now();
        const s = $('status'); if (!s.querySelector('.epssnote')) s.insertAdjacentHTML('beforeend', '<span class="epssnote">EPSS scores unavailable right now</span>');
        break;
      } finally { chunk.forEach(c => inflight.delete(c)); }
    }
    store.set(epssDay, EPSS); paintEpss();
  }

  // ---------- detail ----------
  // Notes mix bare URLs, "Label: URL" and prose, separated by " ; ". Link only well-formed http(s) URLs with no credentials.
  const URLRE = /https?:\/\/?(?:[^\s<>"'()]|\([^\s<>"'()]*\))+/gi;
  function linkify(s) {
    let out = '', last = 0;
    for (const m of s.matchAll(URLRE)) {
      const raw = m[0].replace(/[.,;:]+$/, ''), fixed = raw.replace(/^(https?:)\/(?!\/)/i, '$1//');
      let u = null; try { u = new URL(fixed); } catch { /* not a URL */ }
      out += esc(s.slice(last, m.index));
      if (u && (u.protocol === 'https:' || u.protocol === 'http:') && !u.username && !u.password) {
        const label = (u.host + u.pathname + u.search).replace(/\/$/, '');
        out += `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${esc(label.length > 90 ? label.slice(0, 87) + '…' : label)}</a>`;
      } else out += esc(raw);
      last = m.index + raw.length;
    }
    return out + esc(s.slice(last));
  }
  const noteLinks = notes => notes.split(/\s;\s|;\s+(?=\S)|\s+;/).map(s => s.trim()).filter(Boolean).map(s => `<li>${linkify(s)}</li>`).join('');
  let lastOpen = null, opener = null;
  function openDetail(cve) {
    const d = BY.get(cve); if (!d) return; lastOpen = cve; refreshDays();
    const e = EPSS[cve], fol = follows.has(d.vendorProject), u = urgency(d);
    const facts = `<span class="${u === 'over' ? 'over' : u ? 'due' : ''}">Fix by ${esc(fmt(d.dueDate))} · ${esc(rel(d.daysDue))}</span>`
      + (d.rw ? '<span class="rw">Ransomware: known</span>' : '<span>Ransomware: unknown</span>')
      + (e ? `<span>EPSS ${pct(e[0])} · p${Math.round(e[1] * 100)}</span>` : '');
    $('dlgBody').innerHTML = `<div class="dlg-top"><span class="cve">${esc(d.cveID)}</span><button class="tbtn" id="dClose">Close</button></div>
      <div class="dlg-body">
        <h2 id="dTitle" tabindex="-1">${esc(d.vulnerabilityName)}</h2>
        <div class="facts">${facts}</div>
        <p>${esc(d.shortDescription)}</p>
        <div><div class="blockh">Required action</div><p>${esc(d.requiredAction)}</p></div>
        <dl class="spec">
          <div><dt>Vendor</dt><dd>${esc(d.vendorProject)}</dd></div>
          <div><dt>Product</dt><dd>${esc(d.product)}</dd></div>
          <div><dt>Added</dt><dd>${esc(fmt(d.dateAdded))} (${esc(rel(d.daysAdded))})</dd></div>
          <div><dt>Fix by</dt><dd>${esc(fmt(d.dueDate))} (${esc(rel(d.daysDue))}) · binds US federal civilian agencies</dd></div>
          <div><dt>Ransomware</dt><dd>${d.rw ? 'Known use in ransomware campaigns' : 'Unknown (not known, which is not the same as never)'}</dd></div>
          <div><dt>Forensic triage</dt><dd>${d.ft ? 'Required by BOD 26-04' : 'Not required by BOD 26-04'}</dd></div>
          ${d.cwes.length ? `<div><dt>Weakness</dt><dd>${d.cwes.map(c => `<a href="https://cwe.mitre.org/data/definitions/${esc(c.slice(4))}.html" target="_blank" rel="noopener noreferrer">${esc(c)}</a>`).join(', ')}</dd></div>` : ''}
          <div><dt>EPSS</dt><dd>${e ? `${pct(e[0])} chance of exploitation in the next 30 days (percentile ${Math.round(e[1] * 100)})` : (epssDown ? 'unavailable right now' : 'no score')}</dd></div>
        </dl>
        ${d.notes ? `<div><div class="blockh">References</div><ul class="links">${noteLinks(d.notes)}</ul></div>` : ''}
      </div>
      <div class="acts">
        <a class="pri" href="https://nvd.nist.gov/vuln/detail/${esc(d.cveID)}" target="_blank" rel="noopener noreferrer">NVD ↗</a>
        <button id="dFollow" aria-pressed="${fol}">${fol ? '★ Following ' : '☆ Follow '}${esc(d.vendorProject)}</button>
        <button id="dIcs">Add fix-by date to calendar</button>
      </div>`;
    const dlg = $('dlg'); if (!dlg.open) { opener = document.activeElement; dlg.showModal(); } $('dTitle').focus();
    $('live').textContent = `${d.cveID} details opened`;
  }

  // ---------- calendar (RFC 5545) ----------
  const icsEsc = s => String(s).replace(/\r\n|[\r\n\u2028\u2029\u0085\v\f]/g, '\n').replace(/[\u0000-\u0008\u000e-\u001f\u007f]/g, '')
    .replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\n/g, '\\n');
  const fold = line => {   // lines over 75 octets are folded, counted in UTF-8 bytes, never splitting a character
    const te = new TextEncoder(), out = []; let cur = '', n = 0;
    for (const ch of line) { const b = te.encode(ch).length; if (n + b > (out.length ? 74 : 75)) { out.push(cur); cur = ''; n = 0; } cur += ch; n += b; }
    out.push(cur); return out.join('\r\n ');
  };
  function ics(entries, name) {
    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
    const ev = entries.map(d => {
      const [y, m, dd] = d.dueDate.split('-').map(Number), next = new Date(y, m - 1, dd + 1);   // calendar arithmetic, safe on DST days
      return ['BEGIN:VEVENT', `UID:${d.cveID}@kev.blurxy.net`, `DTSTAMP:${stamp}`, `DTSTART;VALUE=DATE:${d.dueDate.replace(/-/g, '')}`, `DTEND;VALUE=DATE:${ymd(next).replace(/-/g, '')}`,
        `SUMMARY:${icsEsc(`Fix by: ${d.cveID} (${d.vendorProject} ${d.product})`)}`,
        `DESCRIPTION:${icsEsc(`${d.vulnerabilityName}. ${d.requiredAction} CISA KEV due date (binds US federal civilian agencies).`)}`,
        `URL:https://nvd.nist.gov/vuln/detail/${d.cveID}`, 'END:VEVENT'].map(fold).join('\r\n');
    });
    const body = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//blurxy//KEV Watch//EN', 'CALSCALE:GREGORIAN', ...ev, 'END:VCALENDAR'].join('\r\n') + '\r\n';
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([body], { type: 'text/calendar' })); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    $('live').textContent = `Calendar file with ${entries.length} fix-by ${entries.length === 1 ? 'date' : 'dates'} created`;
  }

  // ---------- follows (shared across tabs) ----------
  function syncFollows() { const v = store.get('kev-follows', [], Array.isArray); follows.clear(); v.forEach(x => typeof x === 'string' && follows.add(x)); }
  function toggleFollow(vendor) {
    syncFollows();   // another tab may have changed the list since this one loaded
    if (follows.has(vendor)) follows.delete(vendor); else follows.add(vendor);
    store.set('kev-follows', [...follows]);
    $('live').textContent = `${follows.has(vendor) ? 'Following' : 'Stopped following'} ${vendor}`;
  }
  window.addEventListener('storage', e => { if (e.key === 'kev-follows') { syncFollows(); if (DATA.length) render(); } });

  // ---------- events ----------
  $('viewActs').addEventListener('click', e => {
    const b = e.target.closest('#icsAll'); if (!b) return;
    refreshDays();
    const due = DATA.filter(d => follows.has(d.vendorProject) && d.daysDue >= 0);
    if (due.length) ics(due, 'kev-followed-fix-by-dates.ics');
    else { b.textContent = 'No upcoming fix-by dates for followed vendors'; $('live').textContent = b.textContent; setTimeout(() => { if (b.isConnected) b.textContent = 'Export upcoming fix-by dates (.ics)'; }, 2500); }
  });
  function setView(v, focus) {
    state.view = v; shown = PAGE; store.set('kev-view', v);
    if (location.hash.slice(1) !== v) history.replaceState(null, '', '#' + v);
    render(); if (focus) document.querySelector(`.chip[data-view="${v}"]`)?.focus();
  }
  $('views').addEventListener('click', e => { const b = e.target.closest('.chip[data-view]'); if (b) setView(b.dataset.view, true); });
  window.addEventListener('hashchange', () => { const h = location.hash.slice(1).toLowerCase(); if (VIEWS.some(v => v[0] === h) && h !== state.view && DATA.length) setView(h); });
  let qt; $('q').addEventListener('input', () => { clearTimeout(qt); qt = setTimeout(() => { state.q = $('q').value.trim(); shown = PAGE; render(); }, 150); });
  $('vendor').addEventListener('change', () => { state.vendor = dec($('vendor').value); shown = PAGE; render(); });
  $('more').addEventListener('click', () => { const from = shown; shown += PAGE; render(from, from); });
  $('list').addEventListener('click', e => {
    if (e.target.closest('#reset')) { state.q = ''; state.vendor = ''; $('q').value = ''; $('vendor').value = ''; shown = PAGE; render(); $('q').focus(); return; }
    const s = e.target.closest('.star');
    if (s) { e.stopPropagation(); const idx = [...$('list').querySelectorAll('.star')].indexOf(s); toggleFollow(dec(s.dataset.vendor)); render(); ($('list').querySelectorAll('.star')[idx] || $('q')).focus(); return; }
    const o = e.target.closest('.open'); if (o) openDetail(o.dataset.cve);
  });
  let downOnBackdrop = false;
  $('dlg').addEventListener('pointerdown', e => { downOnBackdrop = e.target === $('dlg'); });
  $('dlg').addEventListener('click', e => {
    const dlg = $('dlg');
    if (e.target === dlg) { if (downOnBackdrop) dlg.close(); return; }   // a drag-select that ends on the backdrop does not close it
    if (e.target.closest('#dClose')) { dlg.close(); return; }
    const d = BY.get(lastOpen); if (!d) return;
    if (e.target.closest('#dFollow')) { toggleFollow(d.vendorProject); openDetail(lastOpen); render(); $('dFollow').focus(); }
    if (e.target.closest('#dIcs')) ics([d], `${d.cveID}-fix-by.ics`);
  });
  $('dlg').addEventListener('close', () => {
    $('live').textContent = 'Details closed';
    let back = opener && opener.isConnected ? opener : $('list').querySelector(`.open[data-cve="${CSS.escape(lastOpen || '')}"]`);
    if (!back) back = $('list').querySelector('.open') || document.querySelector(`.chip[data-view="${state.view}"]`);   // the row left the view
    opener = null; back?.focus();
  });

  // ---------- wall display ----------
  let wake = null, refresher = 0, pager = 0, kioskGen = 0;
  async function lockScreen(gen) {
    try {
      const w = await navigator.wakeLock?.request('screen');
      if (!w) return;
      if (gen !== kioskGen || !document.body.classList.contains('kiosk')) { w.release().catch(() => {}); return; }   // exited while waiting
      wake = w; w.addEventListener('release', () => { if (wake === w) wake = null; });
    } catch { wake = null; }
  }
  function page() {   // advance one screen; back to the top after the last
    const atEnd = window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 4;
    window.scrollTo({ top: atEnd ? 0 : window.scrollY + window.innerHeight * 0.85, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  }
  async function setKiosk(on) {
    const gen = ++kioskGen;
    document.body.classList.toggle('kiosk', on); $('kiosk').setAttribute('aria-pressed', String(on)); $('kiosk').textContent = on ? 'Exit' : 'Wall display';
    clearInterval(refresher); clearInterval(pager); refresher = pager = 0;
    if (on) {
      state.q = ''; state.vendor = ''; $('q').value = ''; $('vendor').value = '';
      state.view = 'due'; store.set('kev-view', 'due'); history.replaceState(null, '', '#due');
      shown = Number.MAX_SAFE_INTEGER; render(); window.scrollTo(0, 0);
      try { await document.documentElement.requestFullscreen?.(); } catch { /* not allowed here: the wall view still works windowed */ }
      if (gen !== kioskGen) return;   // exited while fullscreen was pending
      await lockScreen(gen);
      if (gen !== kioskGen) return;
      pager = setInterval(page, KIOSK_PAGE_MS);   // data refresh is global now (AUTO_REFRESH_MS), runs in every mode
    } else {
      const w = wake; wake = null; try { await w?.release(); } catch { /* already released */ }
      if (document.fullscreenElement) { try { await document.exitFullscreen(); } catch { /* ignore */ } }
      shown = PAGE; render();
    }
  }
  $('kiosk').addEventListener('click', () => setKiosk(!document.body.classList.contains('kiosk')));
  document.addEventListener('fullscreenchange', () => { if (!document.fullscreenElement && document.body.classList.contains('kiosk')) setKiosk(false); });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return;
    if (document.body.classList.contains('kiosk') && !wake) lockScreen(kioskGen);
    if (DATA.length && ymd(today()) !== daysFor) render();   // came back on a new day
    if (Date.now() - lastLoad > FOCUS_REFRESH_MS) load();     // and pull the latest catalog on return
  });
  setInterval(() => { if (DATA.length && ymd(today()) !== daysFor) render(); }, 60000);   // cross midnight while open
  setInterval(() => { if (!document.hidden) load(); }, AUTO_REFRESH_MS);   // keep the live catalog current; skip while the tab is hidden (saves data/battery)

  // ---------- start ----------
  const hv = (location.hash || '').slice(1).toLowerCase(), saved = store.get('kev-view', 'due', v => typeof v === 'string');
  state.view = VIEWS.some(v => v[0] === hv) ? hv : (VIEWS.some(v => v[0] === saved) ? saved : 'due');
  load();
})();
