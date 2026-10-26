// PhishingHUB
document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const $ = id => document.getElementById(id);
  const modes = ['url', 'file', 'imap'];
  let mode = 'url';
  let selectedFile = null;
  let busy = false;
  let worker = null;
  let controller = null;
  let report = null;
  let records = [];
  const MAX_FILE_SIZE = 50 * 1024 * 1024;

  const tabUrl = $('tab-url');
  const tabFile = $('tab-file');
  const tabImap = $('tab-imap');
  const uiUrl = $('ui-url');
  const uiFile = $('ui-file');
  const uiImap = $('ui-imap');
  const dropZone = $('file-drop-zone');
  const fileInput = $('file-input');
  const fileNameDisplay = $('file-name-display');
  const fileSizeDisplay = $('file-size-display');
  const scanBtn = $('scan-btn');
  const cancelBtn = $('cancel-scan');
  const urlInput = $('target-url');
  const resultBox = $('result-box');
  const scanProgress = $('scan-progress');
  const dashboard = $('dashboard');

  const aiMessages = $('ai-messages');
  const aiInput = $('ai-input');
  const aiSend = $('ai-send');
  const aiInclude = $('ai-include');
  const aiContextLine = $('ai-context-line');

  function escapeHtml(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/`/g, '&#96;');
  }

  const VERDICT_META = {
    malicious: { cls: 'v-malicious', sym: '\u25CF' },
    suspicious: { cls: 'v-suspicious', sym: '\u25B2' },
    clean: { cls: 'v-clean', sym: '\u2713' },
    unknown: { cls: 'v-unknown', sym: '?' }
  };
  const VERDICT_TR = { malicious: 'zararli', suspicious: 'süpheli', clean: 'temiz', unknown: 'bilinmiyor' };

  function verdictKey(v) {
    const k = String(v || 'unknown').toLowerCase();
    return VERDICT_META[k] ? k : 'unknown';
  }

  function verdictBadge(v) {
    const k = verdictKey(v);
    const m = VERDICT_META[k];
    return '<span class="verdict ' + m.cls + '" title="' + escapeHtml(VERDICT_TR[k]) + '">' + m.sym + ' ' + escapeHtml(k) + '</span>';
  }

  function boxFor(v) {
    const k = verdictKey(v);
    if (k === 'malicious') return 'error';
    if (k === 'suspicious') return 'warn';
    if (k === 'clean') return 'success';
    return 'info';
  }

  function statusKey(s) {
    const t = String(s || '').toLowerCase();
    if (t.indexOf('malicious') >= 0 || t.indexOf('zarar') >= 0) return 'malicious';
    if (t.indexOf('suspicious') >= 0 || t.indexOf('süpheli') >= 0 || t.indexOf('supheli') >= 0) return 'suspicious';
    if (t.indexOf('clean') >= 0 || t.indexOf('temiz') >= 0 || t.indexOf('tehdit kaydi yok') >= 0 || t.indexOf('kayit yok') >= 0) return 'clean';
    return 'unknown';
  }

  const DOT_COLOR = { malicious: '#a02c22', suspicious: '#8a5f0e', clean: '#2c6735', unknown: '#8b8880' };

  function engineTableHtml(rows) {
    let html = '<table class="eng-table"><tbody>';
    rows.forEach(r => {
      const k = statusKey(r[1]);
      html += '<tr><td><span class="eng-dot" style="background:' + DOT_COLOR[k] + '"></span>' + escapeHtml(r[0]) + '</td>'
        + '<td>' + escapeHtml(r[1] || '-') + '</td></tr>';
    });
    return html + '</tbody></table>';
  }

  function vtBarHtml(stats) {
    stats = stats || {};
    const m = Number(stats.malicious || 0), s = Number(stats.suspicious || 0);
    const c = Number(stats.harmless || 0), u = Number(stats.undetected || 0);
    const total = m + s + c + u;
    if (!total) return '';
    const seg = (v, color) => v > 0
      ? '<div style="width:' + (v / total * 100).toFixed(1) + '%;background:' + color + '"></div>' : '';
    return '<div class="rb-wrap"><div class="rb-track">'
      + seg(m, DOT_COLOR.malicious) + seg(s, DOT_COLOR.suspicious)
      + seg(c, DOT_COLOR.clean) + seg(u, DOT_COLOR.unknown)
      + '</div><div class="rb-label">VT: ' + m + ' zararli / ' + s + ' supheli / ' + c + ' temiz / ' + u + ' bilinmiyor</div></div>';
  }

  function fmtStats(stats) {
    stats = stats || {};
    return 'Zararli=' + escapeHtml(stats.malicious != null ? stats.malicious : 0)
      + ', Suspicious=' + escapeHtml(stats.suspicious != null ? stats.suspicious : 0)
      + ', Temiz=' + escapeHtml(stats.harmless != null ? stats.harmless : 0);
  }

  function defang(s) {
    return String(s).replace(/^https:/i, 'hxxps:').replace(/^http:/i, 'hxxp:').replace(/\./g, '[.]');
  }

  // --- Tab Switching ---
  tabUrl.addEventListener('click', () => { if (busy) return; mode = 'url'; modes.forEach(x => { $('tab-' + x).classList.toggle('active', x === mode); $('ui-' + x).style.display = x === mode ? 'block' : 'none'; }); clearReport(); });
  tabFile.addEventListener('click', () => { if (busy) return; mode = 'file'; modes.forEach(x => { $('tab-' + x).classList.toggle('active', x === mode); $('ui-' + x).style.display = x === mode ? 'block' : 'none'; }); clearReport(); });
  tabImap.addEventListener('click', () => { if (busy) return; mode = 'imap'; modes.forEach(x => { $('tab-' + x).classList.toggle('active', x === mode); $('ui-' + x).style.display = x === mode ? 'block' : 'none'; }); clearReport(); });

  // --- File selection ---
  function setSelectedFile(f) {
    if (!f) return;
    clearReport();
    selectedFile = null;
    if (!f.size) { fileNameDisplay.textContent = 'Bos dosya kabul edilmez'; fileSizeDisplay.textContent = ''; return; }
    if (f.size > MAX_FILE_SIZE) { showFeedback('error', 'Dogrulama Hatasi', 'Dosya çok büyük (limit 50MB).'); fileInput.value = ''; return; }
    selectedFile = f;
    fileNameDisplay.textContent = f.name;
    fileSizeDisplay.textContent = (f.size / 1048576).toFixed(2) + ' MiB · hash cihazda hesaplanacak';
  }

  dropZone.addEventListener('click', () => { if (!busy) fileInput.click(); });
  dropZone.addEventListener('keydown', e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); if (!busy) fileInput.click(); } });
  fileInput.addEventListener('change', e => { if (e.target.files.length > 0) setSelectedFile(e.target.files[0]); });
  ['dragover', 'dragenter'].forEach(ev => dropZone.addEventListener(ev, e => { e.preventDefault(); if (!busy) dropZone.classList.add('dragging'); }));
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
  dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('dragging'); if (e.dataTransfer && e.dataTransfer.files.length > 0) setSelectedFile(e.dataTransfer.files[0]); });

  urlInput.addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); scanBtn.click(); } });

  // --- Copy fallback ---
  function fallbackCopy(val, done) {
    try {
      const ta = document.createElement('textarea');
      ta.value = val;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      done();
    } catch (err) { /* sessiz gec */ }
  }

  function showFeedback(type, title, messageHtml) {
    resultBox.style.display = 'flex';
    resultBox.className = `feedback-box ${type}`;
    let icon = type === 'error'
      ? '<path d="M18 6L6 18M6 6l12 12"></path>'
      : (type === 'warn'
        ? '<line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>'
        : '<polyline points="20 6 9 17 4 12"></polyline>');
    resultBox.innerHTML = ''
      + '<div class="feedback-header">'
      + '<div class="feedback-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + icon + '</svg></div>'
      + '<strong>' + escapeHtml(title) + '</strong>'
      + '</div>'
      + '<div class="feedback-content">' + messageHtml + '</div>';
  }

  function clearReport() {
    report = null;
    records = [];
    dashboard.hidden = true;
    resultBox.style.display = 'none';
    scanProgress.textContent = '';
  }

  function updateAiContextLine() {
    if (!aiContextLine) return;
    if (!report) {
      aiContextLine.textContent = 'Baglam: yok — once bir tarama yap.';
      return;
    }
    if (report.type === 'url') {
      aiContextLine.textContent = 'Baglam: URL ' + (report.url_scanned || '') + ' (' + (VERDICT_TR[verdictKey(report.verdict)] || '') + ')';
    } else if (report.type === 'file') {
      aiContextLine.textContent = 'Baglam: dosya ' + (report.file_hash || '').slice(0, 16) + '…';
    } else if (report.type === 'imap') {
      const n = (report.results || []).length;
      aiContextLine.textContent = 'Baglam: ' + n + ' e-posta taramasi';
    } else {
      aiContextLine.textContent = 'Baglam: ' + report.type;
    }
  }

  // --- API helper ---
  async function api(path, data, signal) {
    const resp = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
      signal
    });
    let value;
    try { value = await resp.json(); } catch { throw new Error('Server gecerli JSON cavabi vermedi. Yeniden deneyin.'); }
    if (!resp.ok) {
      const detail = value.detail;
      throw new Error(typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map(x => x.msg).join('; ') : 'Sorgu red edildi.');
    }
    return value;
  }

  // --- Client-side SHA-256 via Web Worker ---
  function hashFile(file, signal) {
    return new Promise((resolve, reject) => {
      if (!window.Worker) { reject(new Error('Bu tarayici Web Worker desteklemiyor. Guncel bir tarayici kullanin.')); return; }
      worker = new Worker('/static/hash-worker.js');
      let settled = false;
      const finish = (err, value) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', cancel);
        worker?.terminate();
        worker = null;
        err ? reject(err) : resolve(value);
      };
      const cancel = () => finish(new DOMException('Iptal edildi', 'AbortError'));
      signal.addEventListener('abort', cancel, { once: true });
      if (signal.aborted) { cancel(); return; }
      worker.onmessage = e => {
        if (e.data.error) finish(new Error(e.data.error));
        else if (e.data.hash) finish(null, e.data.hash);
        else scanProgress.textContent = 'SHA-256 hesaplaniyor: ' + e.data.progress + '%';
      };
      worker.onerror = () => finish(new Error('Hash hesaplama alinamadi'));
      worker.postMessage({ file });
    });
  }

  const scanBtnOriginalHtml = scanBtn.innerHTML;

  function locking(value) {
    busy = value;
    scanBtn.disabled = value;
    cancelBtn.style.display = value ? 'inline-flex' : 'none';
    fileInput.disabled = value;
    urlInput.disabled = value;
    modes.forEach(m => $('tab-' + m).disabled = value);
    if (value) {
      scanBtn.innerHTML = 'TARAMA DEVAM EDIYOR…<div class="analyze-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg></div>';
    } else {
      scanBtn.innerHTML = scanBtnOriginalHtml;
    }
  }

  cancelBtn.addEventListener('click', () => controller?.abort());

  // --- Flatten report to record rows ---
  function flatten(data) {
    if (!data) return [];
    if (data.type === 'file') return [{ ...data, target: data.filename || data.file_hash }];
    if (data.type === 'url') return (data.results || []).map(r => ({ ...r, target: r.url || r.url_scanned || r.target }));
    const rows = [];
    (data.results || []).forEach(mail => {
      (mail.urls_found || []).forEach(r => rows.push({ ...r, target: r.url, mail_subject: mail.subject }));
      (mail.attachments || []).forEach(a => {
        const vt = a.vt || {};
        const verdict = vt.verdict || 'unknown';
        rows.push({
          target: a.filename, file_hash: a.sha256, file_size: a.size,
          virustotal: vt, verdict, priority: verdict === 'malicious' ? 'high' : verdict === 'suspicious' ? 'medium' : verdict === 'unknown' ? 'needs_data' : 'low',
          findings: [], mail_subject: mail.subject
        });
      });
    });
    return rows;
  }

  function getAiContext() {
    if (!report) return null;
    if (report.type === 'url' && !report.results) return report; // tekli URL
    if (report.type === 'file') return report;
    if (report.type === 'imap') return { ...report, type: 'imap' };
    if (report.type === 'url' && report.results) {
      const first = (report.results || [])[0];
      return {
        type: 'url',
        url_scanned: first ? (first.url || first.url_scanned) : '',
        verdict: first ? first.verdict : 'unknown',
        virustotal: first ? first.virustotal : {},
        urlhaus: first ? first.urlhaus : {},
        abuseipdb: first ? first.abuseipdb : {},
        pulsedive: first ? first.pulsedive : {}
      };
    }
    return report;
  }

  // --- Charts ---
  function drawChart(id, rows) {
    const root = $(id);
    root.replaceChildren();
    const total = rows.reduce((a, r) => a + r[1], 0);
    if (!total) { root.append(document.createTextNode('Grafik icin dogrulanmis bilgi yok.')); return; }
    rows.forEach(([label, n, color]) => {
      const row = document.createElement('div');
      row.className = 'chart-row';
      const track = document.createElement('div');
      track.className = 'chart-track';
      const fill = document.createElement('div');
      fill.style.width = (100 * n / total) + '%';
      fill.style.background = color;
      track.appendChild(fill);
      const lbl = document.createElement('span');
      lbl.textContent = label;
      const num = document.createElement('b');
      num.className = 'chart-number';
      num.textContent = n;
      row.appendChild(lbl);
      row.appendChild(track);
      row.appendChild(num);
      root.appendChild(row);
    });
  }

  function statusText(v) {
    if (!v) return 'Uygulanmiyor';
    return [v.verdict, v.status, v.risk, v.score != null ? 'IP pali: ' + v.score : null].filter(Boolean).join(' · ') || 'Bilinmir';
  }

  // --- Render dashboard ---
  function render() {
    const totals = { malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
    const stats = {};
    records.forEach(r => {
      totals[r.verdict in totals ? r.verdict : 'unknown']++;
      Object.entries(r.virustotal?.stats || r.stats || {}).forEach(([k, v]) => {
        if (Number.isFinite(v) && v > 0) stats[k] = (stats[k] || 0) + v;
      });
    });

    dashboard.hidden = false;
    let meta = 'Tarama saati: ' + new Date(report.checked_at || Date.now()).toLocaleString('tr-TR');
    if (report.type === 'url' && report.duplicates_removed != null) meta += ' · Tekrar cikarildi: ' + report.duplicates_removed;
    if (report.type === 'imap') meta += ' · Mektup: ' + (report.results || []).length;
    $('report-meta').textContent = meta;

    $('report-metrics').replaceChildren();
    [[records.length, 'Yoxlanmis gostergeler'], [totals.malicious, 'Zararli'], [totals.suspicious, 'Supheli'], [totals.unknown, 'Bilinmeyen']].forEach(([n, title]) => {
      const card = document.createElement('div');
      card.className = 'dashboard-metric';
      card.appendChild(document.createElement('b')).textContent = n;
      card.appendChild(document.createElement('span')).textContent = title;
      $('report-metrics').appendChild(card);
    });

    const verdictColors = { malicious: '#a02c22', suspicious: '#8a5f0e', clean: '#2c6735', unknown: '#8b8880' };
    const verdictLabels = { malicious: 'Zararli', suspicious: 'Supheli', clean: 'Temiz', unknown: 'Bilinmeyen' };
    drawChart('verdict-chart', Object.entries(totals).map(([k, n]) => [verdictLabels[k], n, verdictColors[k]]));
    drawChart('engine-chart', [
      ['Zararli', stats.malicious || 0, verdictColors.malicious],
      ['Supheli', stats.suspicious || 0, verdictColors.suspicious],
      ['Tesdetilmedi / bilinmiyor', (stats.undetected || 0), verdictColors.unknown],
      ['Temiz / Harmless', stats.harmless || 0, '#2c6735'],
      ['Hata / diger', ((stats.timeout || 0) + (stats.failure || 0) + (stats['type-unsupported'] || 0) + (stats['confirmed-timeout'] || 0)), verdictColors.unknown]
    ]);

    const priorityLabel = { high: 'Yuksek', medium: 'Orta', needs_data: 'Bilgi Eksik', low: 'Asagi' };
    $('triage-rows').replaceChildren();
    $('findings').replaceChildren();
    records.forEach(r => {
      const tr = document.createElement('tr');
      const tdTarget = document.createElement('td');
      tdTarget.className = 'target-cell';
      tdTarget.textContent = r.target;
      tr.appendChild(tdTarget);
      const tdPr = document.createElement('td');
      tdPr.className = 'priority-' + r.priority;
      tdPr.textContent = priorityLabel[r.priority] || priorityLabel.needs_data;
      tr.appendChild(tdPr);
      const tdVd = document.createElement('td');
      tdVd.textContent = verdictKey(r.verdict);
      tr.appendChild(tdVd);
      [r.virustotal, r.urlhaus, r.abuseipdb, r.pulsedive].forEach(v => {
        const td = document.createElement('td');
        td.textContent = statusText(v);
        if (v) {
          const details = [v.detail, v.error, v.cached ? 'Onbellekten alindi' : null, v.last_analysis_date ? 'Rapor: ' + new Date(v.last_analysis_date * 1000).toLocaleString('tr-TR') : null].filter(Boolean).join(' · ');
          if (details) td.appendChild(document.createElement('small')).textContent = details;
        }
        tr.appendChild(td);
      });
      $('triage-rows').appendChild(tr);

      (r.findings || []).forEach(f => {
        const item = document.createElement('div');
        item.className = 'finding-item';
        const strong = document.createElement('strong');
        strong.textContent = f.code + ' · ' + f.evidence;
        const p1 = document.createElement('p');
        p1.textContent = f.explanation;
        const p2 = document.createElement('p');
        p2.textContent = 'Hedef: ' + r.target + ' · Kaynak: ' + (f.source || 'Lokal kural');
        item.appendChild(strong);
        item.appendChild(p1);
        item.appendChild(p2);
        $('findings').appendChild(item);
      });
    });
    if (!$('findings').children.length) {
      $('findings').appendChild(document.createElement('p')).className = 'empty';
      $('findings').lastElementChild.textContent = 'Lokal kural ila gosterici tapilmadi. Bu, tehlukesizlige garantidir degil.';
    }

    $('next-steps').replaceChildren();
    const steps = ['Süpheli link ve dosyalari acmayin; adresleri defang formatinda paylasin.'];
    if (totals.malicious || totals.suspicious || records.some(r => r.priority === 'medium')) steps.push('Teskilatin DNS, proxy ve e-posta jurnallerinde bu gostergeleri aratin. Tasdiklenmis hedefler icin bloklama kararina teskilat kuralina uygun verin.');
    if (totals.unknown) steps.push('Bilgi eksik hedefleri tehlukesiz saymayin. Kaynak durumlarini kontrol edin; kota bittiyse sonra tekrar edin.');
    steps.push('Sifreler girildiyse, teskilatin hesap guvenligi prosedurunu baslatin. Ortaq hostinq IP-sini elave subut olmadan bloklamayin.');
    steps.forEach((s, i) => {
      const p = document.createElement('p');
      p.className = 'step-item';
      p.textContent = (i + 1) + '. ' + s;
      $('next-steps').appendChild(p);
    });
    if (!records.length) {
      const p = document.createElement('p');
      p.className = 'step-item';
      p.textContent = 'Yoxlanacaq gostergeler tapilamadi; mektubun tehlukesiz oldugu sonucunu cixarmayin.';
      $('next-steps').appendChild(p);
    }
  }

  // --- IOC export ---
  function iocs() {
    const values = new Map();
    const add = (type, value) => { if (value) values.set(type + '|' + value, [type, value]); };
    records.forEach(r => {
      if (r.url) { add('url', r.url); try { add('domain', new URL(r.url).hostname); } catch { } }
      if (r.ip && r.ip !== 'IP Yok') add('ip', r.ip);
      if (r.file_hash) add('sha256', r.file_hash);
    });
    return [...values.values()];
  }

  function download(text, type, name) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function csvCell(s) {
    s = String(s);
    if (/^[=+@\-\t\r\n]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  $('export-json').onclick = () => { if (report) download(JSON.stringify(report, null, 2), 'application/json', 'PhishingHUB-report.json'); };
  $('export-csv').onclick = () => { if (report) download('\uFEFF' + [['type', 'indicator_defanged'], ...iocs().map(([t, v]) => [t, t === 'sha256' ? v : defang(v)])].map(r => r.map(csvCell).join(',')).join('\r\n'), 'text/csv;charset=utf-8', 'PhishingHUB-IOCs.csv'); };
  $('copy-iocs').onclick = async () => {
    try {
      await navigator.clipboard.writeText(iocs().map(([t, v]) => t + ': ' + (t === 'sha256' ? v : defang(v))).join('\n'));
      $('copy-iocs').textContent = 'Kopyalandi';
      setTimeout(() => { $('copy-iocs').textContent = 'IOC Kopyala'; }, 1500);
    } catch { showFeedback('warn', 'Kopyalama izni yok', 'IOC · CSV dugmesini kullanin.'); }
  };
  $('print-report').onclick = () => window.print();

  // --- Live health ---
  const health = $('scan-btn').closest('body').querySelector('.live-status');
  fetch('/health', { signal: AbortSignal.timeout(8000) })
    .then(r => { if (!r.ok) throw Error(); return r.json(); })
    .then(d => {
      health.replaceChildren(document.createElement('div'), document.createTextNode(d.vt_configured ? 'API ACTIVE' : 'API · VT KEY MISSING'));
      health.firstChild.className = 'status-dot';
      health.firstChild.style.background = d.vt_configured ? '#63a66e' : '#c64f44';
    })
    .catch(() => { health.textContent = 'API UNREACHABLE'; });

  // --- Scan submission ---
  scanBtn.addEventListener('click', async () => {
    if (busy) return;
    clearReport();
    const scanMode = mode;
    let urls = [];

    if (scanMode === 'url') {
      urls = urlInput.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      if (!urls.length || urls.length > 10) { showFeedback('error', 'Dogrulama Hatasi', 'Her satirda bir URL olmakla 1–10 adres girin.'); return; }
    }
    if (scanMode === 'file' && !selectedFile) { showFeedback('error', 'Dogrulama Hatasi', 'Once bir dosya secin.'); return; }

    locking(true);
    controller = new AbortController();
    const signal = controller.signal;
    let networkTimer;

    try {
      let data;
      if (scanMode === 'file') {
        const f = selectedFile;
        const digest = await hashFile(f, signal);
        scanProgress.textContent = 'Hash hazir. Mevcut hesap araniyor…';
        networkTimer = setTimeout(() => controller.abort(), 60000);
        data = await api('/analyze/hash', { sha256: digest, file_size: f.size }, signal);
        data.filename = f.name; // Dosya adi tarayicida kalir, sunucuya gitmez
      } else {
        scanProgress.textContent = scanMode === 'imap' ? 'Posta kutusu kontrol ediliyor…' : 'URL ve phishing gostergeleri kontrol ediliyor…';
        networkTimer = setTimeout(() => controller.abort(), 90000);
        if (urls.length === 1) {
          data = await api('/analyze/url', { url: urls[0] }, signal);
          data = { ...data, type: 'url', results: [data] };
        } else {
          data = await api('/analyze/urls', { urls }, signal);
          data.type = 'url';
        }
      }
      report = { ...data, type: scanMode, checked_at: data.checked_at || new Date().toISOString() };
      records = flatten(report);
      render();
      scanProgress.textContent = 'Tarama tamamlandi.';
      if (data.errors?.length) showFeedback('warn', 'Giris uyarilari', data.errors.map(e => e.input + ': ' + e.detail).join('\n'));
      dashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      updateAiContextLine();
      autoAnalyze();
    } catch (e) {
      clearReport();
      showFeedback(e.name === 'AbortError' ? 'error' : 'error', 'Baglanti Hatası', e.name === 'AbortError' ? 'Sorgu iptal edildi veya bekleme suresi doldu. Tamamlanmamis sonuc goruntulenmiyor.' : (e.message || 'Baglanti alinamadi.'));
    } finally {
      clearTimeout(networkTimer);
      worker?.terminate();
      worker = null;
      controller = null;
      locking(false);
    }
  });

  // ================= AI CHAT (MOD-02) =================

  function renderMarkdownLite(text) {
    let t = String(text == null ? '' : text).replace(/^"+|"+$/g, '').trim();
    let h = escapeHtml(t);
    h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    const lines = h.split('\n');
    let out = '', inList = false;
    lines.forEach(ln => {
      const m = ln.match(/^\s*[-•]\s+(.*)$/);
      if (m) {
        if (!inList) { out += '<ul>'; inList = true; }
        out += '<li>' + m[1] + '</li>';
      } else {
        if (inList) { out += '</ul>'; inList = false; }
        if (ln.trim() !== '') out += ln + '<br>';
      }
    });
    if (inList) out += '</ul>';
    return out;
  }

  function scanMiniBars(ctx) {
    if (!ctx) return '';
    try {
      if (ctx.type === 'url') {
        const first = ctx.results ? (ctx.results[0] || {}) : ctx;
        const vt = first.virustotal || {};
        return verdictBadge(first.verdict || ctx.verdict) + vtBarHtml(vt.stats);
      }
      if (ctx.type === 'file') {
        return vtBarHtml(ctx.stats);
      }
      if (ctx.type === 'imap') {
        let html = '';
        (ctx.results || []).slice(0, 5).forEach((m, i) => {
          const first = (m.urls_found && m.urls_found[0]) || null;
          html += '<div>[' + (i + 1) + '] ' + escapeHtml(m.subject || '?') + ' '
            + (first ? verdictBadge(first.verdict) : '<span class="verdict v-unknown">? linksiz</span>') + '</div>';
        });
        return html || 'Mektup yok.';
      }
    } catch (e) { return ''; }
    return '';
  }

  let aiBusy = false;

  async function askAi(text, ctx) {
    const response = await fetch('/analyze/ai-chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, context: ctx || null })
    });
    let data = {};
    try { data = await response.json(); } catch { data = {}; }
    if (!response.ok) {
      let msg = data.detail || 'AI hatasi.';
      if (Array.isArray(msg)) msg = msg.map(d => d.msg || JSON.stringify(d)).join('; ');
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
    return data;
  }

  function addRiskMeter(msgDiv, risk) {
    const p = Math.max(0, Math.min(100, Math.round(Number(risk) || 0)));
    const color = p >= 70 ? '#a02c22' : (p >= 40 ? '#8a5f0e' : '#2c6735');
    const wrap = document.createElement('div');
    wrap.className = 'rb-wrap';
    const track = document.createElement('div');
    track.className = 'rb-track';
    const fill = document.createElement('div');
    fill.style.width = p + '%';
    fill.style.background = color;
    track.appendChild(fill);
    const label = document.createElement('div');
    label.className = 'rb-label';
    label.textContent = 'AI risk skoru: ' + p + '/100';
    wrap.appendChild(track);
    wrap.appendChild(label);
    msgDiv.appendChild(wrap);
    aiMessages.scrollTop = aiMessages.scrollHeight;
  }

  async function autoAnalyze() {
    if (!aiInclude || !aiInclude.checked || aiBusy || !report) return;
    aiBusy = true;
    aiSend.disabled = true;
    const pending = addChatMsg('assistant', 'Otomatik analiz yapiliyor…');
    try {
      const data = await askAi('Bu sonucu kisaca yorumla.', getAiContext());
      pending.innerHTML = renderMarkdownLite(data.reply || '(bos cevap)') + scanMiniBars(getAiContext());
      if (data.risk != null) addRiskMeter(pending, data.risk);
    } catch (e) {
      pending.textContent = 'Otomatik analiz yapilamadi: ' + (e.message || 'hata');
    } finally {
      aiBusy = false;
      aiSend.disabled = false;
      aiMessages.scrollTop = aiMessages.scrollHeight;
    }
  }

  async function sendChat() {
    const text = aiInput.value.trim();
    if (!text || aiSend.disabled || aiBusy) return;
    addChatMsg('user', text);
    aiInput.value = '';
    aiBusy = true;
    aiSend.disabled = true;
    const pending = addChatMsg('assistant', 'Yaziyor…');
    try {
      const data = await askAi(text, (aiInclude && aiInclude.checked) ? getAiContext() : null);
      pending.innerHTML = renderMarkdownLite(data.reply || '(bos cevap)');
      if (data.risk != null) addRiskMeter(pending, data.risk);
    } catch (e) {
      pending.textContent = 'Hata: ' + (e.message || 'AI servisine ulasilamadi.');
    } finally {
      aiBusy = false;
      aiSend.disabled = false;
      aiMessages.scrollTop = aiMessages.scrollHeight;
    }
  }

  function addChatMsg(role, text, md) {
    const sys = aiMessages.querySelector('.ai-msg.system');
    if (sys) sys.remove();
    const div = document.createElement('div');
    div.className = 'ai-msg ' + role;
    if (md) {
      div.innerHTML = renderMarkdownLite(text);
    } else {
      div.textContent = text;
    }
    aiMessages.appendChild(div);
    aiMessages.scrollTop = aiMessages.scrollHeight;
    return div;
  }

  aiSend.addEventListener('click', sendChat);
  aiInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendChat(); });
});
