// PhishingHUB
document.addEventListener('DOMContentLoaded', () => {
            let currentMode = 'url';
            let selectedFile = null;
            const MAX_FILE_SIZE = 50 * 1024 * 1024;

            const tabUrl = document.getElementById('tab-url');
            const tabFile = document.getElementById('tab-file');
            const tabImap = document.getElementById('tab-imap');

            const uiUrl = document.getElementById('ui-url');
            const uiFile = document.getElementById('ui-file');
            const uiImap = document.getElementById('ui-imap');

            const dropZone = document.getElementById('file-drop-zone');
            const fileInput = document.getElementById('file-input');
            const fileNameDisplay = document.getElementById('file-name-display');
            const fileSizeDisplay = document.getElementById('file-size-display');

            const scanBtn = document.getElementById('scan-btn');
            const urlInput = document.getElementById('target-url');
            const resultBox = document.getElementById('result-box');
            let scanContext = null;

            const aiMessages = document.getElementById('ai-messages');
            const aiInput = document.getElementById('ai-input');
            const aiSend = document.getElementById('ai-send');
            const aiInclude = document.getElementById('ai-include');

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
            const VERDICT_TR = { malicious: 'zararl\u0131', suspicious: '\u015F\u00FCpheli', clean: 'temiz', unknown: 'bilinmiyor' };

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

            function fmtStats(stats) {
                stats = stats || {};
                return 'Zararlı=' + escapeHtml(stats.malicious != null ? stats.malicious : 0)
                    + ', Şüpheli=' + escapeHtml(stats.suspicious != null ? stats.suspicious : 0)
                    + ', Temiz=' + escapeHtml(stats.harmless != null ? stats.harmless : 0);
            }

            // --- Tab Switching Logic ---
            tabUrl.addEventListener('click', () => {
                currentMode = 'url';
                tabUrl.classList.add('active');
                tabFile.classList.remove('active');
                tabImap.classList.remove('active');
                uiUrl.style.display = 'block';
                uiFile.style.display = 'none';
                uiImap.style.display = 'none';
                resultBox.style.display = 'none';
            });

            tabFile.addEventListener('click', () => {
                currentMode = 'file';
                tabFile.classList.add('active');
                tabUrl.classList.remove('active');
                tabImap.classList.remove('active');
                uiFile.style.display = 'block';
                uiUrl.style.display = 'none';
                uiImap.style.display = 'none';
                resultBox.style.display = 'none';
            });

            tabImap.addEventListener('click', () => {
                currentMode = 'imap';
                tabImap.classList.add('active');
                tabUrl.classList.remove('active');
                tabFile.classList.remove('active');
                uiImap.style.display = 'block';
                uiUrl.style.display = 'none';
                uiFile.style.display = 'none';
                resultBox.style.display = 'none';
            });

            // --- File Selection Logic ---
            function setSelectedFile(f) {
                if (!f) return;
                if (f.size > MAX_FILE_SIZE) {
                    showFeedback('error', 'Doğrulama Hatası', 'Dosya çok büyük (limit 50MB).');
                    fileInput.value = '';
                    selectedFile = null;
                    return;
                }
                selectedFile = f;
                fileNameDisplay.textContent = selectedFile.name;
                fileSizeDisplay.textContent = (selectedFile.size / (1024 * 1024)).toFixed(2) + ' MB';
            }

            dropZone.addEventListener('click', () => fileInput.click());
            dropZone.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    fileInput.click();
                }
            });
            ['dragenter', 'dragover'].forEach(ev => dropZone.addEventListener(ev, (e) => {
                e.preventDefault();
                dropZone.classList.add('dragging');
            }));
            dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragging');
                if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                    setSelectedFile(e.dataTransfer.files[0]);
                }
            });

            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    setSelectedFile(e.target.files[0]);
                }
            });

            urlInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    scanBtn.click();
                }
            });

            resultBox.addEventListener('click', (e) => {
                const b = e.target.closest ? e.target.closest('[data-copy]') : null;
                if (!b) return;
                const val = b.getAttribute('data-copy') || '';
                const done = () => { b.textContent = 'Kopyalandı'; };
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(val).then(done).catch(() => fallbackCopy(val, done));
                } else {
                    fallbackCopy(val, done);
                }
            });

            function fallbackCopy(val, done) {
                try {
                    const ta = document.createElement('textarea');
                    ta.value = val;
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                    done();
                } catch (err) { /* sessiz geç */ }
            }

            const aiContextLine = document.getElementById('ai-context-line');
            function updateAiContextLine() {
                if (!aiContextLine) return;
                if (!scanContext) {
                    aiContextLine.textContent = 'Bağlam: yok — önce bir tarama yap.';
                    return;
                }
                if (scanContext.type === 'url') {
                    aiContextLine.textContent = 'Bağlam: URL ' + (scanContext.url_scanned || '') + ' (' + (VERDICT_TR[verdictKey(scanContext.verdict)] || '') + ')';
                } else if (scanContext.type === 'file') {
                    aiContextLine.textContent = 'Bağlam: dosya ' + (scanContext.file_hash || '').slice(0, 16) + '…';
                } else if (scanContext.type === 'imap') {
                    const n = (scanContext.results || []).length;
                    aiContextLine.textContent = 'Bağlam: ' + n + ' e-posta taraması';
                }
            }

            function renderUrlResult(data) {
                const vt = data.virustotal || {};
                const uh = data.urlhaus || {};
                const abuse = data.abuseipdb || {};
                const pd = data.pulsedive || {};
                return ''
                    + '<strong>Target:</strong> ' + escapeHtml(data.url_scanned) + '<br>'
                    + '<strong>Verdict:</strong> ' + verdictBadge(data.verdict) + '<br>'
                    + '<strong>VT:</strong> ' + escapeHtml(vt.verdict || vt.status || 'unknown')
                    + ' (' + fmtStats(vt.stats) + ')<br>'
                    + '<strong>VT ID:</strong> ' + escapeHtml(data.vt_analysis_id || vt.analysis_id || 'Yok') + '<br>'
                    + '<strong>URLhaus:</strong> ' + escapeHtml(uh.status || '') + ' - ' + escapeHtml(uh.detail || '') + '<br>'
                    + '<strong>AbuseIPDB (' + escapeHtml(data.ip || abuse.ip || '') + '):</strong> ' + escapeHtml(abuse.status || '') + '<br>'
                    + '<strong>Pulsedive:</strong> ' + escapeHtml(pd.status || pd.risk || '');
            }

            function renderImapResult(data) {
                let html = '<strong>' + escapeHtml(data.message) + '</strong><br><br>';
                if (data.results && data.results.length > 0) {
                    data.results.forEach((item, idx) => {
                        html += '<b>[' + (idx + 1) + '] Konu:</b> ' + escapeHtml(item.subject) + '<br>';
                        html += '<b>Kimden:</b> ' + escapeHtml(item.from) + '<br>';
                        if (item.urls_found && item.urls_found.length > 0) {
                            html += '<b>Bulunan Linkler:</b><br>';
                            item.urls_found.forEach(u => {
                                const vt = u.virustotal || {};
                                html += '&nbsp;&nbsp;- ' + escapeHtml(u.url) + ' ' + verdictBadge(u.verdict)
                                    + ' (URLhaus: ' + escapeHtml((u.urlhaus || {}).status || '') + ', VT: ' + escapeHtml(vt.verdict || vt.status || '') + ')<br>';
                            });
                        } else {
                            html += '&nbsp;&nbsp;- Bağlantı tespit edilmedi.<br>';
                        }
                        if (item.attachments && item.attachments.length > 0) {
                            html += '<b>Ekler:</b><br>';
                            item.attachments.forEach(a => {
                                const vt = a.vt || {};
                                html += '&nbsp;&nbsp;- ' + escapeHtml(a.filename || 'isimsiz')
                                    + ' (' + escapeHtml(a.size != null ? a.size : 0) + ' byte, ' + escapeHtml(a.sha256 || 'hash yok') + ')'
                                    + ' VT: ' + escapeHtml(vt.status || '') + ' ' + escapeHtml(vt.detail || '')
                                    + (vt.stats ? ' (' + fmtStats(vt.stats) + ')' : '') + '<br>';
                            });
                        }
                        html += '<br>';
                    });
                } else {
                    html += 'İşlenecek okunmamış e-posta bulunamadı.';
                }
                return html;
            }

            // --- Submission Logic ---
            scanBtn.addEventListener('click', async () => {
                resultBox.style.display = 'none';

                if (currentMode === 'url' && !urlInput.value.trim()) {
                    showFeedback('error', 'Doğrulama Hatası', 'Geçerli bir hedef URL girin.');
                    return;
                }
                if (currentMode === 'file' && !selectedFile) {
                    showFeedback('error', 'Doğrulama Hatası', 'Akış için bir dosya seçin.');
                    return;
                }
                if (currentMode === 'file' && selectedFile && selectedFile.size > MAX_FILE_SIZE) {
                    showFeedback('error', 'Doğrulama Hatası', 'Dosya çok büyük (limit 50MB).');
                    return;
                }

                scanBtn.disabled = true;
                scanBtn.innerHTML = `ANALYZING...<div class="analyze-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg></div>`;

                try {
                    let response;

                    if (currentMode === 'url') {
                        response = await fetch("/analyze/url", {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ url: urlInput.value.trim() })
                        });
                    } else if (currentMode === 'file') {
                        const formData = new FormData();
                        formData.append('file', selectedFile);
                        response = await fetch("/analyze/file", {
                            method: 'POST',
                            body: formData
                        });
                    } else {
                        response = await fetch("/analyze/imap", {
                            method: 'POST'
                        });
                    }

                    let data = {};
                    try { data = await response.json(); } catch (e) { data = {}; }

                    if (response.ok) {
                        if (currentMode === 'url') {
                            scanContext = Object.assign({ type: 'url' }, data);
                            showFeedback(boxFor(data.verdict), 'Intelligence Scan Complete', renderUrlResult(data));
                        } else if (currentMode === 'file') {
                            scanContext = Object.assign({ type: 'file' }, data);
                            const st = data.stats || null;
                            const fv = st
                                ? (st.malicious > 0 ? 'malicious' : (st.suspicious > 0 ? 'suspicious' : 'clean'))
                                : 'unknown';
                            showFeedback(boxFor(fv), 'Hash Extraction & Analysis Complete', ''
                                + '<strong>Verdict:</strong> ' + verdictBadge(fv) + '<br>'
                                + '<strong>Computed SHA-256:</strong> <span style="font-family: monospace; font-size: 10px;">' + escapeHtml(data.file_hash) + '</span>'
                                + '<button class="copy-btn" data-copy="' + escapeHtml(data.file_hash) + '">Kopyala</button><br>'
                                + '<strong>Status:</strong> ' + escapeHtml(data.message) + '<br>'
                                + '<strong>Action:</strong> ' + escapeHtml(data.action));
                        } else {
                            scanContext = Object.assign({ type: 'imap' }, data);
                            showFeedback('success', 'IMAP Polling Complete', renderImapResult(data));
                        }
                        updateAiContextLine();
                    } else {
                        let msg = data.detail || 'API failure.';
                        if (Array.isArray(msg)) {
                            msg = msg.map(d => (d.loc ? d.loc.join('.') + ': ' : '') + (d.msg || JSON.stringify(d))).join('; ');
                        }
                        showFeedback('error', 'Analysis Rejected', escapeHtml(typeof msg === 'string' ? msg : JSON.stringify(msg)));
                    }
                } catch (error) {
                    showFeedback('error', 'Connection Error', 'Backend service unreachable.');
                } finally {
                    scanBtn.disabled = false;
                    scanBtn.innerHTML = `INITIATE SCAN<div class="analyze-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg></div>`;
                }
            });

            function addChatMsg(role, text) {
                const sys = aiMessages.querySelector('.ai-msg.system');
                if (sys) sys.remove();
                const div = document.createElement('div');
                div.className = 'ai-msg ' + role;
                div.textContent = text;
                aiMessages.appendChild(div);
                aiMessages.scrollTop = aiMessages.scrollHeight;
                return div;
            }

            async function sendChat() {
                const text = aiInput.value.trim();
                if (!text || aiSend.disabled) return;
                addChatMsg('user', text);
                aiInput.value = '';
                aiSend.disabled = true;
                const pending = addChatMsg('assistant', 'Yazıyor...');
                try {
                    const response = await fetch('/analyze/ai-chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            message: text,
                            context: (aiInclude && aiInclude.checked) ? scanContext : null
                        })
                    });
                    let data = {};
                    try { data = await response.json(); } catch (e) { data = {}; }
                    if (response.ok) {
                        pending.textContent = data.reply || '(boş cevap)';
                    } else {
                        let msg = data.detail || 'AI hatası.';
                        if (Array.isArray(msg)) msg = msg.map(d => d.msg || JSON.stringify(d)).join('; ');
                        pending.textContent = 'Hata: ' + msg;
                    }
                } catch (e) {
                    pending.textContent = 'Hata: AI servisine ulaşılamadı.';
                } finally {
                    aiSend.disabled = false;
                    aiMessages.scrollTop = aiMessages.scrollHeight;
                }
            }

            aiSend.addEventListener('click', sendChat);
            aiInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') sendChat();
            });

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
        });
