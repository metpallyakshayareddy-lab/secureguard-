/* =====================================================
   SecureGuard – Frontend Script (Upgraded)
   Connects to Flask Python backend at localhost:5000
   Features: SocketIO alerts, explainable AI reasons,
             batch scan, Gmail inbox scan
   ===================================================== */

// On Vercel, frontend + backend share the same origin → use relative paths.
// For local dev, point at localhost:5000.
const API_BASE = window.location.hostname === 'localhost'
    ? 'http://localhost:5000'
    : '';


// ============================================================
// SOCKET.IO – Real-time phishing alerts
// ============================================================
let socket;
try {
    socket = io(API_BASE, { transports: ['websocket', 'polling'] });

    socket.on('connect', () => {
        console.log('SecureGuard: SocketIO connected ✓');
    });

    socket.on('phishing_alert', (data) => {
        showAlert(
            `⚠️ PHISHING DETECTED — ${data.type}: "${data.content}" (Risk: ${data.risk_score}%)`
        );
    });

    socket.on('disconnect', () => {
        console.log('SecureGuard: SocketIO disconnected');
    });
} catch (e) {
    console.warn('SocketIO not available:', e.message);
}

// ============================================================
// ALERT BANNER
// ============================================================
function showAlert(message) {
    const banner = document.getElementById('alertBanner');
    const text = document.getElementById('alertText');
    if (!banner) return;
    text.textContent = message;
    banner.style.display = 'flex';
    // Auto-dismiss after 8 seconds
    clearTimeout(banner._timer);
    banner._timer = setTimeout(dismissAlert, 8000);
}

function dismissAlert() {
    const banner = document.getElementById('alertBanner');
    if (banner) banner.style.display = 'none';
}

// ============================================================
// SCAN — URL (calls Flask /check_url)
// ============================================================
function scanURL() {
    const input = document.getElementById('urlInput');
    const url = input.value.trim();
    if (!url) {
        input.style.borderColor = 'var(--red)';
        setTimeout(() => { input.style.borderColor = ''; }, 1500);
        return;
    }
    showOverlay();

    fetch(`${API_BASE}/check_url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
    })
        .then(res => res.json())
        .then(data => {
            hideOverlay();
            if (data.error) { alert('Error: ' + data.error); return; }
            renderResult('url', {
                score: data.risk_score,
                prediction: data.prediction,
                indicators: data.reasons || [],
            });
            recordScan('URL', url, data.risk_score, data.prediction, data.reasons || []);
            // Show/hide Report button
            const wrap = document.getElementById('urlReportWrap');
            if (wrap) wrap.style.display = data.prediction === 'phishing' ? 'block' : 'none';
            if (data.prediction === 'phishing') window._lastPhishingUrl = url;
        })
        .catch(() => {
            hideOverlay();
            alert('Cannot connect to backend.\nMake sure you ran:\n  python train.py\n  python app.py');
        });
}

// ============================================================
// SCAN — Email (calls Flask /check_email)
// ============================================================
function scanEmail() {
    const input = document.getElementById('emailInput');
    const text = input.value.trim();
    if (!text || text.length < 5) {
        input.style.borderColor = 'var(--red)';
        setTimeout(() => { input.style.borderColor = ''; }, 1500);
        return;
    }
    showOverlay();

    fetch(`${API_BASE}/check_email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
    })
        .then(res => res.json())
        .then(data => {
            hideOverlay();
            if (data.error) { alert('Error: ' + data.error); return; }
            renderResult('email', {
                score: data.risk_score,
                prediction: data.prediction,
                indicators: data.reasons || [],
            });
            recordScan('Email', text.substring(0, 60) + '…', data.risk_score, data.prediction, data.reasons || []);
        })
        .catch(() => {
            hideOverlay();
            alert('Cannot connect to backend.\nMake sure you ran:\n  python train.py\n  python app.py');
        });
}

// ============================================================
// BATCH SCAN (calls Flask /batch_scan)
// ============================================================
function runBatchScan() {
    const raw = document.getElementById('batchInput').value.trim();
    if (!raw) { alert('Please paste at least one email.'); return; }

    // Split on double blank line
    const emails = raw.split(/\n\s*\n/).map(e => e.trim()).filter(Boolean);
    if (!emails.length) { alert('No valid emails found. Separate them with a blank line.'); return; }

    showOverlay();

    fetch(`${API_BASE}/batch_scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emails }),
    })
        .then(res => res.json())
        .then(data => {
            hideOverlay();
            if (data.error) { alert('Error: ' + data.error); return; }
            renderBatchResults(data.results || []);
        })
        .catch(() => {
            hideOverlay();
            alert('Cannot connect to backend. Is python app.py running?');
        });
}

function renderBatchResults(results) {
    const container = document.getElementById('batchResults');
    if (!results.length) { container.innerHTML = '<p style="color:var(--text-muted)">No results.</p>'; return; }

    const phishCount = results.filter(r => r.prediction === 'phishing').length;

    let html = `<div style="margin-bottom:16px;font-size:0.9rem;color:var(--text-secondary)">
    Scanned <strong>${results.length}</strong> emails —
    <span style="color:#f48fb1;font-weight:600">${phishCount} phishing</span>,
    <span style="color:#7ab8f5;font-weight:600">${results.length - phishCount} safe</span>
  </div>`;

    results.forEach(r => {
        const isPhish = r.prediction === 'phishing';
        const color = isPhish ? '#f48fb1' : '#7ab8f5';
        const icon = isPhish ? '⚠️' : '✅';
        const reasons = (r.reasons || []).map(rr =>
            `<span class="indicator-tag ${rr.level}">${escHtml(rr.text)}</span>`
        ).join(' ');

        html += `
      <div style="border:1px solid ${isPhish ? 'rgba(244,143,177,0.35)' : 'rgba(122,184,245,0.35)'};
                  background:${isPhish ? 'rgba(244,143,177,0.06)' : 'rgba(122,184,245,0.06)'};
                  border-radius:var(--radius-sm);padding:14px 16px;margin-bottom:12px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <span>${icon}</span>
          <span style="font-weight:600;color:${color}">#${r.index} — ${r.prediction.toUpperCase()}</span>
          <span style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--text-muted)">
            Risk: ${r.risk_score}%
          </span>
        </div>
        <p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:8px;font-family:'JetBrains Mono',monospace">
          ${escHtml(r.preview || '')}
        </p>
        <div class="indicators">${reasons}</div>
      </div>`;
    });

    container.innerHTML = html;
}

// ============================================================
// GMAIL – OAuth Connect / Status / Scan (localStorage token)
// ============================================================

const GMAIL_TOKEN_KEY = 'secureguard_gmail_token';

function gmailToken() {
    return localStorage.getItem(GMAIL_TOKEN_KEY);
}

function gmailHeaders() {
    const t = gmailToken();
    return t ? { 'X-Gmail-Token': t } : {};
}

function checkGmailStatus() {
    const dot = document.getElementById('gmailStatusDot');
    const text = document.getElementById('gmailStatusText');
    const connectBtn = document.getElementById('gmailConnectBtn');
    const disconnectBtn = document.getElementById('gmailDisconnectBtn');
    const controls = document.getElementById('gmailScanControls');

    const connected = !!gmailToken();
    if (connected) {
        if (dot) dot.style.background = '#7ab8f5';
        if (text) text.textContent = '✓ Gmail connected — ready to scan';
        if (connectBtn) connectBtn.style.display = 'none';
        if (disconnectBtn) disconnectBtn.style.display = 'inline-block';
        if (controls) controls.style.display = 'flex';
    } else {
        if (dot) dot.style.background = '#ccc';
        if (text) text.textContent = 'Not connected — click Connect Gmail to link your account';
        if (connectBtn) connectBtn.style.display = 'inline-block';
        if (disconnectBtn) disconnectBtn.style.display = 'none';
        if (controls) controls.style.display = 'none';
    }
}

function connectGmail() {
    const popup = window.open(
        `${API_BASE}/auth/login`,
        'Gmail Login',
        'width=520,height=620,left=300,top=150'
    );

    // Listen for the token sent via postMessage from the callback page
    window.addEventListener('message', function onMsg(e) {
        if (e.data && e.data.type === 'gmail_auth_done') {
            window.removeEventListener('message', onMsg);
            if (popup && !popup.closed) popup.close();
            // Store token in localStorage
            localStorage.setItem(GMAIL_TOKEN_KEY, e.data.token);
            checkGmailStatus();
        }
    });

    // Fallback poll if postMessage doesn't fire
    const poll = setInterval(() => {
        if (popup && popup.closed) {
            clearInterval(poll);
            checkGmailStatus();
        }
    }, 1000);
}

function disconnectGmail() {
    localStorage.removeItem(GMAIL_TOKEN_KEY);
    const resultsEl = document.getElementById('gmailResults');
    if (resultsEl) resultsEl.innerHTML = '';
    checkGmailStatus();
}

function scanGmailInbox() {
    const count = document.getElementById('gmailCount').value;
    const resultsEl = document.getElementById('gmailResults');

    if (!gmailToken()) {
        resultsEl.innerHTML = '<p style="color:#f48fb1;font-size:0.85rem">Please click <strong>Connect Gmail</strong> first.</p>';
        return;
    }

    resultsEl.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem">Fetching emails…</p>';

    fetch(`${API_BASE}/scan_inbox?max=${count}`, {
        headers: gmailHeaders()
    })
        .then(res => res.json())
        .then(data => {
            if (data.needs_login || data.error) {
                // Token may be expired — clear it
                if (data.needs_login) {
                    localStorage.removeItem(GMAIL_TOKEN_KEY);
                    checkGmailStatus();
                }
                resultsEl.innerHTML = `<p style="color:#f48fb1;font-size:0.85rem">
                    ${data.error || 'Session expired.'} Please reconnect Gmail.
                </p>`;
                return;
            }
            const emails = data.emails || [];
            renderGmailResults(emails);
            // Feed results into Dashboard stats + scan history
            emails.forEach(e => {
                recordScan(
                    'Email',
                    `${e.from}: ${e.subject}`,
                    e.risk_score,
                    e.prediction
                );
            });

        })
        .catch(() => {
            resultsEl.innerHTML = '<p style="color:#f48fb1;font-size:0.85rem">Cannot connect to backend. Is python app.py running?</p>';
        });
}


function renderGmailResults(emails) {
    const container = document.getElementById('gmailResults');
    if (!emails.length) { container.innerHTML = '<p style="color:var(--text-muted)">No unread emails found.</p>'; return; }

    const phishCount = emails.filter(e => e.prediction === 'phishing').length;

    let html = `<div class="table-wrap"><table>
    <thead><tr>
      <th>From</th><th>Subject</th><th>Risk</th><th>Result</th><th>Links</th>
    </tr></thead><tbody>`;

    emails.forEach(e => {
        const isPhish = e.prediction === 'phishing';
        html += `<tr>
      <td title="${escHtml(e.from)}">${escHtml(e.from.substring(0, 30))}</td>
      <td title="${escHtml(e.subject)}">${escHtml(e.subject.substring(0, 40))}</td>
      <td style="font-family:'JetBrains Mono',monospace">${e.risk_score}%</td>
      <td class="${isPhish ? 'badge-phishing' : 'badge-safe'}">${isPhish ? '⚠ PHISHING' : '✓ SAFE'}</td>
      <td>${e.links_found}</td>
    </tr>`;
    });

    html += `</tbody></table></div>
    <p style="margin-top:12px;font-size:0.8rem;color:var(--text-muted)">
      ${emails.length} emails scanned — ${phishCount} potential phishing found.
    </p>`;

    container.innerHTML = html;
}

// ============================================================
// RENDER RESULT PANEL (URL + Email scanners)
// ============================================================
function renderResult(type, result) {
    const panel = document.getElementById(`${type}Result`);
    const badge = document.getElementById(`${type}Badge`);
    const label = document.getElementById(`${type}Label`);
    const pct = document.getElementById(`${type}RiskPct`);
    const bar = document.getElementById(`${type}RiskBar`);
    const inds = document.getElementById(`${type}Indicators`);
    const isPhish = result.prediction === 'phishing';

    panel.style.display = 'block';
    panel.style.borderColor = isPhish ? 'rgba(244,143,177,0.4)' : 'rgba(122,184,245,0.4)';

    badge.textContent = isPhish ? '⚠️' : '✅';
    badge.className = `result-badge ${isPhish ? 'phish-badge' : 'safe-badge'}`;

    label.textContent = isPhish
        ? '⚠️ PHISHING DETECTED — High Risk'
        : '✅ SAFE — No Significant Threats';
    label.className = `result-label ${isPhish ? 'phish-label' : 'safe-label'}`;

    pct.textContent = `${result.score}%`;

    bar.style.width = '0%';
    bar.className = 'risk-bar-fill ' + (result.score >= 60 ? 'phish-bar' : result.score >= 30 ? 'medium-bar' : 'safe-bar');
    setTimeout(() => { bar.style.width = `${result.score}%`; }, 50);

    inds.innerHTML = (result.indicators || [])
        .map(i => `<span class="indicator-tag ${i.level}">${escHtml(i.text)}</span>`)
        .join('');
}

// ============================================================
// SCAN HISTORY & STATS  (persisted in localStorage)
// ============================================================
const HISTORY_KEY = 'secureguard_history';

function loadState() {
    try {
        const saved = localStorage.getItem(HISTORY_KEY);
        if (saved) return JSON.parse(saved);
    } catch (e) { }
    return { safeCount: 0, phishingCount: 0, history: [] };
}

function saveState() {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(state)); } catch (e) { }
}

const state = loadState();

function recordScan(type, content, score, prediction, indicators) {
    if (prediction === 'phishing') state.phishingCount++;
    else state.safeCount++;

    state.history.unshift({
        type, content, score, prediction,
        indicators: indicators || [],
        ts: new Date().toLocaleTimeString(),
        date: new Date().toLocaleDateString(),
    });
    if (state.history.length > 50) state.history.pop();

    saveState();
    updateStats();
    renderTable();
    addToTicker(type, content, score, prediction);
}

function renderTable() {
    const tbody = document.getElementById('scanTableBody');
    if (!state.history.length) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No scans yet — run a URL or Email scan to see results here.</td></tr>';
        return;
    }
    tbody.innerHTML = state.history.map((h, i) => {
        const p = h.prediction === 'phishing';
        return `<tr>
      <td>${state.history.length - i}</td>
      <td>${h.type === 'URL' ? '🔗 URL' : '📧 Email'}</td>
      <td title="${escHtml(h.content)}">${escHtml(h.content.substring(0, 40))}…</td>
      <td style="color:${p ? '#f48fb1' : '#7ab8f5'}">${h.score}%</td>
      <td class="${p ? 'badge-phishing' : 'badge-safe'}">${p ? '⚠ PHISHING' : '✓ SAFE'}</td>
      <td>${h.ts}</td>
    </tr>`;
    }).join('');
}

function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function updateStats() {
    const total = state.safeCount + state.phishingCount;
    animateCount('statSafe', state.safeCount);
    animateCount('statPhishing', state.phishingCount);
    animateCount('statTotal', total);
    const rate = total > 0 ? Math.round((state.phishingCount / total) * 100) : 0;
    document.getElementById('statRate').textContent = `${rate}%`;
    updateCharts();
}

function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let v = parseInt(el.textContent) || 0;
    const step = Math.max(1, Math.ceil(Math.abs(target - v) / 12));
    const timer = setInterval(() => {
        v = v < target ? Math.min(v + step, target) : Math.max(v - step, target);
        el.textContent = v;
        if (v === target) clearInterval(timer);
    }, 40);
}

function clearHistory() {
    state.history = [];
    state.safeCount = 0;
    state.phishingCount = 0;
    saveState();
    renderTable();

    updateStats();
}

// ============================================================
// NAVIGATION
// ============================================================
const TITLES = {
    'dashboard': { title: 'Dashboard Overview', sub: 'Real-time threat monitoring' },
    'url-scanner': { title: 'URL Scanner', sub: 'AI-powered URL phishing analysis' },
    'email-scanner': { title: 'Email Scanner', sub: 'Detect phishing attempts in emails' },
    'gmail-scan': { title: 'Gmail Inbox Scanner', sub: 'Automatically analyse your inbox' },
    'qr-scanner': { title: 'QR Code Scanner', sub: 'Decode QR codes and scan for phishing' },
    'trainer': { title: 'Phishing Trainer', sub: 'Test your ability to spot phishing emails' },
};

function showSection(id, navEl) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const target = document.getElementById(`section-${id}`);
    if (target) target.classList.add('active');
    if (navEl) navEl.classList.add('active');
    const info = TITLES[id] || {};
    document.getElementById('pageTitle').textContent = info.title || 'Dashboard';
    document.getElementById('pageSubtitle').textContent = info.sub || '';
    document.getElementById('sidebar').classList.remove('open');
    return false;
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
}

// ============================================================
// OVERLAY
// ============================================================
function showOverlay() { document.getElementById('scanOverlay').classList.add('active'); }
function hideOverlay() { document.getElementById('scanOverlay').classList.remove('active'); }

// ============================================================
// EXAMPLE BUTTONS
// ============================================================
function tryURL(url) {
    showSection('url-scanner', document.getElementById('nav-url'));
    document.getElementById('urlInput').value = url;
    setTimeout(scanURL, 200);
}

function tryEmail(text) {
    showSection('email-scanner', document.getElementById('nav-email'));
    document.getElementById('emailInput').value = text;
    setTimeout(scanEmail, 200);
}

// ============================================================
// CHARTS – Dashboard only (doughnut + line)
// ============================================================
const charts = {};

function initCharts() {
    const gridColor = 'rgba(100,120,200,0.08)';
    const tickColor = '#8a9ab8';
    const base = {
        responsive: true,
        plugins: { legend: { labels: { color: '#4a5a80', font: { family: 'Inter', size: 12 } } } },
    };

    // Dashboard doughnut — safe vs phishing breakdown
    charts.doughnut = new Chart(document.getElementById('doughnutChart'), {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Phishing'],
            datasets: [{ data: [0, 0], backgroundColor: ['rgba(122,184,245,0.80)', 'rgba(244,143,177,0.80)'], borderColor: ['#7ab8f5', '#f48fb1'], borderWidth: 2, hoverOffset: 6 }],
        },
        options: { ...base, cutout: '70%', plugins: { legend: { display: false } } },
    });

    // Last 7 scans line chart
    charts.line = new Chart(document.getElementById('lineChart'), {
        type: 'line',
        data: {
            labels: ['1', '2', '3', '4', '5', '6', '7'],
            datasets: [
                { label: 'Safe', data: [0, 0, 0, 0, 0, 0, 0], borderColor: '#7ab8f5', backgroundColor: 'rgba(122,184,245,0.10)', fill: true, tension: 0.4, pointBackgroundColor: '#7ab8f5', pointRadius: 4 },
                { label: 'Phishing', data: [0, 0, 0, 0, 0, 0, 0], borderColor: '#f48fb1', backgroundColor: 'rgba(244,143,177,0.08)', fill: true, tension: 0.4, pointBackgroundColor: '#f48fb1', pointRadius: 4 },
            ],
        },
        options: { ...base, scales: { x: { grid: { color: gridColor }, ticks: { color: tickColor } }, y: { grid: { color: gridColor }, ticks: { color: tickColor }, beginAtZero: true } } },
    });

    updateCharts();
}

function updateCharts() {
    const last7 = [...state.history].slice(0, 7).reverse();
    const lineLabels = last7.map((_, i) => `#${i + 1}`);
    const lineSafe = last7.map(h => h.prediction !== 'phishing' ? 1 : 0);
    const linePhish = last7.map(h => h.prediction === 'phishing' ? 1 : 0);

    // ── Update each chart ───────────────────────────────────────
    if (charts.doughnut) {
        charts.doughnut.data.datasets[0].data = [state.safeCount, state.phishingCount];
        charts.doughnut.update();
    }
    if (charts.line) {
        charts.line.data.labels = lineLabels;
        charts.line.data.datasets[0].data = lineSafe;
        charts.line.data.datasets[1].data = linePhish;
        charts.line.update();
    }
}



// ============================================================
// LIVE CLOCK
// ============================================================
function updateClock() {
    const el = document.getElementById('liveTime');
    if (el) el.textContent = new Date().toLocaleTimeString([], { hour12: false });
}

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    updateClock();
    setInterval(updateClock, 1000);
    checkGmailStatus();   // Check Gmail auth state on load
    updateStats();        // Restore saved stat counts
    renderTable();        // Restore saved scan history
    startTrainer();       // Init phishing trainer

    document.getElementById('urlInput').addEventListener('keydown', e => {
        if (e.key === 'Enter') scanURL();
    });

    document.addEventListener('click', e => {
        const sidebar = document.getElementById('sidebar');
        const hamburger = document.getElementById('hamburger');
        if (sidebar && sidebar.classList.contains('open') &&
            !sidebar.contains(e.target) &&
            hamburger && !hamburger.contains(e.target)) {
            sidebar.classList.remove('open');
        }
    });
});

// ============================================================
// FEATURE 1 – LIVE FEED TICKER
// ============================================================
const tickerItems = [];

function addToTicker(type, content, score, prediction) {
    const isPhish = prediction === 'phishing';
    const icon = type === 'URL' ? '🔗' : '📧';
    const preview = String(content).substring(0, 55);
    const item = { type, icon, preview, score, isPhish, ts: new Date().toLocaleTimeString() };
    tickerItems.unshift(item);
    if (tickerItems.length > 30) tickerItems.pop();
    renderTicker();
}

function renderTicker() {
    const inner = document.getElementById('tickerInner');
    if (!inner) return;

    // Build items × 2 so animation loops seamlessly
    const html = [...tickerItems, ...tickerItems].map(it => `
        <span class="ticker-item">
            <span class="ticker-dot ${it.isPhish ? 'phish' : 'safe'}"></span>
            ${it.icon} ${escHtml(it.preview)}
            <span style="color:${it.isPhish ? '#f48fb1' : '#7ab8f5'};font-weight:600">
                ${it.isPhish ? '⚠ PHISH' : '✓ SAFE'} (${it.score}%)
            </span>
            &nbsp;•&nbsp;
        </span>
    `).join('');

    inner.innerHTML = html;
    // Reset animation duration proportional to item count
    inner.style.animationDuration = `${Math.max(15, tickerItems.length * 4)}s`;
}

// ============================================================
// FEATURE 3 – REPORT TO GOOGLE SAFE BROWSING
// ============================================================
function reportToGoogle() {
    const url = window._lastPhishingUrl || '';
    if (!url) { alert('No phishing URL to report.'); return; }
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`;
    window.open(reportUrl, '_blank');

    // Show confirmation
    const confirm = document.getElementById('urlReportConfirm');
    if (confirm) {
        confirm.style.display = 'inline';
        setTimeout(() => { confirm.style.display = 'none'; }, 4000);
    }
}

// ============================================================
// FEATURE 4 – QR CODE SCANNER
// ============================================================
let _qrExtractedUrl = '';

function handleQRDrop(event) {
    event.preventDefault();
    document.getElementById('qrDropZone').classList.remove('drag-over');
    const file = event.dataTransfer.files[0];
    if (file) processQRFile(file);
}

function handleQRUpload(event) {
    const file = event.target.files[0];
    if (file) processQRFile(file);
}

function processQRFile(file) {
    const reader = new FileReader();
    reader.onload = function (e) {
        const img = new Image();
        img.onload = function () {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);

            // Always show the uploaded image
            const previewArea = document.getElementById('qrPreviewArea');
            previewArea.innerHTML = `<img src="${e.target.result}" class="qr-preview-img" alt="QR Preview" />`;

            const extracted = document.getElementById('qrExtracted');
            const extractedEl = document.getElementById('qrExtractedUrl');
            const qrResult = document.getElementById('qrResult');
            qrResult.style.display = 'none';
            _qrExtractedUrl = '';

            if (!code) {
                extracted.style.display = 'none';
                alert('No QR code detected in this image. Try a clearer photo.');
                return;
            }

            const data = code.data.trim();
            _qrExtractedUrl = data;

            // ── Classify the QR payload ──────────────────────────
            if (data.toLowerCase().startsWith('upi://')) {
                // UPI payment link — show info panel, skip phishing model
                _qrExtractedUrl = '';   // prevent scanQRUrl from firing on stale value
                extracted.style.display = 'block';
                extractedEl.innerHTML = `<span style="color:#5b9ee8;margin-right:8px">💳</span>${escHtml(data)}`;

                qrResult.style.display = 'block';
                qrResult.innerHTML = `
                    <div class="result-header">
                        <div class="result-badge safe-badge" style="font-size:1.3rem">💳</div>
                        <span class="result-label safe-label">UPI Payment QR Code Detected</span>
                    </div>
                    <p style="font-size:0.83rem;color:var(--text-secondary);margin-top:8px">
                        This QR code contains a <strong>UPI payment link</strong> and is not a website URL.
                        It has not been sent to the phishing detection model.
                        Always verify the payee name before completing any payment.
                    </p>`;

                // Remove old scan button if it exists
                const btn = extracted.querySelector('.scan-btn');
                if (btn) btn.style.display = 'none';

            } else if (data.startsWith('http://') || data.startsWith('https://')) {
                // Web URL — send to phishing detection model
                extracted.style.display = 'block';
                extractedEl.innerHTML = `<span style="color:var(--cyan);margin-right:8px">🔗</span>${escHtml(data)}`;

                // Ensure Scan button is visible
                const btn = extracted.querySelector('.scan-btn');
                if (btn) btn.style.display = '';

            } else {
                // Unknown / plain text / other protocols
                _qrExtractedUrl = '';
                extracted.style.display = 'block';
                extractedEl.innerHTML = `<span style="color:#e8a84a;margin-right:8px">⚠️</span>${escHtml(data)}`;

                qrResult.style.display = 'block';
                qrResult.innerHTML = `
                    <div class="result-header">
                        <div class="result-badge" style="background:rgba(232,168,74,0.12);border:1px solid rgba(232,168,74,0.4);font-size:1.1rem">⚠️</div>
                        <span class="result-label" style="color:#c4831a">Unknown QR Format</span>
                    </div>
                    <p style="font-size:0.83rem;color:var(--text-secondary);margin-top:8px">
                        This QR code does not contain a standard web URL or UPI payment link.
                        It may contain plain text, a contact card, Wi-Fi credentials, or another format.
                        No phishing scan performed.
                    </p>`;

                const btn = extracted.querySelector('.scan-btn');
                if (btn) btn.style.display = 'none';
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function scanQRUrl() {
    const url = _qrExtractedUrl;
    // Guard: only http/https URLs should reach here
    if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) return;

    showOverlay();
    fetch(`${API_BASE}/check_url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
    })
        .then(r => r.json())
        .then(data => {
            hideOverlay();
            if (data.error) { alert('Error: ' + data.error); return; }
            renderResult('qr', {
                score: data.risk_score,
                prediction: data.prediction,
                indicators: data.reasons || [],
            });
            recordScan('URL', url, data.risk_score, data.prediction, data.reasons || []);
        })
        .catch(() => { hideOverlay(); alert('Cannot connect to backend.'); });
}


// ============================================================
// FEATURE 5 – PHISHING SIMULATION TRAINER
// ============================================================
const TRAINER_DATASET = [
    {
        from: 'security-alert@paypa1.com', subject: 'Your account has been suspended!',
        body: 'Dear Customer,\n\nYour PayPal account has been SUSPENDED due to suspicious activity.\nYou must verify your account IMMEDIATELY to avoid permanent closure.\n\nClick here to verify: http://paypa1-secure.xyz/verify\n\nThis is your FINAL WARNING. Act now.',
        answer: 'phishing',
        explanation: 'Fake sender domain (paypa1 not paypal), urgent language, suspicious link to .xyz domain.'
    },
    {
        from: 'newsletter@github.com', subject: 'Your GitHub monthly digest — March 2026',
        body: 'Hi there,\n\nHere is your monthly GitHub digest for March 2026.\n\n• 3 new pull requests on your repos\n• 12 new stars on secureguard\n• 2 new followers\n\nView your dashboard: https://github.com/dashboard\n\nUnsubscribe anytime.',
        answer: 'safe',
        explanation: 'Legitimate sender domain, no urgent language, real GitHub link, unsubscribe option present.'
    },
    {
        from: 'noreply@amazon-support-billing.net', subject: 'ACTION REQUIRED: Update your payment method',
        body: 'Dear Valued Customer,\n\nYour Amazon order #112-8734561 cannot be shipped because your payment method has FAILED.\n\nPlease update your credit card details within 24 HOURS or your account will be CLOSED:\nhttp://amaz0n-billing.net/update-payment\n\nAmazon Customer Service',
        answer: 'phishing',
        explanation: 'Fake domain (not amazon.com), urgency tactics, fake Amazon link redirecting to amaz0n-billing.net.'
    },
    {
        from: 'no-reply@accounts.google.com', subject: 'Security alert: New sign-in on Windows',
        body: 'Hi,\n\nWe noticed a new sign-in to your Google Account.\n\nWindows, Chrome · India\n\nIf this was you, you don\'t need to do anything.\n\nIf you don\'t recognize this sign-in, check your account activity:\nhttps://myaccount.google.com/notifications\n\n– The Google Accounts team',
        answer: 'safe',
        explanation: 'Sent from accounts.google.com, no urgent demands, links only to myaccount.google.com.'
    },
    {
        from: 'lottery-claim@intl-prize-winner.org', subject: 'You are our LUCKY WINNER! Claim $500,000 NOW',
        body: 'Dear Winner,\n\nCongratulations! You have been selected as our LUCKY WINNER of $500,000 USD in the International Online Lottery.\n\nTo CLAIM YOUR PRIZE, reply with:\n- Full name\n- Date of birth\n- Bank account number\n\nThis offer EXPIRES in 48 HOURS. Respond immediately!\n\nJohn Smith\nLottery Director',
        answer: 'phishing',
        explanation: 'Classic lottery scam — requests sensitive personal/bank info, extreme urgency, too-good-to-be-true prize.'
    },
    {
        from: 'billing@netflix.com', subject: 'Your Netflix receipt – March 2026',
        body: 'Hi,\n\nThanks for your payment of $15.99 for Netflix Standard plan.\n\nBilling date: March 1, 2026\nNext billing date: April 1, 2026\n\nManage your subscription at netflix.com/account\n\nThanks,\nNetflix',
        answer: 'safe',
        explanation: 'Legitimate billing@netflix.com sender, no urgency, standard billing receipt with correct pricing, real link.'
    },
    {
        from: 'it-support@company-helpdesk.co', subject: 'Your password expires in 2 hours — reset now',
        body: 'Dear Employee,\n\nYour corporate password will expire in 2 HOURS.\n\nFAILURE to reset will result in IMMEDIATE account lockout.\n\nReset your password immediately:\nhttp://corp-reset.company-helpdesk.co/reset\n\nIT Department',
        answer: 'phishing',
        explanation: 'Fake generic IT domain, extreme urgency (2 hours), suspicious reset link, impersonal greeting.'
    },
    {
        from: 'team@slack.com', subject: 'You have been invited to join Acme Corp workspace',
        body: 'Hi,\n\nAlex Johnson has invited you to join the Acme Corp workspace on Slack.\n\nJoin Acme Corp: https://acmecorp.slack.com/\n\nIf you did not expect this invitation, you can ignore this message.\n\n– Slack',
        answer: 'safe',
        explanation: 'Legitimate team@slack.com sender, link goes to slack.com subdomain, no urgency or data requests.'
    },
    {
        from: 'verify@secure-irs-tax-refund.com', subject: 'IRS Tax Refund Approved — Verify to Receive',
        body: 'Dear Taxpayer,\n\nYour IRS tax refund of $3,249.00 has been approved.\n\nTo receive your refund, you must verify your Social Security Number and bank account details within 24 hours:\n\nhttp://irs-refund-claim.secure-irs-tax-refund.com/verify\n\nInternal Revenue Service',
        answer: 'phishing',
        explanation: 'IRS never contacts taxpayers by email. Fake domain, requests SSN and bank info, typical government impersonation scam.'
    },
    {
        from: 'noreply@linkedin.com', subject: 'Sarah Chen viewed your profile',
        body: 'Hi,\n\nSarah Chen (Senior Engineer at Google) viewed your profile.\n\nSee who\'s viewed your profile:\nhttps://www.linkedin.com/in/notifications/\n\nYou are receiving this email because you opted in. Unsubscribe\n\nLinkedIn Corporation, 1000 West Maude Ave, Sunnyvale, CA',
        answer: 'safe',
        explanation: 'Legitimate noreply@linkedin.com, real linkedin.com link, physical address included, standard notification format.'
    },
];

let trainerState = { index: 0, score: 0, answered: false, shuffled: [] };

function shuffle(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

function startTrainer() {
    trainerState = { index: 0, score: 0, answered: false, shuffled: shuffle(TRAINER_DATASET) };
    document.getElementById('trainerQuiz').style.display = 'block';
    document.getElementById('trainerResult').style.display = 'none';
    renderTrainerQuestion();
}

function renderTrainerQuestion() {
    const q = trainerState.shuffled[trainerState.index];
    const total = trainerState.shuffled.length;
    const pct = (trainerState.index / total) * 100;

    document.getElementById('trainerProgressFill').style.width = `${pct}%`;
    document.getElementById('trainerScoreBadge').textContent =
        `${trainerState.score} / ${trainerState.index} | Q${trainerState.index + 1} of ${total}`;

    document.getElementById('trainerMeta').innerHTML =
        `<span><b>From:</b> ${escHtml(q.from)}</span><span><b>Subject:</b> ${escHtml(q.subject)}</span>`;
    document.getElementById('trainerBody').textContent = q.body;

    const fb = document.getElementById('trainerFeedback');
    fb.style.display = 'none';
    fb.className = 'trainer-feedback';

    document.getElementById('trainerButtons').style.display = 'grid';
    const nextBtn = document.getElementById('trainerNextBtn');
    if (nextBtn) nextBtn.style.display = 'none';
    trainerState.answered = false;
}

function trainerGuess(guess) {
    if (trainerState.answered) return;
    trainerState.answered = true;

    const q = trainerState.shuffled[trainerState.index];
    const correct = guess === q.answer;
    if (correct) trainerState.score++;

    const fb = document.getElementById('trainerFeedback');
    fb.className = `trainer-feedback ${correct ? 'correct' : 'wrong'}`;
    fb.style.display = 'block';
    fb.innerHTML = correct
        ? `✅ Correct! ${escHtml(q.explanation)}`
        : `❌ This was <strong>${q.answer.toUpperCase()}</strong>. ${escHtml(q.explanation)}`;

    document.getElementById('trainerButtons').style.display = 'none';
    const nextBtn = document.getElementById('trainerNextBtn');
    if (nextBtn) nextBtn.style.display = 'block';
}

function trainerNext() {
    trainerState.index++;
    if (trainerState.index >= trainerState.shuffled.length) {
        showTrainerResult();
    } else {
        renderTrainerQuestion();
    }
}

function showTrainerResult() {
    document.getElementById('trainerQuiz').style.display = 'none';
    document.getElementById('trainerResult').style.display = 'block';

    const score = trainerState.score;
    const total = trainerState.shuffled.length;
    document.getElementById('trainerFinalScore').textContent = `${score}/${total}`;

    let grade, msg, color;
    if (score === total) {
        grade = '🏆 Perfect Score!'; msg = 'Outstanding! You caught every phishing attempt.'; color = '#7ab8f5';
    } else if (score >= total * 0.8) {
        grade = '🎯 Excellent!'; msg = 'You have a sharp eye for phishing. Almost perfect!'; color = '#9b7de0';
    } else if (score >= total * 0.6) {
        grade = '👍 Good Job'; msg = 'Decent score! Review the ones you missed and try again.'; color = '#e8a84a';
    } else {
        grade = '⚠️ Needs Practice'; msg = 'Phishing can be tricky. Study the explanations and retry!'; color = '#f48fb1';
    }

    const gradeEl = document.getElementById('trainerGrade');
    gradeEl.textContent = grade;
    gradeEl.style.color = color;
    document.getElementById('trainerGradeMsg').textContent = msg;
}

