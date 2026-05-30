/**
 * PhishScan — script.js
 * Handles: form submit → POST /predict → render result card
 */

(() => {
  const form        = document.getElementById('scanForm');
  const urlInput    = document.getElementById('urlInput');
  const submitBtn   = document.getElementById('submitBtn');
  const resultCard  = document.getElementById('resultCard');
  const errorCard   = document.getElementById('errorCard');
  const errorMsg    = document.getElementById('errorMsg');

  // Result card fields
  const verdictBadge   = document.getElementById('verdictBadge');
  const verdictLabel   = document.getElementById('verdictLabel');
  const verdictIcon    = document.getElementById('verdictIcon');
  const confidenceValue = document.getElementById('confidenceValue');
  const scannedUrl     = document.getElementById('scannedUrl');
  const flagList       = document.getElementById('flagList');
  const flagCount      = document.getElementById('flagCount');
  const resultTimestamp = document.getElementById('resultTimestamp');

  // ── Helpers ───────────────────────────────────────────────

  function setLoading(on) {
    submitBtn.classList.toggle('is-loading', on);
    submitBtn.disabled = on;
    urlInput.disabled  = on;
  }

  function hide(el) {
    el.hidden = true;
    if (el === resultCard) el.className = 'result-card';
    if (el === errorCard)  el.className = 'error-card';
  }

  function show(el) {
    el.hidden = false;
  }

  function severityClass(severity) {
    if (!severity) return 'severity-low';
    const s = severity.toLowerCase();
    if (s === 'high')   return 'severity-high';
    if (s === 'medium') return 'severity-medium';
    return 'severity-low';
  }

  // ── Render result ─────────────────────────────────────────

  function renderResult(data, submittedUrl) {
    hide(errorCard);
    const isPhishing = data.verdict?.toUpperCase() === 'PHISHING';

    // Verdict class on card
    resultCard.className = 'result-card ' + (isPhishing ? 'is-phishing' : 'is-legit');

    // Verdict label
    verdictLabel.textContent = isPhishing ? 'PHISHING' : 'LEGITIMATE';

    // Confidence (expects 0–100 or 0.0–1.0)
    let conf = parseFloat(data.confidence ?? 0);
    if (conf <= 1.0) conf = conf * 100;
    const score = Math.round(conf);
    confidenceValue.textContent = score + ' / 100';

    // Scanned URL
    scannedUrl.textContent = submittedUrl;
    scannedUrl.title       = submittedUrl;

    // Timestamp
    const now = new Date();
    resultTimestamp.textContent =
      `Scanned at ${now.toLocaleTimeString()} · ${now.toLocaleDateString()}`;

    // Flags / features
    flagList.innerHTML = '';
    const features = Array.isArray(data.features) ? data.features : [];

    if (features.length === 0) {
      flagCount.textContent = '(0)';
      const li = document.createElement('li');
      li.className = 'no-flags';
      li.textContent = 'No suspicious features detected.';
      flagList.appendChild(li);
    } else {
      flagCount.textContent = `(${features.length})`;

      features.forEach((feat, idx) => {
        const sevClass = severityClass(feat.severity);
        const li = document.createElement('li');
        li.className = `flag-item ${sevClass}`;
        li.style.animationDelay = `${idx * 40}ms`;

        li.innerHTML = `
          <span class="flag-item__bullet" aria-hidden="true"></span>
          <div class="flag-item__body">
            <span class="flag-item__name">${escapeHtml(feat.name ?? 'Unknown feature')}</span>
            <span class="flag-item__desc">${escapeHtml(feat.description ?? '')}</span>
          </div>
          <span class="flag-item__severity">${escapeHtml((feat.severity ?? 'low').toUpperCase())}</span>
        `;
        flagList.appendChild(li);
      });
    }

    hide(errorCard);
    show(resultCard);
  }

  // ── Render error ──────────────────────────────────────────

  function renderError(message) {
    errorMsg.textContent = message || 'An unexpected error occurred. Check the server logs.';
    hide(resultCard);
    show(errorCard);
  }

  // ── Escape HTML ───────────────────────────────────────────

  function escapeHtml(str) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(str).replace(/[&<>"']/g, c => map[c]);
  }

  // ── Form submit ───────────────────────────────────────────

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    let url = urlInput.value.trim();
    if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
        urlInput.value = url;
    }
    if (!url) return;

    setLoading(true);
    hide(resultCard);
    hide(errorCard);

    try {
      const response = await fetch('/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error('Server returned a non-JSON response.');
      }

      if (!response.ok) {
        const msg = data?.error || data?.message || `Server error ${response.status}.`;
        renderError(msg);
        return;
      }

      renderResult(data, url);

    } catch (err) {
      if (err.name === 'TypeError') {
        renderError('Could not reach the server. Is Flask running?');
      } else {
        renderError(err.message);
      }
    } finally {
      setLoading(false);
    }
  });

})();
