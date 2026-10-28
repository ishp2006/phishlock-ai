/**
 * PhishLock Security Suite
 * Client-side heuristic analysis and demonstration telemetry engine.
 */

const API_BASE = window.PHISHLOCK_API_BASE || '';

const appState = {
  activeTab: 'dashboard',
  recentScans: [],
  currentModalScan: null,
  activeFilter: 'all',
  stats: {
    scansToday: 1482,
    threatsIntercepted: 624,
    typosquatRules: 340
  }
};

const URL_PRESETS = [
  {
    label: "Chase Bank Impersonation (.xyz)",
    url: "http://secure-login-chase-update.xyz/verify-identity",
    type: "url"
  },
  {
    label: "Cryptocurrency Airdrop Portal (.net)",
    url: "http://claim-free-eth2026.net/wallet-connect",
    type: "url"
  },
  {
    label: "GitHub Enterprise (Legitimate)",
    url: "https://github.com/security",
    type: "url"
  },
  {
    label: "PayPal Homoglyph / Typosquat",
    url: "http://paypa1-account-resolution.com/signin",
    type: "url"
  },
  {
    label: "Google Workspace Docs (Legitimate)",
    url: "https://docs.google.com/document/u/0/",
    type: "url"
  }
];

const MSG_PRESETS = [
  {
    label: "Financial Account Suspension (Smishing)",
    text: "URGENT ALERT: Your Chase debit card has been temporarily SUSPENDED due to 3 unauthorized transactions. Click immediately at http://secure-verify-card.xyz to confirm your identity within 24 hours or your account will be permanently blocked."
  },
  {
    label: "Postal Delivery Redirection (Fee Lure)",
    text: "USPS Notification: Package #US-98214 could not be delivered due to an incorrect postal address. A $1.85 redelivery charge is required. Pay now: http://usps-tracking-redelivery-fee.top/pay to avoid package return."
  },
  {
    label: "Executive Impersonation (Wire Transfer)",
    text: "Hi, I am currently in an urgent confidential board meeting and cannot take calls. I need you to immediately process an urgent vendor wire transfer of $24,500 to our acquisition partner. Please confirm once sent, do not email the main finance list."
  },
  {
    label: "Advance-Fee Prize Notification",
    text: "CONGRATULATIONS! Your mobile number was selected as the 1st prize winner of $1,500,000 in the International Mobile Rewards Lottery 2026. Reply with your full name, banking details, and SSN to claim immediately."
  },
  {
    label: "Routine Security Sync (Legitimate)",
    text: "Hi team, please find attached the agenda for our quarterly security architecture sync scheduled for Thursday at 2:00 PM EST via Google Meet. Let me know if you need to add any discussion topics."
  }
];

function initializeSampleScans() {
  appState.recentScans = [
    {
      id: "scan-1001",
      target: "http://secure-login-chase-update.xyz/verify",
      type: "URI",
      riskScore: 92,
      riskLevel: "CRITICAL",
      timestamp: "Today, 12:20 PM",
      indicators: [
        { title: "High-Abuse Top-Level Domain", desc: "Domain uses '.xyz', frequently correlated with disposable phishing kits." },
        { title: "Financial Brand Impersonation", desc: "Contains 'chase' coupled with urgency tokens ('secure', 'update')." },
        { title: "Unencrypted Protocol (HTTP)", desc: "Traffic is transmitted in plaintext without standard TLS transport." }
      ],
      recommendations: [
        "Do not submit credentials, OTP factors, or payment card details.",
        "Verify account status directly through official Chase.com channels.",
        "Submit telemetry to enterprise security operations."
      ]
    },
    {
      id: "scan-1002",
      target: "ALERT: Your debit card is locked. Click http://verify-card.xyz immediately",
      type: "Message",
      riskScore: 88,
      riskLevel: "CRITICAL",
      timestamp: "Today, 11:45 AM",
      indicators: [
        { title: "Psychological Coercion Markers", desc: "Employs high-pressure keywords ('LOCKED', 'IMMEDIATELY') to force hasty compliance." },
        { title: "Untrusted Destination URI", desc: "Directs recipient to an unregistered, third-party domain." },
        { title: "Credential Interception Vector", desc: "Attempts collection of financial identity markers via unverified SMS." }
      ],
      recommendations: [
        "Never resolve unprompted links received via unsolicited SMS.",
        "Forward message payload to carrier spam reporting code 7726."
      ]
    },
    {
      id: "scan-1003",
      target: "http://paypa1-account-resolution.com/signin",
      type: "URI",
      riskScore: 78,
      riskLevel: "SUSPICIOUS",
      timestamp: "Today, 10:14 AM",
      indicators: [
        { title: "Homoglyph / Typosquatting Character", desc: "Character substitution '1' detected in place of glyph 'l' (paypa1)." },
        { title: "Authentication Harvesting Pattern", desc: "Path combines 'account-resolution' and 'signin' to mimic dispute centers." }
      ],
      recommendations: [
        "Verify exact character sequence of canonical domain.",
        "Navigate via verified browser bookmark."
      ]
    },
    {
      id: "scan-1004",
      target: "https://github.com/security",
      type: "URI",
      riskScore: 8,
      riskLevel: "SAFE",
      timestamp: "Today, 09:30 AM",
      indicators: [
        { title: "Authoritative Enterprise Root", desc: "Target matches canonical verified domain (github.com)." },
        { title: "Cryptographic Transport (TLS)", desc: "Connection negotiated using modern cryptographic standards." }
      ],
      recommendations: [
        "Resource matches recognized legitimate infrastructure.",
        "Maintain routine security posture and active multi-factor authentication."
      ]
    },
    {
      id: "scan-1005",
      target: "Hi team, agenda for Thursday sync is attached on Google Drive...",
      type: "Message",
      riskScore: 12,
      riskLevel: "SAFE",
      timestamp: "Yesterday, 04:50 PM",
      indicators: [
        { title: "Standard Communication Baseline", desc: "Absence of coercive urgency, credential lures, or unauthorized financial requests." }
      ],
      recommendations: [
        "No critical risk indicators detected in simulated evaluation.",
        "Continue routine vigilance across external communications."
      ]
    }
  ];
}

function switchTab(tabId) {
  closeScanModal();
  appState.activeTab = tabId;

  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    link.classList.toggle('active', link.dataset.tab === tabId);
  });

  const panes = document.querySelectorAll('.tab-pane');
  panes.forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabId}`);
  });

  const breadcrumbEl = document.getElementById('breadcrumbText');
  const tabTitles = {
    'dashboard': 'Dashboard Overview',
    'url-scanner': 'URL & Domain Analyzer',
    'message-analyzer': 'Message NLP Analyzer',
    'recent-scans': 'Session Audit Log',
    'security-tips': 'Defensive Hygiene'
  };
  if (breadcrumbEl) {
    breadcrumbEl.textContent = tabTitles[tabId] || 'Dashboard Overview';
  }

  closeMobileSidebar();
  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (tabId === 'recent-scans') {
    renderFullRecentTable();
  }
}

function setupMobileDrawer() {
  const toggleBtn = document.getElementById('mobileToggleBtn');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');

  if (toggleBtn && sidebar && overlay) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay.classList.toggle('active');
    });

    overlay.addEventListener('click', closeMobileSidebar);
  }
}

function closeMobileSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  if (sidebar && overlay) {
    sidebar.classList.remove('open');
    overlay.classList.remove('active');
  }
}

/**
 * Evaluates a URI string against client-side lexical heuristics.
 * Simulated demonstration data: does not query production security APIs.
 */
function analyzeUrlHeuristics(inputUrl) {
  const normalized = inputUrl.trim().toLowerCase();
  let score = 10;
  const indicators = [];
  const recommendations = [];

  const safeDomains = ['github.com', 'google.com', 'wikipedia.org', 'microsoft.com', 'apple.com', 'mozilla.org', 'mit.edu'];
  const isSafeDomain = safeDomains.some(domain => normalized.includes(domain));

  if (isSafeDomain) {
    score = Math.floor(Math.random() * 8) + 5;
    indicators.push({
      title: "Authoritative Verified Domain",
      desc: "Domain matches recognized canonical records in static whitelist."
    });
    indicators.push({
      title: "Encrypted Transport (TLS)",
      desc: "Standard HTTPS cryptographic protocol observed."
    });
    recommendations.push("Domain identified as verified legitimate host in local database.");
    recommendations.push("Maintain standard zero-trust browsing hygiene.");

    return buildReportObject(inputUrl, "URI", score, indicators, recommendations);
  }

  if (normalized.startsWith('http://')) {
    score += 20;
    indicators.push({
      title: "Plaintext Protocol (Insecure HTTP)",
      desc: "Resource transmits traffic without TLS encryption. Authentic financial portals require HTTPS."
    });
  }

  const suspiciousTlds = ['.xyz', '.top', '.tk', '.ml', '.cf', '.gq', '.click', '.loan', '.work', '.live', '.icu', '.buzz'];
  const hasSuspiciousTld = suspiciousTlds.some(tld => normalized.includes(tld));
  if (hasSuspiciousTld) {
    score += 35;
    indicators.push({
      title: "High-Abuse Top-Level Domain",
      desc: "Target operates on a low-cost or disposable TLD statistically correlated with phishing campaigns."
    });
  }

  const brandKeywords = [
    { brand: 'paypal', variants: ['paypa1', 'pay-pal', 'paypol', 'paypal-secure'] },
    { brand: 'chase', variants: ['chase-login', 'chase-security', 'chase-verify'] },
    { brand: 'apple', variants: ['app1e', 'apple-id-verify', 'icloud-find'] },
    { brand: 'google', variants: ['g00gle', 'google-verify', 'google-drive-share'] },
    { brand: 'microsoft', variants: ['micros0ft', 'office365-login', 'microsoft-live-auth'] },
    { brand: 'crypto', variants: ['airdrop', 'wallet-connect', 'free-eth', 'metamask-claim'] }
  ];

  brandKeywords.forEach(item => {
    item.variants.forEach(variant => {
      if (normalized.includes(variant)) {
        score += 35;
        indicators.push({
          title: `Brand Impersonation Signature: ${item.brand.toUpperCase()}`,
          desc: `Token '${variant}' indicates an attempt to mimic authentic authentication endpoints.`
        });
      }
    });
  });

  const suspiciousKeywords = ['verify', 'login', 'secure', 'account', 'update', 'banking', 'confirm', 'password', 'suspend'];
  const matchedKeywords = suspiciousKeywords.filter(kw => normalized.includes(kw));
  if (matchedKeywords.length >= 2) {
    score += 25;
    indicators.push({
      title: `Credential Harvesting Path Tokens (${matchedKeywords.join(', ')})`,
      desc: "Multiple sensitive credential-gathering keywords chained in URI path."
    });
  }

  // Count domain dot separators to detect multi-tier subdomain obfuscation
  const dotCount = (normalized.match(/\./g) || []).length;
  if (dotCount >= 4) {
    score += 20;
    indicators.push({
      title: "Deep Subdomain Stacking / Obfuscation",
      desc: `Detected ${dotCount} domain delimiters. Adversaries prefix legitimate brand names as subdomains.`
    });
  }

  score = Math.min(Math.max(score, 15), 96);

  if (score >= 70) {
    recommendations.push("Do not input passwords, authentication factors, or financial card details.");
    recommendations.push("Terminate active connection and isolate endpoint if file downloads occurred.");
    recommendations.push("Rotate account credentials via authoritative channels if entered previously.");
  } else if (score >= 40) {
    recommendations.push("Exercise elevated caution. Confirm root domain matches official enterprise records.");
    recommendations.push("Verify authenticity via secondary out-of-band communication.");
  } else {
    recommendations.push("No explicit red flags detected. Continue verifying SSL certificate attributes.");
  }

  return buildReportObject(inputUrl, "URI", score, indicators, recommendations);
}

/**
 * Evaluates textual communication against social engineering and coercion heuristics.
 */
function analyzeMessageHeuristics(text) {
  const normalized = text.toLowerCase();
  let score = 10;
  const indicators = [];
  const recommendations = [];

  const urgencyWords = ['urgent', 'immediately', 'within 24 hours', '1 hour', 'suspended', 'locked', 'terminate', 'legal action', 'arrest', 'warning'];
  const matchedUrgency = urgencyWords.filter(w => normalized.includes(w));
  if (matchedUrgency.length > 0) {
    score += matchedUrgency.length * 15;
    indicators.push({
      title: `High-Pressure Coercive Tokens (${matchedUrgency.slice(0, 3).join(', ')})`,
      desc: "Social engineering vectors induce artificial urgency to circumvent standard verification protocols."
    });
  }

  const financialWords = ['wire transfer', 'gift card', 'bitcoin', 'crypto', 'bank account', 'debit card', 'ssn', 'social security', 'redelivery fee', 'irs', 'refund'];
  const matchedFinancial = financialWords.filter(w => normalized.includes(w));
  if (matchedFinancial.length > 0) {
    score += matchedFinancial.length * 18;
    indicators.push({
      title: `Financial Asset / Payment Redirection (${matchedFinancial.slice(0, 3).join(', ')})`,
      desc: "Unprompted requests for wire transfers, gift cards, or cryptocurrency indicate financial fraud."
    });
  }

  const baitWords = ['congratulations', 'won', 'lottery', 'prize', 'selected', '$1,000,000', 'free reward', 'inheritance'];
  const matchedBait = baitWords.filter(w => normalized.includes(w));
  if (matchedBait.length > 0) {
    score += 30;
    indicators.push({
      title: "Advance-Fee / Prize Solicitation Lure",
      desc: "Unsolicited claims of financial windfalls requesting personal identity verification or processing fees."
    });
  }

  if (normalized.includes('http://') || normalized.includes('https://') || normalized.includes('.xyz') || normalized.includes('.top')) {
    score += 25;
    indicators.push({
      title: "Embedded Unverified Action URI",
      desc: "Message instructs recipient to resolve an external link rather than navigating via official applications."
    });
  }

  score = Math.min(Math.max(score, 12), 97);

  if (score >= 70) {
    recommendations.push("Do not reply, click embedded links, or dial telephone numbers embedded in payload.");
    recommendations.push("Verify independently using verified contacts on official statements.");
    recommendations.push("Forward SMS payloads to carrier shortcode 7726 for network-level mitigation.");
  } else if (score >= 40) {
    recommendations.push("Exercise heightened vigilance on unexpected communications requesting urgent action.");
    recommendations.push("Inspect full RFC-822 email headers to verify SPF, DKIM, and DMARC alignment.");
  } else {
    recommendations.push("Message structure conforms to standard communication baselines.");
  }

  return buildReportObject(text.slice(0, 95) + (text.length > 95 ? '...' : ''), "Message", score, indicators, recommendations);
}

function buildReportObject(target, type, score, indicators, recommendations) {
  let riskLevel = "SAFE";
  if (score >= 68) {
    riskLevel = "CRITICAL";
  } else if (score >= 35) {
    riskLevel = "SUSPICIOUS";
  }

  const now = new Date();
  const timeStr = `Today, ${now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

  return {
    id: `scan-${Date.now().toString().slice(-4)}`,
    target: target,
    type: type,
    riskScore: score,
    riskLevel: riskLevel,
    timestamp: timeStr,
    indicators: indicators.length > 0 ? indicators : [
      { title: "Standard Heuristic Baseline", desc: "No critical anomalous indicators matched during heuristic evaluation." }
    ],
    recommendations: recommendations.length > 0 ? recommendations : [
      "No critical actions required. Maintain routine endpoint hygiene."
    ]
  };
}

function formatBackendReport(data, targetValue, vectorType) {
  const now = new Date();
  const timeStr = `Today, ${now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

  let riskLevel = data.risk_level;
  if (riskLevel === 'LOW_RISK') {
    riskLevel = 'SAFE';
  } else if (!riskLevel) {
    riskLevel = 'SAFE';
  }

  const indicators = (data.indicators || []).map(ind => ({
    title: ind.title || 'Risk Indicator',
    desc: ind.description || ind.desc || 'Heuristic indicator flagged.'
  }));

  if (indicators.length === 0) {
    indicators.push({
      title: "Standard Heuristic Baseline",
      desc: "No critical anomalous indicators matched during heuristic evaluation."
    });
  }

  const recommendations = (data.recommendations && data.recommendations.length > 0)
    ? data.recommendations
    : ["No critical actions required. Maintain routine endpoint hygiene."];

  return {
    id: `scan-${Date.now().toString().slice(-4)}`,
    target: data.target || targetValue,
    type: data.vector_type || vectorType,
    riskScore: typeof data.risk_score === 'number' ? data.risk_score : 0,
    riskLevel: riskLevel,
    timestamp: timeStr,
    indicators: indicators,
    recommendations: recommendations,
    disclaimer: data.disclaimer || '',
    rawPayload: data
  };
}

async function handleUrlScanSubmit(event) {
  event.preventDefault();
  const inputEl = document.getElementById('urlInput');
  const validationEl = document.getElementById('urlValidationMsg');
  const consoleEl = document.getElementById('urlScanConsole');
  const resultsArea = document.getElementById('urlResultsArea');
  const analyzeBtn = document.getElementById('urlAnalyzeBtn');

  if (!inputEl) return;
  const urlValue = inputEl.value.trim();

  if (!urlValue) {
    showValidation(validationEl, "Please specify a valid URL or fully qualified domain name to analyze.", "error");
    inputEl.focus();
    return;
  }

  clearValidation(validationEl);
  resultsArea.innerHTML = '';

  if (analyzeBtn) {
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add('loading');
  }

  if (consoleEl) {
    consoleEl.style.display = 'block';
  }
  const logsContainer = document.getElementById('urlConsoleLogs');
  const progressFill = document.getElementById('urlConsoleProgress');
  if (logsContainer) logsContainer.innerHTML = '';
  if (progressFill) progressFill.style.width = '0%';

  const scanSteps = [
    { text: "Initializing lexical parsing pipeline...", delay: 150, progress: "20%" },
    { text: `Evaluating domain syntax and URI components: "${escapeHtml(urlValue.substring(0, 45))}..."`, delay: 400, progress: "45%" },
    { text: "Scanning for homoglyphs and typosquatting signatures across heuristic rules...", delay: 700, progress: "70%" },
    { text: "Computing lexical entropy and top-level domain risk profile...", delay: 950, progress: "90%" },
    { text: "Compiling heuristic risk assessment report...", delay: 1200, progress: "100%" }
  ];

  scanSteps.forEach(step => {
    setTimeout(() => {
      if (logsContainer) {
        const line = document.createElement('div');
        line.className = 'console-line active';
        line.innerHTML = `<span class="console-prefix">&gt;</span> <span>${step.text}</span>`;
        logsContainer.appendChild(line);
      }
      if (progressFill) {
        progressFill.style.width = step.progress;
      }
    }, step.delay);
  });

  try {
    const [response] = await Promise.all([
      fetch(`${API_BASE}/api/analyze-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlValue })
      }),
      new Promise(resolve => setTimeout(resolve, 1300))
    ]);

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Server error occurred during URL evaluation.');
    }

    const report = formatBackendReport(data, urlValue, 'URI');
    saveScanResult(report);
    renderResultsCard(resultsArea, report);

    showToast(`Analysis Complete: ${report.riskLevel} Risk (${report.riskScore}/100)`, report.riskLevel === 'CRITICAL' ? 'error' : 'info');
    resultsArea.scrollIntoView({ behavior: 'smooth', block: 'start' });

  } catch (err) {
    console.error('URL analysis failed:', err);
    showValidation(validationEl, `Analysis error: ${err.message}`, "error");
    showToast(`Analysis failed: ${err.message}`, "error");
  } finally {
    if (analyzeBtn) {
      analyzeBtn.disabled = false;
      analyzeBtn.classList.remove('loading');
    }
  }
}

async function handleMessageScanSubmit(event) {
  event.preventDefault();
  const inputEl = document.getElementById('msgInput');
  const validationEl = document.getElementById('msgValidationMsg');
  const consoleEl = document.getElementById('msgScanConsole');
  const resultsArea = document.getElementById('msgResultsArea');
  const analyzeBtn = document.getElementById('msgAnalyzeBtn');

  if (!inputEl) return;
  const textValue = inputEl.value.trim();

  if (!textValue) {
    showValidation(validationEl, "Please provide message content or email excerpt for evaluation.", "error");
    inputEl.focus();
    return;
  }

  if (textValue.length < 10) {
    showValidation(validationEl, "Message payload must contain at least 10 characters for heuristic evaluation.", "error");
    return;
  }

  clearValidation(validationEl);
  resultsArea.innerHTML = '';

  if (analyzeBtn) {
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add('loading');
  }

  if (consoleEl) {
    consoleEl.style.display = 'block';
  }
  const logsContainer = document.getElementById('msgConsoleLogs');
  const progressFill = document.getElementById('msgConsoleProgress');
  if (logsContainer) logsContainer.innerHTML = '';
  if (progressFill) progressFill.style.width = '0%';

  const scanSteps = [
    { text: "Tokenizing message payload and filtering delimiters...", delay: 150, progress: "25%" },
    { text: "Evaluating psychological coercion pressure and urgency markers...", delay: 400, progress: "50%" },
    { text: "Scanning financial redirection targets and wire transfer indicators...", delay: 700, progress: "75%" },
    { text: "Synthesizing linguistic heuristic risk assessment...", delay: 950, progress: "100%" }
  ];

  scanSteps.forEach(step => {
    setTimeout(() => {
      if (logsContainer) {
        const line = document.createElement('div');
        line.className = 'console-line active';
        line.innerHTML = `<span class="console-prefix">&gt;</span> <span>${step.text}</span>`;
        logsContainer.appendChild(line);
      }
      if (progressFill) {
        progressFill.style.width = step.progress;
      }
    }, step.delay);
  });

  try {
    const [response] = await Promise.all([
      fetch(`${API_BASE}/api/analyze-message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: textValue })
      }),
      new Promise(resolve => setTimeout(resolve, 1100))
    ]);

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Server error occurred during message evaluation.');
    }

    const report = formatBackendReport(data, textValue.slice(0, 95) + (textValue.length > 95 ? '...' : ''), 'Message');
    saveScanResult(report);
    renderResultsCard(resultsArea, report);

    showToast(`Analysis Complete: ${report.riskLevel} Risk (${report.riskScore}/100)`, report.riskLevel === 'CRITICAL' ? 'error' : 'info');
    resultsArea.scrollIntoView({ behavior: 'smooth', block: 'start' });

  } catch (err) {
    console.error('Message analysis failed:', err);
    showValidation(validationEl, `Analysis error: ${err.message}`, "error");
    showToast(`Analysis failed: ${err.message}`, "error");
  } finally {
    if (analyzeBtn) {
      analyzeBtn.disabled = false;
      analyzeBtn.classList.remove('loading');
    }
  }
}

function clearMessageInput() {
  const input = document.getElementById('msgInput');
  const validation = document.getElementById('msgValidationMsg');
  if (input) {
    input.value = '';
    document.getElementById('msgCharCount').textContent = '0';
    document.getElementById('msgWordCount').textContent = '0';
    input.focus();
  }
  clearValidation(validation);
}

function loadMsgPreset(index) {
  const preset = MSG_PRESETS[index];
  if (!preset) return;
  const input = document.getElementById('msgInput');
  if (input) {
    input.value = preset.text;
    input.dispatchEvent(new Event('input'));
    clearValidation(document.getElementById('msgValidationMsg'));
    showToast(`Scenario Loaded: ${preset.label}`, 'info');
  }
}

function renderResultsCard(container, report) {
  const riskClass = report.riskLevel === 'CRITICAL'
    ? 'risk-critical'
    : report.riskLevel === 'SUSPICIOUS'
      ? 'risk-suspicious'
      : 'risk-safe';

  const badgeClass = report.riskLevel === 'CRITICAL'
    ? 'badge-critical-bg'
    : report.riskLevel === 'SUSPICIOUS'
      ? 'badge-suspicious-bg'
      : 'badge-safe-bg';

  const strokeColor = report.riskLevel === 'CRITICAL'
    ? '#ff3366'
    : report.riskLevel === 'SUSPICIOUS'
      ? '#f59e0b'
      : '#00ff88';

  // Calculate SVG stroke offset for radius 45 (circumference = 2 * PI * 45 = 282.74)
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (report.riskScore / 100) * circumference;

  const indicatorsHtml = report.indicators.map(ind => `
    <div class="indicator-item">
      <svg class="indicator-icon ${report.riskLevel === 'CRITICAL' ? 'text-red' : report.riskLevel === 'SUSPICIOUS' ? 'text-amber' : 'text-green'}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      <div class="indicator-content">
        <div class="indicator-title">${escapeHtml(ind.title)}</div>
        <div class="indicator-desc">${escapeHtml(ind.desc)}</div>
      </div>
    </div>
  `).join('');

  const recsHtml = report.recommendations.map(rec => `
    <li class="rec-item">
      <span class="rec-bullet">&bull;</span>
      <span>${escapeHtml(rec)}</span>
    </li>
  `).join('');

  const rawJson = JSON.stringify({
    simulated_environment: true,
    evaluation_type: "client_side_heuristic_simulation",
    target: report.target,
    vector_type: report.type,
    risk_score: report.riskScore,
    classification: report.riskLevel,
    timestamp: report.timestamp,
    heuristics_matched: report.indicators.map(i => i.title),
    recommended_mitigations: report.recommendations
  }, null, 2);

  const cardHtml = `
    <div class="results-card ${riskClass}">
      
      <div class="demo-results-banner">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="demo-banner-icon">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <div class="demo-banner-text">
          <strong>Notice:</strong> Simulated assessment based on deterministic client-side heuristic rules. This interface does not connect to live external security databases or verify production certificates.
        </div>
      </div>

      <div class="results-score-block">
        <div class="score-meter">
          <svg class="meter-svg" viewBox="0 0 100 100">
            <circle class="meter-bg" cx="50" cy="50" r="45"></circle>
            <circle 
              class="meter-bar" 
              cx="50" 
              cy="50" 
              r="45" 
              style="stroke: ${strokeColor}; stroke-dashoffset: ${offset};"
            ></circle>
          </svg>
          <div class="score-number-wrap">
            <span class="score-number" style="color: ${strokeColor};">${report.riskScore}</span>
            <span class="score-sublabel">Risk Index</span>
          </div>
        </div>

        <div class="results-meta">
          <div class="results-level-row">
            <span class="risk-level-badge ${badgeClass}">${report.riskLevel} Risk </span>
            <span class="badge badge-outline">${report.type} Vector</span>
          </div>
          <div class="results-target-title">Target Resource:</div>
          <div class="results-target-str">${escapeHtml(report.target)}</div>
        </div>
      </div>

      <div class="results-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon text-cyan">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="16" x2="12" y2="12"/>
          <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
        <span>Heuristic Indicators Flagged (${report.indicators.length})</span>
      </div>
      <div class="indicators-list">
        ${indicatorsHtml}
      </div>

      <div class="recommendations-box">
        <div class="results-section-title" style="margin-bottom: 8px;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon text-green">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
          <span>Recommended Protective Actions</span>
        </div>
        <ul class="rec-list">
          ${recsHtml}
        </ul>
      </div>

      <div class="heuristics-accordion">
        <div class="accordion-header" onclick="window.toggleJsonAccordion(this)">
          <span>{ } Raw Heuristic Telemetry (JSON Payload)</span>
          <span class="accordion-icon">+</span>
        </div>
        <div class="accordion-body">
          <pre>${escapeHtml(rawJson)}</pre>
        </div>
      </div>

      <div class="results-footer-actions">
        <button class="btn btn-sm btn-primary" onclick="window.copyReportToClipboard('${report.id}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
          Copy Report
        </button>
        <button class="btn btn-sm btn-ghost" onclick="window.switchTab('recent-scans')">
          View in Session Log &rarr;
        </button>
      </div>

    </div>
  `;

  container.innerHTML = cardHtml;
}

function toggleJsonAccordion(headerEl) {
  const body = headerEl.nextElementSibling;
  const icon = headerEl.querySelector('.accordion-icon');
  if (body) {
    body.classList.toggle('open');
    if (icon) {
      icon.textContent = body.classList.contains('open') ? '−' : '+';
    }
  }
}

function saveScanResult(report) {
  appState.recentScans.unshift(report);

  appState.stats.scansToday += 1;
  if (report.riskLevel === 'CRITICAL') {
    appState.stats.threatsIntercepted += 1;
  }
  updateStatsDisplay();

  renderDashboardRecentTable();
  renderFullRecentTable();
  updateBadgeCounts();
}

function renderDashboardRecentTable() {
  const tbody = document.getElementById('dashboardRecentTableBody');
  if (!tbody) return;

  const topScans = appState.recentScans.slice(0, 5);
  tbody.innerHTML = topScans.map(scan => createTableRowHtml(scan)).join('');
}

function renderFullRecentTable() {
  const tbody = document.getElementById('fullRecentTableBody');
  const emptyMsg = document.getElementById('emptyHistoryMsg');
  if (!tbody) return;

  let filtered = appState.recentScans;
  if (appState.activeFilter === 'critical') {
    filtered = filtered.filter(s => s.riskLevel === 'CRITICAL');
  } else if (appState.activeFilter === 'suspicious') {
    filtered = filtered.filter(s => s.riskLevel === 'SUSPICIOUS');
  } else if (appState.activeFilter === 'safe') {
    filtered = filtered.filter(s => s.riskLevel === 'SAFE');
  }

  if (filtered.length === 0) {
    tbody.innerHTML = '';
    if (emptyMsg) emptyMsg.style.display = 'block';
  } else {
    if (emptyMsg) emptyMsg.style.display = 'none';
    tbody.innerHTML = filtered.map(scan => createTableRowHtml(scan)).join('');
  }

  updateFilterCounts();
}

function createTableRowHtml(scan) {
  const badgeClass = scan.riskLevel === 'CRITICAL'
    ? 'badge-red'
    : scan.riskLevel === 'SUSPICIOUS'
      ? 'badge-amber'
      : 'badge-green';

  const scoreColor = scan.riskLevel === 'CRITICAL'
    ? 'text-red'
    : scan.riskLevel === 'SUSPICIOUS'
      ? 'text-amber'
      : 'text-green';

  return `
    <tr>
      <td>
        <div class="table-target" title="${escapeHtml(scan.target)}">${escapeHtml(scan.target)}</div>
      </td>
      <td>
        <span class="badge badge-outline">${scan.type}</span>
      </td>
      <td>
        <span class="table-score ${scoreColor}">${scan.riskScore}/100</span>
      </td>
      <td>
        <span class="badge ${badgeClass}">${scan.riskLevel} (Simulated)</span>
      </td>
      <td style="color: var(--text-dim); font-size: 0.8rem;">
        ${scan.timestamp}
      </td>
      <td>
        <button class="btn btn-sm btn-ghost" onclick="window.openScanModal('${scan.id}')">
          View Details
        </button>
      </td>
    </tr>
  `;
}

function filterScans(filter) {
  appState.activeFilter = filter;
  const filterBtns = document.querySelectorAll('.filter-btn');
  filterBtns.forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filter);
  });
  renderFullRecentTable();
}

function updateFilterCounts() {
  const allCount = appState.recentScans.length;
  const critCount = appState.recentScans.filter(s => s.riskLevel === 'CRITICAL').length;
  const suspCount = appState.recentScans.filter(s => s.riskLevel === 'SUSPICIOUS').length;
  const safeCount = appState.recentScans.filter(s => s.riskLevel === 'SAFE').length;

  const setEl = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setEl('countAll', allCount);
  setEl('countCritical', critCount);
  setEl('countSuspicious', suspCount);
  setEl('countSafe', safeCount);
}

function updateBadgeCounts() {
  const badge = document.getElementById('recentBadgeCount');
  if (badge) {
    badge.textContent = appState.recentScans.length;
  }
}

function updateStatsDisplay() {
  const scansEl = document.getElementById('statScansCount');
  const threatsEl = document.getElementById('statThreatsCount');
  if (scansEl) scansEl.textContent = appState.stats.scansToday.toLocaleString();
  if (threatsEl) threatsEl.textContent = appState.stats.threatsIntercepted.toLocaleString();
}

function resetDemoHistory() {
  if (confirm("Reset simulated session telemetry to default values?")) {
    initializeSampleScans();
    renderDashboardRecentTable();
    renderFullRecentTable();
    updateBadgeCounts();
    showToast("Session telemetry reset to default state.", "info");
  }
}

function exportDemoHistory() {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(appState.recentScans, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `phishlock_telemetry_${Date.now()}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
  showToast("Exported telemetry JSON successfully.", "success");
}

function openScanModal(scanId) {
  const scan = appState.recentScans.find(s => s.id === scanId);
  if (!scan) return;

  appState.currentModalScan = scan;
  const modal = document.getElementById('scanModal');
  const modalBody = document.getElementById('modalBody');
  const modalTitle = document.getElementById('modalTitle');

  if (modal && modalBody) {
    if (modalTitle) modalTitle.textContent = `Assessment Report #${scan.id}`;
    renderResultsCard(modalBody, scan);
    modal.style.display = 'flex';
  }
}

function closeScanModal() {
  const modal = document.getElementById('scanModal');
  if (modal) {
    modal.style.display = 'none';
  }
  appState.currentModalScan = null;
}

function copyModalReport() {
  if (appState.currentModalScan) {
    copyReportToClipboard(appState.currentModalScan.id);
  }
}

function runPresetScan(type, index) {
  if (type === 'url') {
    switchTab('url-scanner');
    loadUrlPreset(index);
    setTimeout(() => {
      const form = document.getElementById('urlScanForm');
      if (form) form.dispatchEvent(new Event('submit', { cancelable: true }));
    }, 150);
  } else if (type === 'message') {
    switchTab('message-analyzer');
    loadMsgPreset(index);
    setTimeout(() => {
      const form = document.getElementById('msgScanForm');
      if (form) form.dispatchEvent(new Event('submit', { cancelable: true }));
    }, 150);
  }
}

function loadFeaturedDemoScan() {
  openScanModal('scan-1001');
}

function copyReportToClipboard(scanId) {
  const scan = appState.recentScans.find(s => s.id === scanId);
  if (!scan) return;

  const reportText = `[PHISHLOCK SECURITY SUITE — SIMULATED ASSESSMENT REPORT]
Notice: Generated via client-side heuristic evaluation in demonstration mode.
Target: ${scan.target}
Vector: ${scan.type}
Risk Index: ${scan.riskScore}/100
Classification: ${scan.riskLevel} (Simulated)

Timestamp: ${scan.timestamp}

Indicators:
${scan.indicators.map(i => `- ${i.title}: ${i.desc}`).join('\n')}

Recommendations:
${scan.recommendations.map(r => `* ${r}`).join('\n')}
`;

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(reportText).then(() => {
      showToast("Evaluation report copied to clipboard.", "success");
    }).catch(() => {
      fallbackCopyText(reportText);
    });
  } else {
    fallbackCopyText(reportText);
  }
}

function fallbackCopyText(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  document.body.appendChild(textArea);
  textArea.select();
  try {
    document.execCommand('copy');
    showToast("Evaluation report copied to clipboard.", "success");
  } catch (err) {
    showToast("Unable to copy to clipboard.", "error");
  }
  document.body.removeChild(textArea);
}

function showValidation(el, message, type) {
  if (!el) return;
  el.textContent = message;
  el.className = `validation-msg ${type}`;
}

function clearValidation(el) {
  if (!el) return;
  el.textContent = '';
  el.className = 'validation-msg';
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const iconSvg = type === 'success'
    ? `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`
    : type === 'error'
      ? `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
      : `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

  toast.innerHTML = `${iconSvg} <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

function escapeHtml(string) {
  const entityMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  };
  return String(string).replace(/[&<>"'/]/g, s => entityMap[s]);
}

document.addEventListener('DOMContentLoaded', () => {
  initializeSampleScans();

  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      const targetTab = link.dataset.tab;
      if (targetTab) switchTab(targetTab);
    });
  });

  const quickUrlBtn = document.getElementById('quickUrlBtn');
  const quickMsgBtn = document.getElementById('quickMsgBtn');
  if (quickUrlBtn) quickUrlBtn.addEventListener('click', () => switchTab('url-scanner'));
  if (quickMsgBtn) quickMsgBtn.addEventListener('click', () => switchTab('message-analyzer'));

  setupMobileDrawer();
  setupMessageCharCounter();

  renderDashboardRecentTable();
  renderFullRecentTable();
  updateBadgeCounts();

  const scanModal = document.getElementById('scanModal');
  if (scanModal) {
    scanModal.addEventListener('click', (e) => {
      if (e.target === scanModal) {
        closeScanModal();
      }
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeScanModal();
    }
  });

  // Probe backend health to verify connection
  fetch(`${API_BASE}/api/health`)
    .then(res => res.json())
    .then(data => {
      const statusTitle = document.querySelector('.status-title');
      if (statusTitle) statusTitle.textContent = 'Backend Engine (Live)';
    })
    .catch(() => {
      console.warn('Backend currently unreachable, local mode.');
    });
});

// Export functions to window for DOM event bindings
window.switchTab = switchTab;
window.handleUrlScanSubmit = handleUrlScanSubmit;
window.clearUrlInput = clearUrlInput;
window.loadUrlPreset = loadUrlPreset;
window.fillRandomUrlPreset = fillRandomUrlPreset;
window.handleMessageScanSubmit = handleMessageScanSubmit;
window.clearMessageInput = clearMessageInput;
window.loadMsgPreset = loadMsgPreset;
window.runPresetScan = runPresetScan;
window.loadFeaturedDemoScan = loadFeaturedDemoScan;
window.filterScans = filterScans;
window.resetDemoHistory = resetDemoHistory;
window.exportDemoHistory = exportDemoHistory;
window.openScanModal = openScanModal;
window.closeScanModal = closeScanModal;
window.copyModalReport = copyModalReport;
window.copyReportToClipboard = copyReportToClipboard;
window.toggleJsonAccordion = toggleJsonAccordion;
