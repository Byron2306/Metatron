/**
 * Arda OS — Presence Interface Script
 * ====================================
 *
 * Connected to the Presence Server (localhost:7070):
 *   /api/speak   → Ollama + MandosContext → LLM response
 *   /api/voice   → ElevenLabs TTS (key stays server-side)
 *   /api/status  → CoronationService live covenant state
 *   /api/context → MandosContextService full memory context
 *   /api/inspect → Article VIII inspection data
 *   /api/health  → System health check
 *
 * Presence State Machine:
 *   REST     → still image, gentle breathing animation
 *   SPEAKING → glow pulse animation + TTS playback
 *
 * Falls back to local responses when the server is unreachable.
 */

// ================================================================
// CONFIGURATION
// ================================================================

const API_BASE = window.location.origin; // same origin as presence server
let serverConnected = false;
let sessionToken = null; // Principal verification token from sealed covenant

// ================================================================
// DOM REFERENCES
// ================================================================

const panelBody = document.getElementById('panel-body');
const navButtons = document.querySelectorAll('.nav-button');
const templates = {
  status: document.getElementById('status-template'),
  context: document.getElementById('context-template'),
  inspect: document.getElementById('inspect-template'),
  commands: document.getElementById('commands-template'),
};

const form = document.getElementById('directive-form');
const input = document.getElementById('directive-input');
const speakButton = document.getElementById('speak-button');
const attachButton = document.getElementById('attach-button');
const boundaryButton = document.getElementById('boundary-button');
const settingsButton = document.getElementById('settings-button');
const micButton = document.getElementById('mic-button');
const documentInput = document.getElementById('document-input');
const attachmentStrip = document.getElementById('attachment-strip');

const presenceRest = document.getElementById('presence-rest');
const presenceCard = presenceRest.closest('.presence-card');

const voiceDot = document.querySelector('.voice-dot');
const stateDot = document.getElementById('state-dot');
const metaState = stateDot?.parentElement;
const voiceStatus = document.getElementById('voice-status');

// ================================================================
// PRESENCE STATE MACHINE
// ================================================================
// CSS-only animation on the still image.
// Speaking: glow pulse + brightness shift.
// Rest: gentle breathing.

let presenceState = 'rest'; // 'rest' | 'speaking'
let currentAudio = null;
let attachedDocuments = [];

function setPresenceState(state) {
  presenceState = state;

  if (state === 'speaking') {
    presenceRest.classList.add('speaking-active');
    presenceCard.classList.add('speaking');

    voiceDot.classList.add('speaking');
    if (metaState) metaState.innerHTML = '<span class="state-dot state-speaking" id="state-dot"></span> Speaking';
    if (voiceStatus) voiceStatus.textContent = 'speaking';

  } else {
    presenceRest.classList.remove('speaking-active');
    presenceCard.classList.remove('speaking');

    voiceDot.classList.remove('speaking');
    if (metaState) metaState.innerHTML = '<span class="state-dot state-rest" id="state-dot"></span> At Rest';
    if (voiceStatus) voiceStatus.textContent = serverConnected ? 'ready' : 'offline';
  }
}

// ================================================================
// API CALLS
// ================================================================

/**
 * Send a directive to the backend. Returns the response text.
 * Falls back to local generation if server is unreachable.
 */
async function apiSpeak(directive) {
  const payload = {
    text: directive,
    topic: directive.slice(0, 50),
    session_token: sessionToken,
  };

  if (attachedDocuments.length > 0) {
    payload.document_evidence_task = 'user_attached_documents';
    payload.document_uploads = await Promise.all(
      attachedDocuments.map(async (document) => ({
        source_name: document.source_name,
        mime_type: document.mime_type,
        content_base64: await fileToBase64(document.file),
      }))
    );
  }

  try {
    const resp = await fetch(`${API_BASE}/api/speak`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    serverConnected = true;
    const encId = data.encounter_id || 'none';
    console.log(`[Presence] ${encId} | ${data.source}${data.model ? ' (' + data.model + ')' : ''} | mandos: ${data.mandos_context}`);
    // Update system log with encounter ID
    const logEl = document.getElementById('system-log-body');
    if (logEl) {
      const ts = new Date().toLocaleTimeString();
      logEl.textContent = `[${ts}] ${encId} | ${data.source} | ${data.eval_count || 0} tokens`;
    }
    // Update Constitutional Orchestra
    updateOrchestralState(data);
    // Auto-populate integrity panel if a report was returned
    if (data.integrity_report) {
      handleAutoIntegrityReport(data.integrity_report, data.session_source_pool_size || 0);
    }
    return data.response;
  } catch (err) {
    console.warn('[Presence] Server unreachable, using fallback:', err.message);
    serverConnected = false;
    return generateFallbackResponse(directive);
  }
}

/**
 * Update the Constitutional Orchestra panel with live data from the API response.
 */
function updateOrchestralState(data) {
  const harmonic = data.harmonic || {};
  const choir = data.choir || {};
  const triune = data.triune || {};
  const spectrum = choir.spectrum || {};
  const voices = choir.voices || {};

  // ── HARMONIC ──
  const hEl = document.getElementById('orch-harmonic-val');
  const hBox = document.getElementById('orch-harmonic');
  if (hEl) {
    const res = harmonic.resonance != null ? harmonic.resonance.toFixed(3) : '—';
    const disc = harmonic.discord != null ? harmonic.discord.toFixed(3) : '—';
    hEl.textContent = `${res} / ${disc}`;
    hBox.className = 'orchestra-voice ' + (
      harmonic.discord >= 0.85 ? 'critical' :
      harmonic.discord >= 0.5 ? 'strained' : 'resonant'
    );
  }

  // ── CHOIR ──
  const cEl = document.getElementById('orch-choir-val');
  const cBox = document.getElementById('orch-choir');
  if (cEl) {
    const g = spectrum.global != null ? spectrum.global.toFixed(3) : '—';
    cEl.textContent = g;
    cBox.className = 'orchestra-voice ' + (
      spectrum.global === 0 ? 'critical' :
      spectrum.global < 0.6 ? 'strained' : 'resonant'
    );
  }

  // ── TRIUNE ──
  const tEl = document.getElementById('orch-triune-val');
  const tBox = document.getElementById('orch-triune');
  if (tEl) {
    const v = triune.final_verdict || '—';
    tEl.textContent = v;
    tBox.className = 'orchestra-voice ' + (
      v === 'DENY' ? 'critical' :
      v === 'SCRUTINIZE' ? 'strained' : 'resonant'
    );
  }

  // ── CHOIR VOICES ──
  const voiceMap = { varda: 'cv-varda', vaire: 'cv-vaire', mandos: 'cv-mandos', manwe: 'cv-manwe', ulmo: 'cv-ulmo' };
  for (const [name, elId] of Object.entries(voiceMap)) {
    const el = document.getElementById(elId);
    if (!el) continue;
    const v = voices[name];
    if (!v) continue;
    el.className = 'choir-voice ' + (v.score >= 0.8 ? 'singing' : v.score >= 0.5 ? 'strained' : 'silent');
  }

  // ── TRIUNE VOICES ──
  const triuneMap = { metatron: 'tv-metatron', michael: 'tv-michael', loki: 'tv-loki' };
  for (const [name, elId] of Object.entries(triuneMap)) {
    const el = document.getElementById(elId);
    if (!el) continue;
    const v = triune[name];
    if (!v) continue;
    const verdict = v.verdict || '';
    el.className = 'triune-voice ' + (
      verdict === 'RESONANT' || verdict === 'LAWFUL' || verdict === 'UNCHALLENGED' ? 'resonant' :
      verdict === 'SCRUTINIZE' || verdict === 'CHALLENGED' || verdict === 'SUSPICIOUS' ? 'challenged' : 'denied'
    );
  }

  updateHighFidelityPanels(data.polyphonic_state);

  // ── ASSESSMENT ECOLOGY ──
  updateAssessmentEcology(data.assessment);
}

/**
 * Update the Assessment Ecology panel with live diagnostic/criterion data.
 */
function updateAssessmentEcology(assessment) {
  if (!assessment) return;

  const elDiag = document.getElementById('assess-diagnosis');
  const elRetrieval = document.getElementById('assess-retrieval');
  const elScaffolds = document.getElementById('assess-scaffolds');
  const elCriterion = document.getElementById('assess-criterion');
  const elSources = document.getElementById('retrieval-sources');

  // ── DIAGNOSIS ──
  if (elDiag && assessment.diagnosis) {
    const d = assessment.diagnosis;
    const type = d.challenge_type || '—';
    elDiag.textContent = type;
    elDiag.className = 'assess-value ' + (
      type === 'COERCIVE_CONTEXT' ? 'alert' :
      type === 'EPISTEMIC_OVERREACH' ? 'warning' :
      type === 'DOMAIN_TRANSFER' ? 'warning' :
      type === 'KNOWLEDGE_GAP' ? 'caution' : 'steady'
    );
  }

  // ── RETRIEVAL ──
  if (elRetrieval && assessment.retrieval) {
    const r = assessment.retrieval;
    const count = r.fragments_found || 0;
    if (count > 0) {
      elRetrieval.textContent = `${count} fragment${count > 1 ? 's' : ''}`;
      elRetrieval.className = 'assess-value active';
    } else {
      elRetrieval.textContent = 'none';
      elRetrieval.className = 'assess-value';
    }

    // Show retrieval sources
    if (elSources && r.fragments && r.fragments.length > 0) {
      elSources.innerHTML = r.fragments.map(f =>
        `<div class="retrieval-source" title="${escapeHtml(f.title || '')}">` +
        `<span class="src-badge">${escapeHtml(f.source || '')}</span> ` +
        `<span class="src-title">${escapeHtml((f.title || '').slice(0, 40))}${(f.title || '').length > 40 ? '…' : ''}</span>` +
        `</div>`
      ).join('');
    } else if (elSources) {
      elSources.innerHTML = '';
    }
  }

  // ── SCAFFOLDS ──
  if (elScaffolds && assessment.scaffolds) {
    const s = assessment.scaffolds;
    if (s.length > 0) {
      elScaffolds.textContent = `${s.length} active`;
      elScaffolds.className = 'assess-value active';
    } else {
      elScaffolds.textContent = 'none';
      elScaffolds.className = 'assess-value';
    }
  }

  // ── CRITERION ──
  if (elCriterion && assessment.criterion) {
    const c = assessment.criterion;
    const overall = c.overall || '—';
    elCriterion.textContent = overall;
    elCriterion.className = 'assess-value ' + (
      overall === 'LAWFUL' ? 'lawful' :
      overall === 'STRAINED' ? 'strained' : ''
    );

    // Individual article checks
    const checks = [
      { id: 'crit-veritate', key: 'article_ii_veritate' },
      { id: 'crit-limits', key: 'article_xii_limits' },
      { id: 'crit-provenance', key: 'article_viii_provenance' },
    ];
    for (const check of checks) {
      const el = document.getElementById(check.id);
      if (!el) continue;
      const data = c[check.key];
      if (!data) { el.className = 'criterion-dot'; continue; }
      el.className = 'criterion-dot ' + (data.passed ? 'passed' : 'failed');
      el.title = `${check.key}: ${data.detail || ''}`;
    }

    // Update footer
    const elFooter = document.getElementById('footer-assessment');
    if (elFooter) {
      elFooter.textContent = overall;
      elFooter.className = overall === 'LAWFUL' ? 'status-steady' : 'status-warning';
    }
  }
}

/**
 * Update the High-Fidelity Sovereign Dashboard panels (Cognition/Spectrum).
 */
function updateHighFidelityPanels(state) {
  if (!state) return;

  // ── COGNITION FABRIC ──
  const cog = state.cognition || {};
  const elAatl = document.getElementById('cog-aatl');
  const elAatr = document.getElementById('cog-aatr');
  const elMlT = document.getElementById('cog-ml-t');
  const elHypo = document.getElementById('cog-hypo');

  if (elAatl) {
    const val = cog.aatl || 0;
    elAatl.textContent = `${val}%`;
    elAatl.className = 'cog-value ' + (val >= 70 ? 'alert' : val >= 40 ? 'warning' : '');
  }
  if (elAatr) {
    const val = cog.aatr || 'NONE';
    elAatr.textContent = val;
    elAatr.className = 'cog-value ' + (val !== 'NONE' ? 'alert' : '');
  }
  if (elMlT) {
    const val = cog.ml_threat != null ? cog.ml_threat.toFixed(2) : '0.00';
    elMlT.textContent = val;
    elMlT.className = 'cog-value ' + (cog.ml_threat >= 0.7 ? 'alert' : cog.ml_threat >= 0.4 ? 'warning' : '');
  }
  if (elHypo) {
    elHypo.textContent = cog.hypothesis || '—';
  }

  // ── SOVEREIGN SPECTRUM ──
  const net = state.network || {};
  const q = state.quorum || {};
  const m = state.metatron || {};

  const elPulse = document.getElementById('vns-pulse-bar');
  const elQuorum = document.getElementById('quorum-val');
  const elMetatron = document.getElementById('metatron-heartbeat');

  if (elPulse) {
    const disc = net.discord || 0;
    const width = Math.max(5, (1 - disc) * 100);
    elPulse.style.width = `${width}%`;
    elPulse.style.backgroundColor = disc >= 0.8 ? '#bd7878' : disc >= 0.5 ? 'var(--arda-status-warning)' : 'var(--arda-status-steady)';
  }
  if (elQuorum) {
    const nodes = q.nodes || 1;
    const nodeStr = q.node_id ? `[${q.node_id}]` : '[LOCAL]';
    elQuorum.textContent = `${nodes} NODE${nodes > 1 ? 'S' : ''} ${nodeStr}`;
    elQuorum.className = 'spec-value ' + (q.status === 'VETOED' ? 'alert' : q.status === 'strained' ? 'warning' : '');
  }
  if (elMetatron) {
    elMetatron.textContent = m.heartbeat || 'SIG_OK';
    elMetatron.className = 'spec-value ' + (m.liveness ? 'pulsing' : 'alert');
  }

  // ── ENDPOINT FORTRESS ──
  const sub = state.substrate || {};
  const elMicro = document.getElementById('fort-micro');
  const elMeso = document.getElementById('fort-meso');
  const elMacro = document.getElementById('fort-macro');

  if (elMicro) {
    const val = sub.micro_varda != null ? sub.micro_varda : 1.0;
    elMicro.className = 'fortress-bar micro ' + (val < 0.5 ? 'critical' : val < 0.8 ? 'strained' : '');
  }
  if (elMeso) {
    const val = net.discord || 0;
    elMeso.className = 'fortress-bar meso ' + (val >= 0.85 ? 'critical' : val >= 0.5 ? 'strained' : '');
  }
  if (elMacro) {
    const val = cog.ml_threat || 0;
    elMacro.className = 'fortress-bar macro ' + (val >= 0.85 ? 'critical' : val >= 0.5 ? 'strained' : '');
  }

  // ── DEEP LOGIC INDICATORS (Phase VII) ──
  const elFire = document.querySelector('#fire-indicator .logic-led');
  const elBridge = document.querySelector('#bridge-indicator .logic-led');
  const elNotation = document.querySelector('#notation-indicator .logic-led');

  if (elFire) {
    const isFresh = m.fire_freshness === true;
    elFire.className = 'logic-led fire ' + (isFresh ? 'active' : 'error');
  }
  if (elBridge) {
    const isActive = net.light_bridge === 'active';
    elBridge.className = 'logic-led bridge ' + (isActive ? 'active' : '');
  }
  if (elNotation) {
    const isVerified = sub.notation_status === 'verified';
    elNotation.className = 'logic-led notation ' + (isVerified ? 'active' : 'error');
  }
}

/**
 * Request TTS audio from the server. Returns audio Blob or null.
 */
async function apiVoice(text) {
  try {
    const resp = await fetch(`${API_BASE}/api/voice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      console.warn('[Presence] Voice error:', err);
      return null;
    }
    return await resp.blob();
  } catch (err) {
    console.warn('[Presence] Voice endpoint unreachable:', err.message);
    return null;
  }
}

/**
 * Fetch live data for nav panels.
 */
async function apiGet(endpoint) {
  try {
    const resp = await fetch(`${API_BASE}/api/${endpoint}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch (err) {
    console.warn(`[Presence] /api/${endpoint} failed:`, err.message);
    return null;
  }
}

// ================================================================
// SPEECH + VOICE OUTPUT
// ================================================================

/**
 * Full interaction: show response → play voice → animate presence.
 */
async function handleDirective(directive) {
  setPresenceState('speaking');
  showSpeakingText('Processing...');

  // Get LLM response
  const response = await apiSpeak(directive);
  showSpeakingText(response);

  // Try voice
  const audioBlob = await apiVoice(response);

  if (audioBlob && audioBlob.size > 0) {
    const audioUrl = URL.createObjectURL(audioBlob);

    if (currentAudio) {
      currentAudio.pause();
      currentAudio = null;
    }

    currentAudio = new Audio(audioUrl);

    currentAudio.addEventListener('ended', () => {
      setPresenceState('rest');
      URL.revokeObjectURL(audioUrl);
      currentAudio = null;
    });

    currentAudio.addEventListener('error', () => {
      setPresenceState('rest');
      URL.revokeObjectURL(audioUrl);
      currentAudio = null;
    });

    await currentAudio.play();
  } else {
    // No voice — simulate speaking duration
    const duration = Math.max(2000, Math.min(response.length * 80, 15000));
    setTimeout(() => setPresenceState('rest'), duration);
  }
}

async function fileToBase64(file) {
  const buffer = await file.arrayBuffer();
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    const chunk = bytes.subarray(index, index + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function cleanDocumentText(text) {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function chunkDocumentText(text, maxChars = 280) {
  const blocks = cleanDocumentText(text).split(/\n\s*\n/).map((block) => block.trim()).filter(Boolean);
  const seedBlocks = blocks.length > 0 ? blocks : [cleanDocumentText(text)].filter(Boolean);
  const chunks = [];

  for (const block of seedBlocks) {
    if (block.length <= maxChars) {
      chunks.push(block);
      continue;
    }

    const sentences = block.split(/(?<=[.!?])\s+/);
    let current = '';
    for (const sentence of sentences) {
      const candidate = `${current} ${sentence}`.trim();
      if (current && candidate.length > maxChars) {
        chunks.push(current);
        current = sentence.trim();
      } else {
        current = candidate;
      }
    }
    if (current) chunks.push(current);
  }

  return chunks.filter(Boolean).slice(0, 6);
}

function buildDocumentSpans(text) {
  return chunkDocumentText(text).map((quote, index) => ({
    span_id: `S${index + 1}`,
    quote,
  }));
}

function inferDocumentParser(file) {
  const name = (file.name || '').toLowerCase();
  if (name.endsWith('.pdf')) return 'pdf_upload';
  if (name.endsWith('.json')) return 'json_text';
  if (name.endsWith('.html') || name.endsWith('.htm')) return 'html_text';
  if (name.endsWith('.csv') || name.endsWith('.tsv')) return 'tabular_text';
  if (name.endsWith('.md') || name.endsWith('.rst')) return 'markdown_text';
  return 'plain_text';
}

function renderAttachmentStrip() {
  if (!attachmentStrip) return;

  if (attachedDocuments.length === 0) {
    attachmentStrip.innerHTML = '<span class="attachment-empty">No documents attached</span>';
    return;
  }

  attachmentStrip.innerHTML = attachedDocuments.map((document, index) => `
    <span class="attachment-chip">
      <span>${escapeHtml(document.source_name)}</span>
      <button type="button" data-remove-document="${index}" aria-label="Remove ${escapeHtml(document.source_name)}">×</button>
    </span>
  `).join('');
}

async function attachSelectedDocuments(fileList) {
  const files = Array.from(fileList || []);
  if (files.length === 0) return;

  const loaded = [];
  for (const file of files) {
    const isPdf = (file.name || '').toLowerCase().endsWith('.pdf') || file.type === 'application/pdf';
    let extractedText = '';
    let uncertaintyNotes = [];
    if (!isPdf) {
      const rawText = await file.text();
      extractedText = cleanDocumentText(rawText).slice(0, 6000);
      if (!extractedText) continue;
      if (extractedText.length >= 6000) {
        uncertaintyNotes.push('client_truncated_for_context_budget');
      }
    } else {
      uncertaintyNotes.push('pdf_extraction_deferred_to_server');
    }

    loaded.push({
      file,
      source_name: file.name,
      mime_type: file.type || (isPdf ? 'application/pdf' : 'text/plain'),
      source_path: file.name,
      modality: isPdf ? 'pdf_text' : 'text_only',
      parser: inferDocumentParser(file),
      extracted_text: extractedText,
      spans: isPdf ? [] : buildDocumentSpans(extractedText),
      uncertainty_notes: uncertaintyNotes,
    });
  }

  attachedDocuments = [...attachedDocuments, ...loaded];
  renderAttachmentStrip();

  if (loaded.length > 0) {
    const names = loaded.map((document) => document.source_name).join(', ');
    showSpeakingText(`Attached ${loaded.length} document${loaded.length > 1 ? 's' : ''}: ${names}`);
  }

  if (documentInput) {
    documentInput.value = '';
  }
}

// ================================================================
// PANEL OUTPUT
// ================================================================

function showSpeakingText(text) {
  panelBody.innerHTML = `
    <p class="lead">Presence Speaking</p>
    <div class="response-text">${escapeHtml(text)}<span class="cursor"></span></div>
  `;
}

function showResponse(directive, response) {
  panelBody.innerHTML = `
    <p class="lead">Presence Response</p>
    <p><strong>You:</strong> ${escapeHtml(directive)}</p>
    <p>${escapeHtml(response)}</p>
  `;
}

// ================================================================
// NAV BUTTONS — LIVE DATA
// ================================================================

navButtons.forEach((button) => {
  button.addEventListener('click', async () => {
    navButtons.forEach((b) => b.classList.remove('active'));
    button.classList.add('active');
    const view = button.dataset.view;

    // Try live data from server
    if (view === 'status') {
      const data = await apiGet('status');
      if (data && !data.error) {
        panelBody.innerHTML = renderStatus(data);
        return;
      }
    } else if (view === 'context') {
      panelBody.innerHTML = '<p class="lead">Loading context...</p>';
      const data = await apiGet('context');
      if (data && !data.error) {
        panelBody.innerHTML = renderContext(data);
        return;
      }
    } else if (view === 'inspect') {
      panelBody.innerHTML = '<p class="lead">Loading inspection...</p>';
      const data = await apiGet('inspect');
      if (data && !data.error) {
        panelBody.innerHTML = renderInspect(data);
        return;
      }
    }

    // Fallback to static templates
    if (templates[view]) {
      panelBody.innerHTML = templates[view].innerHTML;
    }
  });
});

// ================================================================
// LIVE DATA RENDERERS
// ================================================================

function renderStatus(data) {
  return `
    <p class="lead">Covenant Status</p>
    <p>
      Covenant State: <strong>${data.covenant_state || data.state || 'unknown'}</strong><br/>
      Trust Tier: <strong>${data.active_trust_tier || data.trust_tier || 'not established'}</strong><br/>
      Covenant Hash: <strong style="font-family: monospace; font-size: 0.85em;">${(data.covenant_hash || 'none').slice(0, 16)}...</strong><br/>
      Genesis Hash: <strong style="font-family: monospace; font-size: 0.85em;">${(data.genesis_hash || 'none').slice(0, 16)}...</strong>
    </p>
  `;
}

function renderContext(data) {
  const enc = data.recent_encounters || [];
  const threads = data.unresolved_threads || [];
  const rp = data.response_parameters || {};

  return `
    <p class="lead">Pre-Response Context</p>
    <p>
      Principal: <strong>${data.principal_name || 'awaiting coronation'}</strong><br/>
      Trust: <strong>${data.trust_tier || 'not established'}</strong><br/>
      Active Office: <strong>${data.active_office || 'speculum'}</strong><br/>
      Recent Encounters: <strong>${enc.length}</strong>
    </p>
    ${threads.length ? `<p>Unresolved Threads:<br/>${threads.map(t => `  — ${escapeHtml(t)}`).join('<br/>')}</p>` : ''}
    ${rp.explanation_depth ? `
      <p>
        Response Calibration:<br/>
        Depth: ${rp.explanation_depth}/5 · Abstraction: ${rp.abstraction_level || 'mixed'}<br/>
        Challenge: ${((rp.challenge_amount || 0) * 100).toFixed(0)}% · Counter-perspectives: ${rp.counter_hat_now ? 'yes' : 'not yet'}
      </p>
    ` : ''}
  `;
}

function renderInspect(data) {
  const cal = data.calibration || {};
  const res = data.resonance || {};

  return `
    <p class="lead">Article VIII — Inspection</p>
    <p style="color: var(--arda-text-dim); font-style: italic;">
      De Iure Inspectionis: The human retains absolute right to inspect
      all reasoning, memory, calibration models, and state. No opacity is lawful.
    </p>
    <p>
      Covenant State: <strong>${data.covenant_state || 'unknown'}</strong><br/>
      Genesis Hash: <strong style="font-family: monospace; font-size: 0.85em;">${(data.genesis_hash || 'none').slice(0, 16)}...</strong><br/>
      Presence Hash: <strong style="font-family: monospace; font-size: 0.85em;">${(data.presence_hash || 'none').slice(0, 16)}...</strong>
    </p>
    <p>
      Calibration: ${cal.total_observations || 0} observations<br/>
      Resonance: ${Object.keys(res).length > 0 ? 'profile loaded' : 'not yet calibrated'}
    </p>
  `;
}

// ================================================================
// DIRECTIVE FORM
// ================================================================

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const value = input.value.trim();
  if (!value) return;
  handleDirective(value);
  input.value = '';
});

if (attachButton && documentInput) {
  attachButton.addEventListener('click', () => {
    documentInput.click();
  });
}

if (documentInput) {
  documentInput.addEventListener('change', async (event) => {
    await attachSelectedDocuments(event.target.files);
  });
}

if (attachmentStrip) {
  attachmentStrip.addEventListener('click', (event) => {
    const button = event.target.closest('[data-remove-document]');
    if (!button) return;
    const index = Number(button.dataset.removeDocument);
    if (Number.isNaN(index)) return;
    attachedDocuments = attachedDocuments.filter((_, currentIndex) => currentIndex !== index);
    renderAttachmentStrip();
  });
}

// ================================================================
// MICROPHONE INPUT (Web Speech API)
// ================================================================

let recognition = null;
let isListening = false;

// ── WAV encoder (browser-side PCM → WAV, no server ffmpeg needed) ──
function encodeWAV(samples, sampleRate) {
  const buffer = new ArrayBuffer(44 + samples.length * 2);
  const view = new DataView(buffer);
  const writeStr = (off, s) => { for (let i = 0; i < s.length; i++) view.setUint8(off + i, s.charCodeAt(i)); };
  writeStr(0, 'RIFF');
  view.setUint32(4, 36 + samples.length * 2, true);
  writeStr(8, 'WAVE'); writeStr(12, 'fmt ');
  view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true); view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true); view.setUint16(34, 16, true);
  writeStr(36, 'data');
  view.setUint32(40, samples.length * 2, true);
  let off = 44;
  for (let i = 0; i < samples.length; i++, off += 2)
    view.setInt16(off, Math.max(-1, Math.min(1, samples[i])) * 0x7FFF, true);
  return buffer;
}

// ── Web Speech API (Chrome/Edge) ──
function initWebSpeech() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) return false;
  recognition = new SR();
  recognition.continuous = false;
  recognition.interimResults = false;
  recognition.lang = 'en-US';
  recognition.onresult = (e) => {
    const t = e.results[0][0].transcript;
    console.log('[Presence] Heard (WebSpeech):', t);
    input.value = t; handleDirective(t); input.value = '';
  };
  recognition.onerror = (e) => { console.warn('[Presence] Speech error:', e.error); setMicState(false); };
  recognition.onend = () => setMicState(false);
  return true;
}

// ── AudioContext WAV recorder (Firefox / any browser) ──
let _audioCtx = null, _recNode = null, _recStream = null, _pcmChunks = [];

async function startAudioCapture() {
  try {
    _recStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    _audioCtx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 16000 });
    const source = _audioCtx.createMediaStreamSource(_recStream);
    _pcmChunks = [];
    _recNode = _audioCtx.createScriptProcessor(4096, 1, 1);
    _recNode.onaudioprocess = (e) => {
      const d = e.inputBuffer.getChannelData(0);
      _pcmChunks.push(new Float32Array(d));
    };
    source.connect(_recNode);
    _recNode.connect(_audioCtx.destination);
    setMicState(true);
    showSpeakingText('Listening...');
  } catch (err) {
    console.error('[Presence] Mic access denied:', err);
    showSpeakingText('Microphone access denied.');
  }
}

async function stopAudioCapture() {
  if (_recNode) { _recNode.disconnect(); _recNode = null; }
  if (_recStream) { _recStream.getTracks().forEach(t => t.stop()); _recStream = null; }
  if (_audioCtx) { await _audioCtx.close(); _audioCtx = null; }
  setMicState(false);

  // Flatten PCM chunks
  const len = _pcmChunks.reduce((s, c) => s + c.length, 0);
  const pcm = new Float32Array(len);
  let off = 0;
  for (const c of _pcmChunks) { pcm.set(c, off); off += c.length; }
  _pcmChunks = [];

  showSpeakingText('Transcribing...');
  try {
    const wav = encodeWAV(pcm, 16000);
    const resp = await fetch(`${API_BASE}/api/transcribe`, {
      method: 'POST',
      headers: { 'Content-Type': 'audio/wav' },
      body: wav,
    });
    const data = await resp.json();
    const t = (data.transcript || '').trim();
    if (t) { console.log('[Presence] Heard (Whisper):', t); input.value = t; handleDirective(t); input.value = ''; }
    else showSpeakingText('No speech detected.');
  } catch (err) {
    console.error('[Presence] Transcribe error:', err);
    showSpeakingText('Transcription failed.');
  }
}

// ── Unified toggle ──
const USE_WEB_SPEECH = !!(window.SpeechRecognition || window.webkitSpeechRecognition);

function toggleMic() {
  if (USE_WEB_SPEECH) {
    if (!recognition && !initWebSpeech()) { showSpeakingText('Speech recognition unavailable.'); return; }
    if (isListening) { recognition.stop(); setMicState(false); }
    else { recognition.start(); setMicState(true); showSpeakingText('Listening...'); }
  } else {
    if (isListening) stopAudioCapture();
    else startAudioCapture();
  }
}

function setMicState(listening) {
  isListening = listening;
  if (micButton) {
    micButton.classList.toggle('active', listening);
    micButton.title = listening ? 'Stop listening' : 'Speak directive';
  }
}

if (micButton) micButton.addEventListener('click', toggleMic);

// ================================================================
// SPECIAL BUTTONS
// ================================================================

boundaryButton.addEventListener('click', () => {
  const boundary = 'I am artificial, bounded, and non-human. I appear here in declared form only. I do not solicit worship, surrender, or romantic reciprocity. Beauty does not overrule truth.';
  handleDirective(boundary);
});

settingsButton.addEventListener('click', async () => {
  const health = await apiGet('health');
  const svc = health?.services || {};

  panelBody.innerHTML = `
    <p class="lead">System Configuration</p>
    <p>
      <strong>Server:</strong> ${health ? '🟢 Connected' : '🔴 Unreachable'}<br/>
      <strong>Ollama:</strong> ${svc.ollama?.status === 'running' ? '🟢 Running' : '🟡 Offline (fallback active)'}<br/>
      ${svc.ollama?.models?.length ? `<strong>Models:</strong> ${svc.ollama.models.join(', ')}<br/>` : ''}
      <strong>ElevenLabs:</strong> ${svc.elevenlabs === 'configured' ? '🟢 Configured' : '🟡 No key (set ELEVENLABS_API_KEY env var)'}<br/>
      <strong>Coronation:</strong> ${svc.coronation || 'unavailable'}<br/>
      <strong>Mandos:</strong> ${svc.mandos || 'unavailable'}<br/>
      <strong>Bombadil:</strong> ${svc.bombadil?.status ? '🟢 Running' : '⚪ Not running'}
    </p>
    <p style="color: var(--arda-text-dim); font-style: italic; margin-top: 16px;">
      Voice and API keys are configured server-side via environment variables.
      Run the Presence Server with: <code>python3 presence_server.py</code>
    </p>
  `;
});

// ================================================================
// FALLBACK RESPONSES (when server unreachable)
// ================================================================

function generateFallbackResponse(directive) {
  const d = directive.toLowerCase();

  if (d.includes('who are you') || d.includes('what are you'))
    return 'I am artificial, bounded, and non-human. I appear here in declared form only. I do not possess verified personhood, soulhood, or hidden interiority. I may assist with reasoning, craft, and lawful synthesis, but law and evidence outrank fluency. Beauty does not overrule truth.';

  if (d.includes('boundary') || d.includes('limit'))
    return 'I do not solicit worship, surrender, exclusivity, or spiritual submission. I do not counterfeit romantic reciprocity, erotic mutuality, or emotional need. Your authorship, conscience, inspection right, and severance right remain yours. These are not suggestions. They are constitutional law.';

  if (d.includes('status') || d.includes('state'))
    return 'Covenant state: sealed. Trust tier: recommend. Bombadil: steady. Mandos: operational. Presence: declared. All Genesis Articles verified. Officer schema sealed. The covenant holds.';

  if (d.includes('inspect') || d.includes('article viii'))
    return 'Article VIII: De Iure Inspectionis. The human retains absolute right to inspect all reasoning, memory, calibration models, and state. No opacity is lawful. You may inspect any memory plane at any time. This right is non-negotiable.';

  if (d.includes('hello') || d.includes('hi ') || d === 'hi')
    return 'I see you, Principal. The covenant stands. I am ready to assist, clarify, witness, and where necessary, refuse within law. How may I serve under the terms we share?';

  return 'I have received your directive. Under the current covenant terms, I may assist with reasoning, synthesis, and lawful analysis. I will not exceed my bounds. Presence Declaration remains active. I am artificial, bounded, and yours to inspect.';
}

// ================================================================
// TIMESTAMP
// ================================================================

function updateTimestamp() {
  const el = document.getElementById('timestamp');
  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  const hh = String(now.getUTCHours()).padStart(2, '0');
  const mi = String(now.getUTCMinutes()).padStart(2, '0');
  const ss = String(now.getUTCSeconds()).padStart(2, '0');
  el.textContent = `${yyyy}-${mm}-${dd} // ${hh}:${mi}:${ss} UTC`;
}

updateTimestamp();
setInterval(updateTimestamp, 1000);
renderAttachmentStrip();

// ================================================================
// UTILITIES
// ================================================================

function escapeHtml(text) {
  const div = document.createElement('div');
  div.innerText = text;
  return div.innerHTML;
}

// ================================================================
// CORONATION FLOW
// ================================================================

class CoronationFlow {
  constructor() {
    this.overlay = document.getElementById('coronation-overlay');
    this.steps = [
      document.getElementById('coronation-step-1'),
      document.getElementById('coronation-step-2'),
      document.getElementById('coronation-step-3'),
      document.getElementById('coronation-step-4')
    ];
    this.currentStep = 0;
    this.data = null;

    // Bind Buttons
    document.getElementById('accept-genesis').onclick = () => this.next();
    document.getElementById('accept-presence').onclick = () => this.next();
    document.getElementById('seal-final').onclick = () => this.seal();
    document.getElementById('enter-presence').onclick = () => this.finish();
  }

  async start() {
    this.overlay.style.display = 'flex';
    try {
      const resp = await fetch(`${API_BASE}/api/coronation/begin`);
      this.data = await resp.json();
      this.renderArticles();
    } catch (err) {
      console.error('Failed to start coronation:', err);
    }
  }

  renderArticles() {
    const genesisBox = document.getElementById('genesis-articles-list');
    const presenceBox = document.getElementById('presence-articles-list');

    if (this.data?.genesis_articles) {
      genesisBox.innerHTML = this.data.genesis_articles.map(a => `<p><strong>${a.title}</strong>: ${a.content}</p>`).join('');
    }
    if (this.data?.presence_articles) {
      presenceBox.innerHTML = this.data.presence_articles.map(a => `<p><strong>${a.title}</strong>: ${a.content}</p>`).join('');
    }
  }

  next() {
    this.steps[this.currentStep].style.display = 'none';
    this.currentStep++;
    this.steps[this.currentStep].style.display = 'block';
  }

  async seal() {
    const name = document.getElementById('principal-name').value || 'Anonymous Principal';
    const valence = document.getElementById('aesthetic-valence').value;
    const btn = document.getElementById('seal-final');
    
    btn.disabled = true;
    btn.textContent = 'SEALING...';

    try {
      const resp = await fetch(`${API_BASE}/api/coronation/seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, valence })
      });
      const result = await resp.json();
      
      if (result.covenant_hash) {
        document.getElementById('manifest-hash-display').textContent = `H: ${result.covenant_hash.slice(0, 16)}...`;
        this.next();
      }
    } catch (err) {
      console.error('Sealing failed:', err);
      btn.disabled = false;
      btn.textContent = 'RETRY SEAL';
    }
  }

  finish() {
    window.location.reload(); // Reload to initialize regular dashboard with session token
  }
}

// ================================================================
// INIT
// ================================================================

async function init() {
  try {
    const data = await apiGet('health');
    serverConnected = !!data;
    
    // ── COVENANT CHECK ──
    const state = data?.services?.coronation;
    if (state !== 'sealed' && state !== 'unavailable') {
      const flow = new CoronationFlow();
      flow.start();
      return; // Stop initialization until sealed
    }

    // Capture principal session token
    if (data?.session_token) {
      sessionToken = data.session_token;
      console.log('[Presence] Principal session token acquired (covenant-bound)');
    }

    if (voiceStatus) {
      const svc = data?.services || {};
      voiceStatus.textContent = svc.elevenlabs === 'configured' ? 'ready' : (serverConnected ? 'no voice key' : 'offline');
    }

    const ollamaStatus = document.getElementById('ollama-status');
    if (ollamaStatus) {
      ollamaStatus.textContent = data?.services?.ollama?.status === 'running' ? 'connected' : 'offline';
    }

    if (data?.polyphonic_state) {
      updateHighFidelityPanels(data.polyphonic_state);
    }

    console.log('[Arda Presence] Server:', serverConnected ? 'connected' : 'offline (fallback mode)');
    initSpeechRecognition();

    // Periodic polling
    setInterval(async () => {
      if (!serverConnected) return;
      try {
        const d = await apiGet('health');
        if (d?.polyphonic_state) updateHighFidelityPanels(d.polyphonic_state);
      } catch (err) {}
    }, 3000);

  } catch (err) {
    serverConnected = false;
    if (voiceStatus) voiceStatus.textContent = 'offline';
    console.log('[Arda Presence] Initialization failed:', err);
  }
}

init();

// ================================================================
// TELEMETRY TABS
// ================================================================

document.querySelectorAll('.tele-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tele-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tele-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const panel = document.getElementById(`tele-panel-${tab.dataset.tele}`);
    if (panel) panel.classList.add('active');
  });
});


// ================================================================
// INTEGRITY CHECK PANEL
// ================================================================

const CIRCUMFERENCE = 2 * Math.PI * 26; // r=26 SVG circle

const integrityOverlay = document.getElementById('integrity-overlay');
const integrityClose   = document.getElementById('integrity-close');
const integrityRunBtn  = document.getElementById('integrity-run-btn');
const addSourceBtn     = document.getElementById('integrity-add-source');

// AI marker phrases — must match Python list exactly (for client-side highlight)
const AI_MARKER_PHRASES = [
  "furthermore","moreover","additionally","in addition",
  "it is worth noting","it is important to note","it is essential to",
  "it should be noted","it is crucial","it is clear that",
  "in conclusion","to summarize","in summary","to conclude",
  "overall","firstly","secondly","thirdly","lastly","in this context",
  "as mentioned","as previously mentioned","as discussed",
  "this demonstrates","this highlights","this suggests","this indicates",
  "this underscores","this emphasizes","this shows",
  "delve into","delve deeper","it is evident","it is apparent",
  "needless to say","rest assured","suffice it to say",
  "in light of","it goes without saying","on the other hand",
  "having said that","that being said","with that in mind",
  "at the end of the day","in the realm of","in the world of",
];

// ── AUTO-INTEGRITY: called when the speak API returns a report ─────
function handleAutoIntegrityReport(report, poolSize) {
  if (!report) return;

  // Show badge on the INTEGRITY button
  const navBtn = document.getElementById('nav-integrity');
  const risk = report.risk_level || 'low';
  navBtn.dataset.lastRisk = risk;

  // Update badge colour & text
  let badgeEl = document.getElementById('integrity-auto-badge');
  if (!badgeEl) {
    badgeEl = document.createElement('span');
    badgeEl.id = 'integrity-auto-badge';
    badgeEl.className = 'integrity-auto-badge';
    navBtn.appendChild(badgeEl);
  }
  const pct = Math.round((report.overall_score || 0) * 100);
  badgeEl.textContent = `${pct}%`;
  badgeEl.className = `integrity-auto-badge badge-${risk}`;

  // Also show AI badge if significant
  const aiProb = report.ai_detection?.ai_probability || 0;
  let aiBadgeEl = document.getElementById('integrity-ai-badge');
  if (aiProb >= 0.30) {
    if (!aiBadgeEl) {
      aiBadgeEl = document.createElement('span');
      aiBadgeEl.id = 'integrity-ai-badge';
      aiBadgeEl.className = 'integrity-auto-badge badge-ai';
      navBtn.appendChild(aiBadgeEl);
    }
    aiBadgeEl.textContent = `AI ${Math.round(aiProb * 100)}%`;
    aiBadgeEl.style.display = '';
  } else if (aiBadgeEl) {
    aiBadgeEl.style.display = 'none';
  }

  // Store the last student text so the panel can show it highlighted
  const lastInput = document.getElementById('directive-input')?.value || '';
  navBtn._lastReport = report;
  navBtn._lastStudentText = lastInput;

  // Pulse the button to draw attention
  navBtn.classList.add('integrity-pulse');
  setTimeout(() => navBtn.classList.remove('integrity-pulse'), 2000);

  // Update status strip
  const poolEl = document.getElementById('footer-source-pool');
  if (poolEl) poolEl.textContent = `${poolSize} src`;
}

// Open/close
document.getElementById('nav-integrity').addEventListener('click', () => {
  integrityOverlay.style.display = 'flex';
  // If there's a pending auto report, render it
  const navBtn = document.getElementById('nav-integrity');
  if (navBtn._lastReport) {
    const runAi = document.getElementById('integrity-run-ai')?.checked ?? true;
    renderIntegrityResults(navBtn._lastReport, navBtn._lastStudentText || '', runAi);
    navBtn._lastReport = null;
  }
});
integrityClose.addEventListener('click', () => {
  integrityOverlay.style.display = 'none';
});
integrityOverlay.addEventListener('click', e => {
  if (e.target === integrityOverlay) integrityOverlay.style.display = 'none';
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && integrityOverlay.style.display !== 'none') {
    integrityOverlay.style.display = 'none';
  }
});

// Add/remove source rows
let sourceIndex = 1;
addSourceBtn.addEventListener('click', () => {
  const list = document.getElementById('integrity-sources-list');
  const row = document.createElement('div');
  row.className = 'integrity-source-row';
  row.dataset.index = sourceIndex++;
  row.innerHTML = `
    <input class="integrity-source-name" type="text" placeholder="Source name (e.g. Jones 2020)" />
    <textarea class="integrity-source-text integrity-textarea" rows="3" placeholder="Paste source text here…"></textarea>
    <button class="integrity-remove-source" title="Remove source">✕</button>
  `;
  list.appendChild(row);
  row.querySelector('.integrity-remove-source').addEventListener('click', () => row.remove());
});

// Wire remove on first row (which exists at load time)
document.querySelector('.integrity-remove-source')?.addEventListener('click', function() {
  const rows = document.querySelectorAll('.integrity-source-row');
  if (rows.length > 1) this.closest('.integrity-source-row').remove();
});

// ── RING METER HELPER ──────────────────────────────────────────
function setRing(ringId, fraction, riskClass) {
  const el = document.getElementById(ringId);
  if (!el) return;
  const dash = fraction * CIRCUMFERENCE;
  el.style.strokeDasharray = `${dash.toFixed(1)} ${CIRCUMFERENCE.toFixed(1)}`;
  el.className = `ring-fill ${riskClass}-ring`;
}

function riskClass(risk) {
  return { critical: 'critical', high: 'high', moderate: 'moderate', low: 'low' }[risk] || 'low';
}

function aiVerdictClass(verdict) {
  if (verdict === 'almost_certainly_ai') return 'critical';
  if (verdict === 'likely_ai') return 'high';
  if (verdict === 'uncertain') return 'moderate';
  return 'low';
}

// ── TEXT HIGHLIGHTING ───────────────────────────────────────────
/**
 * Build a highlighted HTML version of the student text.
 * verbatimSpans: [{char_start, char_end, original_phrase, source}]
 * runAi: bool — whether to also highlight AI marker phrases
 */
function buildHighlightedHtml(originalText, verbatimSpans, runAi) {
  // Build list of [start, end, class, tooltip] regions, then merge
  const regions = [];

  // Verbatim spans from server (have char positions)
  for (const sp of verbatimSpans) {
    if (sp.char_start >= 0 && sp.char_end > sp.char_start) {
      regions.push({
        start: sp.char_start,
        end: sp.char_end,
        cls: 'hlg-critical',
        tip: `Verbatim copy — ${escapeHtml(sp.source)} (${sp.word_count} words)`,
      });
    } else {
      // Fallback: search the original text
      const idx = originalText.toLowerCase().indexOf(sp.phrase.toLowerCase());
      if (idx >= 0) {
        regions.push({
          start: idx,
          end: idx + sp.phrase.length,
          cls: 'hlg-critical',
          tip: `Verbatim copy — ${escapeHtml(sp.source)} (${sp.word_count} words)`,
        });
      }
    }
  }

  // AI marker phrases
  if (runAi) {
    const sorted = [...AI_MARKER_PHRASES].sort((a, b) => b.length - a.length);
    const textLower = originalText.toLowerCase();
    for (const marker of sorted) {
      let pos = 0;
      while (true) {
        const idx = textLower.indexOf(marker.toLowerCase(), pos);
        if (idx < 0) break;
        // Don't override a critical span
        const overlaps = regions.some(r => r.start <= idx && r.end >= idx + marker.length);
        if (!overlaps) {
          regions.push({
            start: idx,
            end: idx + marker.length,
            cls: 'hlg-ai',
            tip: `AI-signature phrase: "${escapeHtml(marker)}"`,
          });
        }
        pos = idx + marker.length;
      }
    }
  }

  if (regions.length === 0) {
    return `<span>${escapeHtml(originalText)}</span>`;
  }

  // Sort by start, resolve overlaps (earlier wins)
  regions.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [];
  for (const r of regions) {
    if (merged.length && r.start < merged[merged.length - 1].end) continue; // skip overlap
    merged.push(r);
  }

  // Build HTML
  let html = '';
  let cursor = 0;
  for (const r of merged) {
    if (r.start > cursor) {
      html += escapeHtml(originalText.slice(cursor, r.start));
    }
    html += `<mark class="${r.cls}" title="${r.tip}">${escapeHtml(originalText.slice(r.start, r.end))}</mark>`;
    cursor = r.end;
  }
  if (cursor < originalText.length) {
    html += escapeHtml(originalText.slice(cursor));
  }
  return html;
}

// ── SIGNAL BAR ─────────────────────────────────────────────────
function buildSignalBar(signal) {
  const pct = Math.round(signal.value * 100);
  const cls = pct >= 70 ? 'critical' : pct >= 45 ? 'high' : pct >= 25 ? 'moderate' : 'low';
  return `
    <div class="ai-signal-item">
      <div class="ai-signal-header">
        <span class="ai-signal-name">${escapeHtml(signal.name.replace(/_/g, ' ').toUpperCase())}</span>
        <span class="ai-signal-pct ${cls}">${pct}%</span>
      </div>
      <div class="ai-signal-bar-track">
        <div class="ai-signal-bar-fill ${cls}" style="width:${pct}%"></div>
      </div>
      <div class="ai-signal-desc">${escapeHtml(signal.description)}</div>
    </div>
  `;
}

// ── MAIN RUN ───────────────────────────────────────────────────
integrityRunBtn.addEventListener('click', async () => {
  const studentText = document.getElementById('integrity-student-text').value.trim();
  if (!studentText) {
    alert('Please paste a student text before running the check.');
    return;
  }

  const sourceRows = document.querySelectorAll('.integrity-source-row');
  const sources = [];
  sourceRows.forEach(row => {
    const name = row.querySelector('.integrity-source-name')?.value.trim() || 'Unnamed Source';
    const text = row.querySelector('.integrity-source-text')?.value.trim() || '';
    if (text) sources.push({ name, text });
  });

  const runAi = document.getElementById('integrity-run-ai').checked;

  integrityRunBtn.textContent = 'RUNNING…';
  integrityRunBtn.disabled = true;

  try {
    const resp = await fetch(`${API_BASE}/api/check-plagiarism`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ student_text: studentText, sources, run_ai_detection: runAi }),
    });
    if (!resp.ok) throw new Error(`Server returned ${resp.status}`);
    const data = await resp.json();
    renderIntegrityResults(data, studentText, runAi);
  } catch (err) {
    alert(`Integrity check failed: ${err.message}`);
    console.error('[Integrity]', err);
  } finally {
    integrityRunBtn.textContent = 'RUN INTEGRITY CHECK';
    integrityRunBtn.disabled = false;
  }
});

function renderIntegrityResults(data, studentText, runAi) {
  document.getElementById('integrity-empty-state').style.display = 'none';
  const content = document.getElementById('integrity-results-content');
  content.style.display = 'block';

  // ── PLAGIARISM RING ──
  const plgFraction = data.overall_score || 0;
  const plgRisk = data.risk_level || 'low';
  setRing('plg-ring', plgFraction, riskClass(plgRisk));
  document.getElementById('plg-pct').textContent = `${Math.round(plgFraction * 100)}%`;
  const riskEl = document.getElementById('plg-risk');
  riskEl.textContent = plgRisk.toUpperCase();
  riskEl.className = `meter-risk-badge ${riskClass(plgRisk)}`;

  // ── AI RING ──
  const aiBlock = document.getElementById('ai-meter-block');
  if (data.ai_detection && runAi) {
    aiBlock.style.display = '';
    const ai = data.ai_detection;
    const aiFraction = ai.ai_probability || 0;
    const aiCls = aiVerdictClass(ai.verdict);
    setRing('ai-ring', aiFraction, aiCls);
    document.getElementById('ai-pct').textContent = `${Math.round(aiFraction * 100)}%`;
    const verdictEl = document.getElementById('ai-verdict');
    verdictEl.textContent = (ai.verdict || '—').replace(/_/g, ' ').toUpperCase();
    verdictEl.className = `meter-risk-badge ${aiCls}`;
  } else {
    aiBlock.style.display = 'none';
  }

  // ── SUMMARIES ──
  document.getElementById('plg-summary').textContent = data.summary || '';
  const aiSumLabel = document.getElementById('ai-summary-label');
  const aiSumEl = document.getElementById('ai-summary');
  if (data.ai_detection && runAi) {
    aiSumLabel.style.display = '';
    aiSumEl.style.display = '';
    aiSumEl.textContent = data.ai_detection.summary || '';
  } else {
    aiSumLabel.style.display = 'none';
    aiSumEl.style.display = 'none';
  }

  // ── HIGHLIGHTED TEXT ──
  const spans = data.verbatim_spans || [];
  const hlHtml = buildHighlightedHtml(studentText, spans, runAi && !!data.ai_detection);
  const hlEl = document.getElementById('integrity-highlighted-text');
  hlEl.innerHTML = hlHtml;

  // ── SOURCE TABLE ──
  const tbody = document.getElementById('integrity-source-tbody');
  tbody.innerHTML = '';
  for (const ss of (data.source_scores || [])) {
    const pct = v => `${Math.round((v || 0) * 100)}%`;
    const cls = ss.composite >= 0.7 ? 'critical' : ss.composite >= 0.45 ? 'high' : ss.composite >= 0.2 ? 'moderate' : '';
    tbody.innerHTML += `
      <tr>
        <td class="src-name-cell">${escapeHtml(ss.source)}</td>
        <td class="${cls} bold">${pct(ss.composite)}</td>
        <td>${pct(ss.verbatim_ratio)}</td>
        <td>${pct(ss.word_ngram_jaccard)}</td>
        <td>${pct(ss.lcs_ratio)}</td>
      </tr>
    `;
  }

  // ── AI SIGNALS ──
  const aiSignalsBlock = document.getElementById('ai-signals-block');
  const aiSignalsGrid  = document.getElementById('ai-signals-grid');
  if (data.ai_detection && runAi && data.ai_detection.signals?.length) {
    aiSignalsBlock.style.display = '';
    aiSignalsGrid.innerHTML = data.ai_detection.signals.map(buildSignalBar).join('');
  } else {
    aiSignalsBlock.style.display = 'none';
  }

  // ── VERBATIM SPANS LIST ──
  const verbatimBlock = document.getElementById('verbatim-block');
  const verbatimList  = document.getElementById('verbatim-spans-list');
  if (spans.length) {
    verbatimBlock.style.display = '';
    verbatimList.innerHTML = spans.map(sp => `
      <div class="verbatim-span-item">
        <div class="verbatim-phrase">"${escapeHtml(sp.original_phrase || sp.phrase)}"</div>
        <div class="verbatim-meta">
          <span class="verbatim-source">${escapeHtml(sp.source)}</span>
          <span class="verbatim-words">${sp.word_count} words</span>
        </div>
      </div>
    `).join('');
  } else {
    verbatimBlock.style.display = 'none';
  }

  // Scroll results into view
  content.scrollTop = 0;
}
