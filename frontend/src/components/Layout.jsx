import { useEffect, useState } from 'react';
import { Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  LogOut,
  ChevronRight,
  Cpu,
  Activity,
  Network,
  Crosshair,
  Radar,
  FileText,
  ShieldAlert,
  Settings,
  Clock,
  ScrollText,
  Container,
  Lock,
  GitBranch,
  Brain,
  Workflow,
  Key,
  ShieldCheck,
  Box,
  Globe,
  BarChart3,
  Terminal,
  Radio,
  Map,
  Mail,
  Chrome,
  Server,
  Cloud,
  Eye,
  FlaskConical,
  Fingerprint,
  Smartphone,
  Link,
  Shield,
  Sparkles
} from 'lucide-react';
import { Button } from './ui/button';
import MusicPlayer from './MusicPlayer';
import triunePages from '../triune_pages_map';

const NAV_SECTIONS = [
  {
    id: 'sophia',
    title: 'Sophia · ARDA OS',
    defaultOpen: true,
    items: [
      { path: '/sophia', icon: Sparkles, label: 'Sophia Dashboard' },
      { path: '/sophia-chat', icon: Brain, label: 'Sophia Chat', external: true, url: '__SOPHIA_CHAT__' },
      { path: '/arda-desktop', icon: Shield, label: 'ARDA Desktop', external: true, url: '__ARDA_DESKTOP__' },
      { path: '/kernel-sensors', icon: Cpu, label: 'Kernel Sensors' },
      { path: '/secure-boot', icon: Shield, label: 'Secure Boot' },
      { path: '/advanced', icon: Cpu, label: 'Cross-Plane Ops', subtitle: 'mcp · vns · governance · world' },
    ],
  },
  {
    id: 'command',
    title: 'Command',
    defaultOpen: true,
    items: [
      { path: '/command', icon: LayoutDashboard, label: 'Command Workspace' },
      { path: '/timeline', icon: Clock, label: 'Timeline' },
    ],
  },
  {
    id: 'intelligence',
    title: 'Intelligence',
    defaultOpen: true,
    items: [
      { path: '/world', icon: Brain, label: 'World Manifold', subtitle: 'authoritative state · triune view' },
      { path: '/investigation', icon: GitBranch, label: 'Investigation' },
      { path: '/ai-activity', icon: Brain, label: 'AI Activity' },
      { path: '/hunting', icon: Crosshair, label: 'Threat Hunting' },
      { path: '/network', icon: Network, label: 'Network Map' },
      { path: '/honeypots', icon: Radar, label: 'Honeypots' },
    ],
  },
  {
    id: 'response',
    title: 'Response',
    defaultOpen: true,
    items: [
      { path: '/unified-agent', icon: Cpu, label: 'Unified Agent' },
      { path: '/agent-dashboard', icon: Link, label: 'Agent Dashboard', external: true, url: '__AGENT_UI__' },
      { path: '/response-operations', icon: Workflow, label: 'Response Operations' },
      { path: '/deception', icon: Eye, label: 'Deception Control', subtitle: 'routing · lures · harmonic pressure' },
      { path: '/honey-tokens', icon: Key, label: 'Honey Tokens' },
      { path: '/ransomware', icon: ShieldAlert, label: 'Ransomware' },
    ],
  },
  {
    id: 'platform',
    title: 'Platform',
    defaultOpen: true,
    items: [
      { path: '/identity', icon: Fingerprint, label: 'Identity' },
      { path: '/zero-trust', icon: ShieldCheck, label: 'Zero Trust' },
      { path: '/vpn', icon: Lock, label: 'VPN' },
      { path: '/cspm', icon: Cloud, label: 'Cloud Security' },
      { path: '/containers', icon: Container, label: 'Containers' },
      { path: '/browser-isolation', icon: Globe, label: 'Browser Isolation' },
      { path: '/email-security', icon: Mail, label: 'Email Security' },
      { path: '/endpoint-mobility', icon: Smartphone, label: 'Endpoint Mobility' },
    ],
  },
  {
    id: 'engineering',
    title: 'Engineering',
    defaultOpen: false,
    items: [
      { path: '/detection-engineering', icon: FlaskConical, label: 'Detection Engineering' },
      { path: '/zeek', icon: Radio, label: 'Zeek NDR' },
      { path: '/osquery-fleet', icon: Terminal, label: 'osquery / Fleet' },
      { path: '/ml-prediction', icon: Brain, label: 'ML Prediction' },
      { path: '/sandbox', icon: Box, label: 'Sandbox' },
    ],
  },
  {
    id: 'admin',
    title: 'Admin',
    defaultOpen: false,
    items: [
      { path: '/reports', icon: FileText, label: 'Reports' },
      { path: '/audit', icon: ScrollText, label: 'Audit Logs' },
      { path: '/tenants', icon: Globe, label: 'Tenants' },
      { path: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
  {
    id: 'more-tools',
    title: 'More Tools',
    defaultOpen: true,
    items: [
      { path: '/heatmap', icon: Map, label: 'Threat Heatmap' },
      { path: '/vns-alerts', icon: Mail, label: 'VNS Pulse Alerts', subtitle: 'slack · email · drift warnings' },
      { path: '/browser-extension', icon: Chrome, label: 'Browser Extension' },
      { path: '/kibana', icon: BarChart3, label: 'Kibana' },
      { path: '/setup-guide', icon: Server, label: 'Setup Guide' },
    ],
  },
];

// 7-color neon cycle. Each nav section gets a different identity instead of
// cycling 3 — keeps the sidebar from feeling samey.
const SECTION_NEON_TONES = [
  { color: '#8ef7ff', border: 'rgba(0, 240, 255, 0.55)',  bg: 'rgba(0, 240, 255, 0.18)',  glow: 'rgba(0, 240, 255, 0.6)'  }, // cyan
  { color: '#88ffb0', border: 'rgba(57, 255, 20, 0.5)',   bg: 'rgba(57, 255, 20, 0.16)',  glow: 'rgba(57, 255, 20, 0.55)' }, // green
  { color: '#ff9ff0', border: 'rgba(255, 43, 214, 0.55)', bg: 'rgba(255, 43, 214, 0.18)', glow: 'rgba(255, 43, 214, 0.6)' }, // magenta
  { color: '#d4b4ff', border: 'rgba(155, 48, 255, 0.55)', bg: 'rgba(155, 48, 255, 0.18)', glow: 'rgba(155, 48, 255, 0.6)' }, // purple
  { color: '#ffc890', border: 'rgba(255, 154, 31, 0.55)', bg: 'rgba(255, 154, 31, 0.18)', glow: 'rgba(255, 154, 31, 0.6)' }, // orange
  { color: '#ffb0b0', border: 'rgba(255, 91, 91, 0.55)',  bg: 'rgba(255, 91, 91, 0.18)',  glow: 'rgba(255, 91, 91, 0.6)'  }, // red
  { color: '#fef08a', border: 'rgba(253, 224, 71, 0.6)',  bg: 'rgba(253, 224, 71, 0.18)', glow: 'rgba(253, 224, 71, 0.6)' }, // yellow
];

const Layout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const isSophiaRoute = location.pathname.startsWith('/sophia');

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Seraph AI brand icon — local SVG instead of the external customer-assets
  // URL so the sidebar always renders even when the host has no internet.
  const logoUrl = "/icon-transparent.png";

  const [openSections, setOpenSections] = useState(() =>
    NAV_SECTIONS.reduce((acc, section) => {
      const hasActive = section.items.some(
        (item) => !item.external && location.pathname.startsWith(item.path),
      );
      acc[section.id] = section.defaultOpen || hasActive;
      return acc;
    }, {}),
  );

  useEffect(() => {
    setOpenSections((prev) => {
      const next = { ...prev };
      for (const section of NAV_SECTIONS) {
        const hasActive = section.items.some(
          (item) => !item.external && location.pathname.startsWith(item.path),
        );
        if (hasActive) {
          next[section.id] = true;
        } else if (next[section.id] === undefined) {
          next[section.id] = section.defaultOpen;
        }
      }
      return next;
    });
  }, [location.pathname]);

  // ====================================================================
  // SERAPH DESIGN SYSTEM — STYLE LOCK
  // ====================================================================
  // Locked rules (do not change without explicit design review):
  //
  // PALETTE & SEMANTIC MEANING:
  //   GREEN   = healthy, online, enabled, active, verified, low severity,
  //             resolved, lawful, success
  //   CYAN    = information, neutral default (DEFAULT for un-tagged content)
  //   YELLOW  = caution, medium severity, pending, warning
  //   ORANGE  = high severity, alert, elevated
  //   RED     = critical, offline, disabled, error, failed, denied
  //   MAGENTA = secondary accent (sparingly, variety-fallback)
  //   PURPLE  = system-level / special (sparingly, variety-fallback)
  //
  // BLOCK FILL RULES:
  //   - Top-level wrapper panels (sections/major regions) →
  //     WIREFRAME (thin border + near-black interior + edge glow). They
  //     are frames defining sections, not content blocks.
  //   - Content cards (KPI tiles, list items, status cards) →
  //     SOLID FILLED with the colored gradient.
  //   - Inner cards inside content cards → subtle tinted fill
  //     (subordinate to parent, never the same saturation).
  //   - Buttons → translucent fill + colored border (inherit parent).
  //   - Status badges/pills → SOLID FILLED, semantic-only coloring.
  //
  // COLOR SELECTION:
  //   - Semantic match wins always (ONLINE/CRITICAL/HIGH/etc.)
  //   - Otherwise cycle through the 7 colors based on stable per-element
  //     index. The wireframe-vs-filled distinction in the rendering pass
  //     is what carries the structural hierarchy, NOT a uniform color.
  // ====================================================================
  useEffect(() => {
    // Inline-style approach (not class-based): set --neo-panel-rgb etc. as
    // inline custom properties with !important on each card. Inline +
    // !important beats *any* external !important rule regardless of
    // specificity — guarantees we win over the existing :nth-child(6n+x)
    // cycle without specificity arithmetic.
    //
    // Tuple = [panel-rgb, panel-text-hex, panel-cross-rgb]
    const COLOR_MAP = {
      cyan:    ['0, 240, 255',  '#aef7ff', '255, 43, 214'],
      green:   ['57, 255, 20',  '#b8ffca', '0, 240, 255'],
      magenta: ['255, 43, 214', '#ffb8e9', '155, 48, 255'],
      purple:  ['155, 48, 255', '#d4b4ff', '0, 240, 255'],
      orange:  ['255, 154, 31', '#ffcfaa', '253, 224, 71'],
      yellow:  ['253, 224, 71', '#fff3a8', '255, 154, 31'],
      red:     ['255, 91, 91',  '#ffd4d4', '255, 154, 31'],
    };
    const colors = Object.keys(COLOR_MAP);
    const cardSelector = [
      '.seraph-ui-card', '.sophia-card-glow', '.sophia-panel-glow',
      '.sophia-highlight-box', '.sophia-ti-panel', '.seraph-panel',
      '.seraph-panel-gold', '.seraph-stat-card', '.glass', '.seraph-glass',
      '[class*="bg-slate-9"]', '[class*="bg-slate-8"]',
      '[class*="bg-gray-9"]', '[class*="bg-gray-8"]',
      '[class*="bg-zinc-9"]', '[class*="bg-zinc-8"]',
      '[class*="bg-neutral-9"]', '[class*="bg-neutral-8"]',
      '[class*="bg-stone-9"]', '[class*="bg-stone-8"]',
      '[class*="bg-red-"]', '[class*="bg-orange-"]',
      '[class*="bg-amber-"]', '[class*="bg-yellow-"]',
      '[class*="bg-green-"]', '[class*="bg-emerald-"]',
      '[class*="bg-cyan-"]', '[class*="bg-blue-"]',
      '[class*="bg-purple-"]', '[class*="bg-fuchsia-"]',
      '[class*="bg-pink-"]',
      '[class*="rounded"][class*="border"]',
      '[class*="border"][class*="rounded"]',
      '[class*="rounded-lg"][class*="border"]',
      '[class*="rounded-xl"][class*="border"]',
      '[class*="rounded-2xl"][class*="border"]',
      // Pages like AIActivityWorkspacePage use inline styles instead of
      // Tailwind classes — match those by style attribute fragments.
      'div[style*="border"]',
      'div[style*="background"]',
    ].join(',');
    const excludeSelector =
      'button,a,input,textarea,select,[role="tab"],[role="dialog"],' +
      '[role="menu"],[role="listbox"],[role="tooltip"],.inline-flex';

    // Semantic-color detection. Cyberpunk TRON/Matrix design rule:
    // colors mean something — green = healthy/active, red = critical,
    // orange = high alert, yellow = warning, cyan = info/neutral.
    // Walks each card's textContent and picks a semantic color if any
    // status keyword matches; otherwise falls back to the cycle.
    // Order matters: more-specific patterns first. "non compliant"
    // must beat "compliant" → green. Negations must beat positives.
    const STATUS_RULES = [
      // Negations FIRST so they aren't shadowed by positive matches
      { rx: /\b(non[\s-]*compliant|not[\s-]*compliant|untrusted|unverified|uncovered)\b/i, color: 'red' },
      // Threat/action labels must beat generic positive words like
      // "active"; otherwise "ACTIVE THREATS" paints healthy green.
      { rx: /\b(active[\s_-]*threats?|threats?[\s_-]*(?:detected|active)|alert[\s_-]*feed|critical[\s_-]*hosts?|high[\s_-]*risk[\s_-]*identit(?:y|ies))(?=\b|\d)/i, color: 'red' },
      // Strong negative status. "denied" moved OUT — in this dashboard
      // "ARDA denied N exec(s)" means the defense WORKED (good, not bad).
      // Similarly "blocked" / "isolated" can mean attacker blocked (good)
      // OR target blocked (bad) — too ambiguous, removed.
      { rx: /\b(critical|fatal|offline|breach|compromise|x\s*off|inactive|disabled|stopped|down|error|failed?|broken|expired|revoked|rejected|quarantined)\b/i, color: 'red' },
      // High-risk severity ONLY. Earlier matches on bare "alert" / "high"
      // turned every alert row + every "High-Fidelity"/"High Availability"
      // card orange (e.g. /alerts page had 59 orange cards out of ~100).
      // Now require severity-qualifier follow-up words so "high" matches
      // only when used as a severity ("high risk"/"high severity"), not
      // as a description ("high-fidelity").
      { rx: /\bhigh[\s_-]+(?:risk|sev(?:erity)?|priority|priorit|impact|threat|confidence|importance)\b/i, color: 'orange' },
      { rx: /\b(elevated[\s_-]+(?:risk|threat|alert)|hostile|malicious|adversary|severe|urgent|imminent)\b/i, color: 'orange' },
      // Caution / mid
      { rx: /\b(medium|warning|pending|degraded|caution|review|paused|throttled|deprecated|stale)\b/i, color: 'yellow' },
      // Low-risk / benign / info-neutral
      { rx: /\b(low(?:\s*risk)?|trivial|noise|benign|baseline|normal)\b/i, color: 'green' },
      // Positive status / compliant / healthy. Includes "denied" /
      // "blocked" / "prevented" / "deflected" — in defense context
      // these mean the WAFFLE caught the threat, i.e. good outcome.
      { rx: /\b(online|active|enabled|healthy|verified|compliant|ok|armed|live|lawful|secure|safe|ready|running|operational|watching|monitoring|connected|protected|approved|resolved|contained|hardened|trusted|passed|success|allowed|permitted|authorized|denied|blocked|isolated|prevented|deflected|mitigated|neutralized)\b/i, color: 'green' },
      // Information / neutral
      { rx: /\b(info|informational|noted|logged|unknown|scan|scanning|recon|discovery|telemetry|inventory)\b/i, color: 'cyan' },
    ];
    const detectSemantic = (el) => {
      // Only consider short labels — avoid matching big text blocks
      // that contain status words incidentally.
      const text = (el.textContent || '').slice(0, 200).trim();
      if (!text) return null;
      for (const r of STATUS_RULES) if (r.rx.test(text)) return r.color;
      return null;
    };

    // Heuristic: any DIV/SECTION/ARTICLE under main that visually looks
    // like a card — has rounded corners, has either a border or non-
    // transparent background, and is large enough. Catches the cards that
    // use neither Tailwind classes nor inline `style="border:..."` (e.g.
    // MITRE's KpiBlock which uses motion.div + .seraph-stat-tile only).
    const looksLikeCard = (el) => {
      const tag = el.tagName;
      if (tag !== 'DIV' && tag !== 'SECTION' && tag !== 'ARTICLE') return false;
      if (el.offsetWidth < 100 || el.offsetHeight < 40) return false;
      const s = getComputedStyle(el);
      const radius = parseFloat(s.borderTopLeftRadius) || 0;
      if (radius < 4) return false;
      const hasBorder = parseFloat(s.borderTopWidth) > 0
        && s.borderTopStyle !== 'none'
        && !s.borderTopColor.startsWith('rgba(0, 0, 0, 0');
      const bg = s.backgroundColor;
      const hasBg = bg && bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent';
      return hasBorder || hasBg;
    };

    // Buttons get a separate solid-fill treatment: inside fill matches the
    // border color (user request — buttons should be solid, not outlined).
    const buttonSelector =
      'button, [role="button"], a.seraph-ui-btn, a.sophia-btn,' +
      ' .seraph-ui-btn, .sophia-btn, .arm-button';

    let assigning = false;
    const assignColors = () => {
      if (assigning) return;
      assigning = true;
      try {
        const main = document.querySelector('.seraph-cyberpunk-main');
        if (!main) return;
        // Build the full candidate list: explicit selector matches +
        // heuristic-detected cards. De-dupe via a Set.
        const explicit = main.querySelectorAll(cardSelector);
        const heuristicAll = main.querySelectorAll('div,section,article');
        const seen = new Set();
        const candidates = [];
        for (const el of explicit) {
          if (!seen.has(el)) { seen.add(el); candidates.push(el); }
        }
        for (const el of heuristicAll) {
          if (seen.has(el)) continue;
          if (looksLikeCard(el)) { seen.add(el); candidates.push(el); }
        }
        // Stable index assignment: once a card is given an index, it
        // keeps that index forever. This prevents the "flicker on async
        // data load" the user reported — if new cards appear mid-DOM,
        // the cards already-painted DON'T renumber + repaint to a new
        // color in the cycle. Stored on a shared <main> counter.
        const mainEl = main;
        let nextIndex = parseInt(mainEl.dataset.neoNextIndex || '0', 10);
        for (const el of candidates) {
          if (el.matches(excludeSelector)) continue;
          // Size gate: catches small accent strips picked up via
          // div[style*=...] heuristics that aren't really cards.
          if (el.offsetWidth < 100 || el.offsetHeight < 40) continue;
          // Assign a permanent index on first sight.
          if (el.dataset.neoIndex === undefined) {
            el.dataset.neoIndex = String(nextIndex);
            nextIndex += 1;
          }
          // Semantic color (ONLINE/CRITICAL/etc.) overrides everything
          // else when the card's text matches. Frozen on first
          // assignment so a re-render with new copy can't re-color.
          if (el.dataset.neoSemantic === undefined) {
            const semantic = detectSemantic(el);
            el.dataset.neoSemantic = semantic || '';
          }
          // Color selection: semantic > cycle (variety).
          // Earlier the lock forced top-level cards to cyan for uniform
          // chrome, but that washed out the dashboard ("almost ALL
          // cyan"). Instead, top-level cards still cycle for variety —
          // the wireframe-vs-filled distinction (in the pass below)
          // is what makes the structure read, NOT a uniform color.
          // Spread cycle: step by 3 instead of 1 so adjacent siblings
          // get max hue distance (cyan→purple→red→magenta→yellow→green
          // →orange→cyan) instead of adjacent hue creep
          // (cyan→green→magenta→...) that produced "samey brown"
          // clusters on tool catalogs / bulk command grids.
          const idx = parseInt(el.dataset.neoIndex, 10);
          const parent = el.parentElement;
          const ancestorColorHost = parent ? parent.closest('[data-neo-color]') : null;
          const visibleSiblings = parent
            ? Array.from(parent.children).filter((child) =>
                child instanceof HTMLElement && child.offsetWidth >= 100 && child.offsetHeight >= 32,
              )
            : [];
          const siblingCount = visibleSiblings.length || 1;
          const siblingOrdinal = visibleSiblings.length ? visibleSiblings.indexOf(el) : idx;
          const previousVisibleSibling = siblingOrdinal > 0 ? visibleSiblings[siblingOrdinal - 1] : null;
          const previousSiblingColor = previousVisibleSibling?.dataset?.neoColor || null;
          const ancestorColor = ancestorColorHost?.dataset?.neoColor || null;
          const nearbyColors = new Set([previousSiblingColor, ancestorColor].filter(Boolean));
          const spreadColor = (seedIndex) => {
            for (let offset = 0; offset < colors.length; offset += 1) {
              const candidate = colors[((seedIndex + offset) * 3) % colors.length];
              if (!nearbyColors.has(candidate)) return candidate;
            }
            return colors[(seedIndex * 3) % colors.length];
          };
          const isRepeatedRow = siblingCount >= 4 && el.offsetHeight <= 150;
          const textPreview = (el.textContent || '').slice(0, 160);
          const structuralColor = (() => {
            if (/\bconstitutional\s+formation\b/i.test(textPreview)) return 'green';
            if (/\btpm\s+attestation\b/i.test(textPreview)) return 'cyan';
            if (/\bkernel\s+lsm\b/i.test(textPreview)) return 'orange';
            if (/\bfabric\s+peers\b/i.test(textPreview)) return 'red';
            if (/\bworld\s+entities\b/i.test(textPreview)) return 'magenta';
            if (/\btriune\s+intelligence\b/i.test(textPreview)) return 'purple';
            if (/\barda\s+fabric\s+peers\b/i.test(textPreview)) return 'cyan';
            if (/\battestation\s*&\s*kernel\b/i.test(textPreview)) return 'green';
            if (/\bactive\s+threats\b/i.test(textPreview)) return 'red';
            if (/\balert\s+feed\b/i.test(textPreview)) return 'red';
            if (/\brecent\s+threats\b/i.test(textPreview)) return 'cyan';
            if (/\bbrowser\s+extension\s+package\b/i.test(textPreview)) return 'magenta';
            if (/\binstall\s+instructions\b/i.test(textPreview)) return 'green';
            if (/\breal-time\s+threat\s+detection\b/i.test(textPreview)) return 'red';
            if (/\banti-fingerprinting\s+guard\b/i.test(textPreview)) return 'purple';
            if (/\bactive\s+session\s+protection\b/i.test(textPreview)) return 'cyan';
            if (/\bdomain\s+enforcement\b/i.test(textPreview)) return 'orange';
            if (/\bwhat\s+the\s+extension\s+does\b/i.test(textPreview)) return 'yellow';
            if (/\bwhat\s+is\s+included\s+in\s+the\s+zip\b/i.test(textPreview)) return 'purple';
            return null;
          })();
          const isHeaderBand = Boolean(
            ancestorColorHost
            && el.offsetHeight <= 120
            && (
              el === parent?.firstElementChild
              || /\b(view\s+all|latest|feed|overview|summary|dashboard)\b/i.test(textPreview)
            ),
          );
          el.dataset.neoListRow = isRepeatedRow ? 'true' : 'false';
          el.dataset.neoHeaderBand = isHeaderBand ? 'true' : 'false';

          let target;
          if (structuralColor) {
            target = structuralColor;
          } else if (isHeaderBand && ancestorColorHost.dataset.neoColor) {
            target = ancestorColorHost.dataset.neoColor;
          } else if (el.dataset.neoSemantic && !isRepeatedRow) {
            target = el.dataset.neoSemantic;
          } else {
            target = spreadColor(idx + Math.max(siblingOrdinal, 0));
          }
          // For neutral/non-semantic cards, avoid placing the same tone
          // directly against its parent or previous visible sibling.
          // Semantic colors are kept intact because their meaning matters.
          if (
            !structuralColor
            && !(el.dataset.neoSemantic && !isRepeatedRow)
            && nearbyColors.has(target)
          ) {
            target = spreadColor(idx + Math.max(siblingOrdinal, 0) + 1);
          }
          if (
            !structuralColor
            && previousSiblingColor === target
            && target !== 'red'
            && target !== 'orange'
          ) {
            target = spreadColor(idx + Math.max(siblingOrdinal, 0) + 2);
          }
          // Skip if already assigned the same color — avoids MutationObserver
          // loop and unnecessary style writes.
          if (el.dataset.neoColor !== target) {
            const [rgb, text, cross] = COLOR_MAP[target];
            // Set every per-card variable name the codebase uses (in case
            // some downstream rule reads it), plus paint the visible
            // properties directly inline. Inline + !important is the
            // highest-priority slot in the cascade, so no external rule
            // (regardless of selector specificity or !important) can
            // override these.
            el.style.setProperty('--neo-panel-rgb', rgb, 'important');
            el.style.setProperty('--neo-panel-text', text, 'important');
            el.style.setProperty('--neo-panel-cross-rgb', cross, 'important');
            el.style.setProperty('--sweep-panel-rgb', rgb, 'important');
            el.style.setProperty('--sophia-accent', rgb, 'important');
            // Two-layer paint: solid dark base (no alpha → outer color
            // can't bleed through nested cards), with a faded colored
            // gradient on top. The lighter alphas here (was 0.42→0.14,
            // now 0.28→0.08) give a subtler "tinted dark" feel rather
            // than a saturated panel — user requested more fade.
            // Initial paint = saturated "top-level" treatment. The
            // nested-subtlety pass after this loop dials nested cards
            // back down so outer panels pop while inner cards stay
            // visible but subordinate.
            // Initial paint = transparent-tinted fill. The nested pass
            // below INVERTS this for top-level cards (wireframe) and
            // mutes the saturation of inner cards that have many same-
            // level siblings (the "color vomit" failure mode — a grid
            // of 6 evidence sub-cards each in a different bright color).
            el.style.setProperty('background-color', 'rgba(3, 8, 18, 0.82)', 'important');
            el.style.setProperty(
              'background-image',
              `linear-gradient(160deg, rgba(${rgb}, ${isRepeatedRow ? 0.20 : 0.28}), rgba(3, 8, 18, 0.82) 48%, rgba(${rgb}, ${isRepeatedRow ? 0.12 : 0.16}))`,
              'important',
            );
            // Force ALL FOUR edges to the same color. Some components set
            // border-top-color / border-left-color etc. as individual
            // inline properties which beat the `border` shorthand and
            // produce the "two-color border" effect you saw (magenta top,
            // green sides). Setting each longhand explicitly with
            // !important guarantees uniform color.
            el.style.setProperty('border-width', isRepeatedRow ? '1px' : '2px', 'important');
            el.style.setProperty('border-style', 'solid', 'important');
            // Softer border (0.65 vs 0.95) — was reading as a harsh
            // neon outline on the Pending Approvals playbook cards.
            const borderColor = `rgba(${rgb}, ${isRepeatedRow ? 0.78 : 0.95})`;
            el.style.setProperty('border-top-color', borderColor, 'important');
            el.style.setProperty('border-right-color', borderColor, 'important');
            el.style.setProperty('border-bottom-color', borderColor, 'important');
            el.style.setProperty('border-left-color', borderColor, 'important');
            // Inset-only glow — no outer halo leaking onto adjacent cards.
            el.style.setProperty(
              'box-shadow',
              `0 0 ${isRepeatedRow ? 13 : 24}px rgba(${rgb}, ${isRepeatedRow ? 0.34 : 0.50}), inset 0 0 18px rgba(${rgb}, ${isRepeatedRow ? 0.18 : 0.24})`,
              'important',
            );
            el.dataset.neoColor = target;
          }
        }
        // Persist the counter so future MutationObserver runs don't
        // restart from 0 and renumber existing cards.
        mainEl.dataset.neoNextIndex = String(nextIndex);
        // -------- TRON/Matrix wireframe-vs-fill inversion --------
        // Top-level cards (no tagged ancestor) become WIREFRAMES:
        // near-black interior, thin glowing border, outer edge-glow.
        // They define section boundaries without competing for attention.
        // Nested cards stay SOLID-FILLED — they're the actual content
        // and should pop against the wireframe parent.
        for (const el of candidates) {
          if (!el.dataset.neoColor) continue;
          const ownColor = el.dataset.neoColor;
          if (!COLOR_MAP[ownColor]) continue;
          const [crgb] = COLOR_MAP[ownColor];
          const parent = el.parentElement;
          const ancestor = parent ? parent.closest('[data-neo-color]') : null;
          const isTopLevel = !ancestor || ancestor === el;
          if (isTopLevel) {
            // Top-level wireframe. But check sibling count: if 5+ tagged
            // top-level siblings share the same parent → this is a list
            // (technique rows, large KPI grid). MUTE the borders so the
            // overall page doesn't read as a "rainbow of rows".
            const __siblings = parent
              ? parent.querySelectorAll(':scope > [data-neo-color]').length
              : 1;
            const __mutedList = __siblings >= 5;
            el.style.setProperty('background-color', 'rgba(3, 8, 18, 0.84)', 'important');
            el.style.setProperty(
              'background-image',
              `linear-gradient(160deg, rgba(${crgb}, ${__mutedList ? 0.18 : 0.30}), rgba(3, 8, 18, 0.82) 52%, rgba(${crgb}, ${__mutedList ? 0.10 : 0.18}))`,
              'important',
            );
            el.style.setProperty(
              'box-shadow',
              `0 0 ${__mutedList ? 14 : 28}px rgba(${crgb}, ${__mutedList ? 0.32 : 0.52}), inset 0 0 20px rgba(${crgb}, ${__mutedList ? 0.15 : 0.26})`,
              'important',
            );
            // Slightly heavier border so the frame reads clearly.
            const outerBorder = `rgba(${crgb}, ${__mutedList ? 0.78 : 0.98})`;
            el.style.setProperty('border-width', __mutedList ? '1px' : '2px', 'important');
            el.style.setProperty('border-top-color', outerBorder, 'important');
            el.style.setProperty('border-right-color', outerBorder, 'important');
            el.style.setProperty('border-bottom-color', outerBorder, 'important');
            el.style.setProperty('border-left-color', outerBorder, 'important');
          }
          // Nested card → check how many sibling tagged cards it has.
          // 4+ siblings in the same parent = grid-of-blocks. To stop
          // the "color vomit" effect (6 evidence cards in 6 different
          // saturated colors), mute these: lower saturation + thinner
          // border so each color reads as a region tone, not a slab.
          else if (parent) {
            const siblings = parent.querySelectorAll(':scope > [data-neo-color]');
            if (siblings.length >= 4) {
              el.style.setProperty(
                'background-image',
                `linear-gradient(160deg, rgba(${crgb}, 0.20), rgba(3, 8, 18, 0.82) 55%, rgba(${crgb}, 0.10))`,
                'important',
              );
              const mutedBorder = `rgba(${crgb}, 0.80)`;
              el.style.setProperty('border-top-color', mutedBorder, 'important');
              el.style.setProperty('border-right-color', mutedBorder, 'important');
              el.style.setProperty('border-bottom-color', mutedBorder, 'important');
              el.style.setProperty('border-left-color', mutedBorder, 'important');
              el.style.setProperty(
                'box-shadow',
                `0 0 14px rgba(${crgb}, 0.34), inset 0 0 14px rgba(${crgb}, 0.16)`,
                'important',
              );
            }
            // Smaller sibling counts keep their full solid fill —
            // these are the "feature" cards that should pop.
          }
        }

        // -------- Buttons + outline badges: semi-transparent fill -------
        // User feedback: buttons should look like the cards (translucent,
        // not solid opaque). Outline badges (e.g. shadcn Badge with only
        // a colored border, transparent interior — the "SIMULATION" pill)
        // should get the SAME translucent-tinted fill so the inside reads
        // as the border color. Animations + text-shadow are stripped to
        // kill the "whitish flickering" user reported.
        //
        // Use the same selector as cards plus shadcn badges
        // (.inline-flex with border classes — excluded from the card loop).
        const interactiveSelector = [
          buttonSelector,
          '.inline-flex.border',
          '[class*="inline-flex"][class*="border"]',
          '[class*="badge"]', '[class*="Badge"]', '[data-slot="badge"]',
        ].join(',');
        const interactive = main.querySelectorAll(interactiveSelector);
        let bi = 0;
        for (const btn of interactive) {
          if (btn.disabled) continue;
          if (btn.offsetWidth < 28 || btn.offsetHeight < 16) continue;
          // Semantic check on button text first (e.g. "REJECT" → red,
          // "APPROVE" → green, "BLOCK" → red, "ENABLE" → green).
          const btnSemantic = detectSemantic(btn);
          let color;
          if (btnSemantic) {
            color = btnSemantic;
          } else {
            // When 4+ siblings under same parent → cycle through colors
            // (not inherit parent). Stops Bulk Commands' 8 buttons all
            // reading green from a green parent.
            const btnParent = btn.parentElement;
            const btnSiblings = btnParent
              ? btnParent.querySelectorAll(':scope > ' + interactiveSelector.split(',').map(s => s.trim()).join(', :scope > '))
              : null;
            if (btnSiblings && btnSiblings.length >= 4) {
              if (btn.dataset.neoBtnIdx === undefined) {
                btn.dataset.neoBtnIdx = String(bi);
              }
              const idx = parseInt(btn.dataset.neoBtnIdx, 10);
              color = colors[(idx * 3) % colors.length];
            } else {
              const host = btn.closest('[data-neo-color]');
              color = host ? host.dataset.neoColor : colors[bi % colors.length];
            }
          }
          bi += 1;
          if (btn.dataset.neoButton === color) continue;
          const [brgb] = COLOR_MAP[color];
          // Semi-transparent like cards, but slightly punchier (higher
          // alpha) so interactive elements read as distinct from panels.
          btn.style.setProperty('background-color', 'rgba(8, 12, 24, 0.6)', 'important');
          btn.style.setProperty(
            'background-image',
            `linear-gradient(135deg, rgba(${brgb}, 0.38), rgba(${brgb}, 0.22))`,
            'important',
          );
          btn.style.setProperty('border-width', '1px', 'important');
          btn.style.setProperty('border-style', 'solid', 'important');
          const btnBorder = `rgba(${brgb}, 0.85)`;
          btn.style.setProperty('border-top-color', btnBorder, 'important');
          btn.style.setProperty('border-right-color', btnBorder, 'important');
          btn.style.setProperty('border-bottom-color', btnBorder, 'important');
          btn.style.setProperty('border-left-color', btnBorder, 'important');
          // Text is the color of the border (high-alpha) — readable on
          // the dark+tinted background, matches the border.
          btn.style.setProperty('color', `rgba(${brgb}, 1)`, 'important');
          // No text-shadow, no animation → kills the white flicker the
          // user complained about on tab pills.
          btn.style.setProperty('text-shadow', 'none', 'important');
          btn.style.setProperty('animation', 'none', 'important');
          btn.style.setProperty(
            'box-shadow',
            `inset 0 0 10px rgba(${brgb}, 0.18)`,
            'important',
          );
          btn.dataset.neoButton = color;
        }

        // -------- Status badge semantic coloring --------
        // Two-tier badge treatment:
        //   1. Badge text matches semantic keyword → solid colored
        //      (TVR VALIDATED → green, CRITICAL → red, HIGH → orange...)
        //   2. Badge text does NOT match → uniform cyan/neutral so a
        //      row full of label-tags (YARA / SIGMA / CLAMAV / SOAR /
        //      HONEST TVR) doesn't look like rainbow vomit.
        const badgeCandidates = main.querySelectorAll(
          '[class*="badge" i], [class*="Badge"], [data-slot="badge"]',
        );
        for (const b of badgeCandidates) {
          if (b.dataset.neoStatus !== undefined) continue;
          const t = (b.textContent || '').trim();
          if (!t || t.length > 60) continue;
          const semantic = detectSemantic(b);
          if (semantic) {
            const [srgb] = COLOR_MAP[semantic];
            b.style.setProperty('color', `rgb(${srgb})`, 'important');
            b.style.setProperty(
              'background',
              `linear-gradient(135deg, rgba(${srgb}, 0.22), rgba(${srgb}, 0.10))`,
              'important',
            );
            b.style.setProperty('border-color', `rgba(${srgb}, 0.85)`, 'important');
            b.style.setProperty(
              'text-shadow',
              `0 0 6px rgba(${srgb}, 0.55), 0 0 14px rgba(${srgb}, 0.25)`,
              'important',
            );
            b.dataset.neoStatus = semantic;
          } else {
            // Neutral cyan default — kills the rainbow-vomit effect
            // on technique badges like YARA / SIGMA / SOAR / HONEST TVR.
            b.style.setProperty('color', 'rgba(174, 247, 255, 1)', 'important');
            b.style.setProperty(
              'background',
              'linear-gradient(135deg, rgba(0, 240, 255, 0.14), rgba(0, 240, 255, 0.06))',
              'important',
            );
            b.style.setProperty('border-color', 'rgba(0, 240, 255, 0.55)', 'important');
            b.style.setProperty(
              'text-shadow',
              '0 0 5px rgba(0, 240, 255, 0.35)',
              'important',
            );
            b.dataset.neoStatus = 'neutral';
          }
        }

        // -------- Status pip coloring --------
        // Tiny circular elements (≤22×22, border-radius: 50%) are status
        // dots. Color them by the NEAREST status signal: either an
        // adjacent semantic badge, or the parent card's semantic, or the
        // parent card's cycle color. So a small dot next to "OFFLINE"
        // reads red, next to "ARMED" reads green — the user's "pip
        // color codes" ask.
        const pipCandidates = main.querySelectorAll(
          'span, i, div, svg circle',
        );
        for (const dot of pipCandidates) {
          if (dot.dataset.neoPip) continue;
          // Size + shape gate — only tiny round things.
          const w = dot.offsetWidth || (dot.getBoundingClientRect && dot.getBoundingClientRect().width) || 0;
          const h = dot.offsetHeight || (dot.getBoundingClientRect && dot.getBoundingClientRect().height) || 0;
          if (w < 4 || w > 22 || h < 4 || h > 22) continue;
          if (Math.abs(w - h) > 4) continue;  // not roughly square/circular
          if (dot.tagName !== 'CIRCLE') {
            const s = getComputedStyle(dot);
            const r = parseFloat(s.borderTopLeftRadius);
            if (r < w / 3) continue;  // not actually round
          }
          // Find semantic from nearest sibling or ancestor card.
          let pipColor = null;
          const sib = dot.nextElementSibling || dot.previousElementSibling;
          if (sib && sib.dataset && sib.dataset.neoStatus) {
            pipColor = sib.dataset.neoStatus;
          } else {
            const parent = dot.parentElement;
            const tagged = parent ? parent.closest('[data-neo-semantic]') : null;
            if (tagged && tagged.dataset.neoSemantic) {
              pipColor = tagged.dataset.neoSemantic;
            } else {
              const cardAncestor = parent ? parent.closest('[data-neo-color]') : null;
              if (cardAncestor && cardAncestor.dataset.neoColor) {
                pipColor = cardAncestor.dataset.neoColor;
              }
            }
          }
          if (!pipColor || !COLOR_MAP[pipColor]) continue;
          const [prgb] = COLOR_MAP[pipColor];
          dot.style.setProperty('background-color', `rgb(${prgb})`, 'important');
          if (dot.tagName === 'CIRCLE') {
            dot.style.setProperty('fill', `rgb(${prgb})`, 'important');
          }
          dot.style.setProperty(
            'box-shadow',
            `0 0 6px rgba(${prgb}, 0.85), 0 0 12px rgba(${prgb}, 0.45)`,
            'important',
          );
          dot.dataset.neoPip = pipColor;
        }

        // -------- Hard-target dials/rings (crystal clear glow) --------
        // The drop-shadow approach can't equalize different hues — green
        // naturally reads brighter than cyan/pink due to luma. Solution:
        // OVERRIDE the gradient stroke entirely with a near-white solid,
        // and use drop-shadow in the dial's source color for the halo.
        // We pick the source color from the FIRST gradient stop inside
        // the parent SVG so the glow keeps the dial's identity.
        const dialCircles = main.querySelectorAll('svg circle[stroke^="url"]');
        for (const c of dialCircles) {
          if (c.dataset.neoDial) continue;
          // Find the linearGradient's first stop color for the halo.
          let haloColor = '#ffffff';
          const svg = c.ownerSVGElement;
          if (svg) {
            const firstStop = svg.querySelector('linearGradient stop[offset="0%"], linearGradient stop:first-child');
            if (firstStop) haloColor = firstStop.getAttribute('stop-color') || '#ffffff';
          }
          // Solid bright stroke → uniform brightness on every dial.
          c.style.setProperty('stroke', 'rgba(255,255,255,0.92)', 'important');
          c.style.setProperty(
            'filter',
            `drop-shadow(0 0 8px ${haloColor}) `
            + `drop-shadow(0 0 18px ${haloColor}) `
            + `drop-shadow(0 0 32px ${haloColor})`,
            'important',
          );
          c.setAttribute('stroke-width', '12');
          c.dataset.neoDial = haloColor;
        }
      } finally {
        assigning = false;
      }
    };

    const raf = requestAnimationFrame(assignColors);
    const initialDelay = setTimeout(assignColors, 250);

    const main = document.querySelector('.seraph-cyberpunk-main');
    let debounceId = null;
    const observer = main
      ? new MutationObserver(() => {
          if (assigning) return;
          if (debounceId) clearTimeout(debounceId);
          debounceId = setTimeout(assignColors, 80);
        })
      : null;
    if (observer && main) {
      observer.observe(main, { childList: true, subtree: true });
    }

    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(initialDelay);
      if (debounceId) clearTimeout(debounceId);
      if (observer) observer.disconnect();
    };
  }, [location.pathname]);

  const toggleSection = (sectionId) => {
    setOpenSections((prev) => ({ ...prev, [sectionId]: !prev[sectionId] }));
  };

  const resolveTriuneRoles = (item) => {
    const labelKey = item.label.replace(/[^A-Za-z0-9]/g, '') + 'Page';
    const altKey = item.label.replace(/\s+/g, '') + 'Page';
    const simpleKey = item.path.replace(/\//g, '');
    return (
      triunePages[labelKey] ||
      triunePages[altKey] ||
      triunePages[item.label] ||
      triunePages[simpleKey] ||
      []
    );
  };

  const renderNavItem = (item) => {
    if (item.external) {
      const resolvedExternalUrl = item.url === '__AGENT_UI__'
        ? `${window.location.protocol}//${window.location.hostname}:5000`
        : item.url === '__SOPHIA_CHAT__'
        ? `${window.location.protocol}//${window.location.hostname}:7070`
        : item.url === '__ARDA_DESKTOP__'
        ? `${window.location.protocol}//${window.location.hostname}:8082`
        : item.url;
      return (
        <a
          key={item.path}
          href={resolvedExternalUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 group seraph-nav-item"
          style={{ color: '#A5F3FC', border: '1px solid transparent' }}
        >
          <item.icon className="w-4 h-4" style={{ color: '#A5F3FC' }} />
          <span className="font-medium text-sm" style={{ color: '#A5F3FC' }}>
            {item.label}
          </span>
          <ChevronRight className="w-4 h-4 ml-auto" style={{ color: '#A5F3FC' }} />
        </a>
      );
    }

    return (
      <NavLink
        key={item.path}
        to={item.path}
        className={({ isActive }) =>
          `flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 group ${
            isActive ? 'seraph-nav-active' : 'seraph-nav-item'
          }`
        }
        style={({ isActive }) =>
          isActive
            ? {
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                color: '#38BDF8',
              }
            : {
                color: '#A5F3FC',
                border: '1px solid transparent',
              }
        }
      >
        {({ isActive }) => {
          const roles = resolveTriuneRoles(item);
          return (
            <>
              <item.icon className="w-4 h-4" style={{ color: isActive ? '#38BDF8' : '#A5F3FC' }} />
              <span className="min-w-0" style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <span className="font-medium text-sm" style={{ color: isActive ? '#E0E7FF' : '#A5F3FC' }}>
                  {item.label}
                  {roles.length ? (
                    <span style={{ marginLeft: 8, display: 'inline-flex', gap: 6 }}>
                      {roles.map((role) => (
                        <span
                          key={role}
                          style={{
                            fontSize: 10,
                            padding: '2px 6px',
                            borderRadius: 6,
                            background: 'rgba(255,255,255,0.04)',
                            color: '#A5F3FC',
                          }}
                        >
                          {role[0]}
                        </span>
                      ))}
                    </span>
                  ) : null}
                </span>
                {item.subtitle ? (
                  <span
                    style={{
                      fontSize: 10,
                      lineHeight: 1.2,
                      letterSpacing: '0.12em',
                      textTransform: 'uppercase',
                      color: isActive ? 'rgba(224, 231, 255, 0.78)' : 'rgba(165, 243, 252, 0.58)',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {item.subtitle}
                  </span>
                ) : null}
              </span>
              {isActive ? (
                <ChevronRight className="w-4 h-4 ml-auto" style={{ color: '#38BDF8' }} />
              ) : null}
            </>
          );
        }}
      </NavLink>
    );
  };

  return (
    <div className="min-h-screen flex seraph-cyberpunk-shell" style={{ backgroundColor: '#0a1624' }}>
      {/* Sidebar */}
      <aside className="w-64 flex flex-col seraph-cyberpunk-sidebar" style={{ backgroundColor: '#06111d', borderRight: '1px solid rgba(0, 240, 255, 0.3)' }}>
        {/* Logo */}
        <div className="p-6" style={{ borderBottom: '1px solid rgba(0, 240, 255, 0.22)' }}>
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-xl overflow-hidden" style={{ 
              background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(188, 19, 254, 0.2))',
              boxShadow: '0 0 30px rgba(0, 240, 255, 0.25), 0 0 50px rgba(188, 19, 254, 0.2), inset 0 0 20px rgba(0, 240, 255, 0.1)',
              border: '1px solid rgba(0, 240, 255, 0.45)'
            }}>
              <img src={logoUrl} alt="Seraph AI" className="w-full h-full object-contain" />
            </div>
            <div>
              <h1 className="font-mono font-bold text-xl tracking-wider" style={{ color: '#dffbff', textShadow: '0 0 15px rgba(0, 240, 255, 0.45)' }}>SERAPH AI</h1>
              <p className="text-xs" style={{ color: '#9fe7ff' }}>Seraphic Watch</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-2 overflow-y-auto">
          {NAV_SECTIONS.map((section, sectionIndex) => {
            const tone = SECTION_NEON_TONES[sectionIndex % SECTION_NEON_TONES.length];

            return (
            <div key={section.id} className="space-y-1">
              <button
                type="button"
                onClick={() => toggleSection(section.id)}
                className="w-full flex items-center justify-between px-2 py-1 rounded-md transition-colors"
                style={{
                  color: tone.color,
                  backgroundColor: tone.bg,
                  border: `2px solid ${tone.border}`,
                  boxShadow: `inset 0 0 12px ${tone.bg}, 0 0 12px ${tone.glow}`,
                }}
              >
                <span
                  className="text-xs font-semibold uppercase tracking-widest"
                  style={{
                    color: tone.color,
                    textShadow: `0 0 10px ${tone.glow}`,
                  }}
                >
                  {section.title}
                </span>
                <ChevronRight
                  className="w-4 h-4 transition-transform duration-200"
                  style={{
                    color: tone.color,
                    transform: openSections[section.id] ? 'rotate(90deg)' : 'rotate(0deg)',
                  }}
                />
              </button>
              {openSections[section.id] ? (
                <div className="space-y-0.5">
                  {section.items.map((item) => renderNavItem(item))}
                </div>
              ) : null}
            </div>
          );
          })}
        </nav>

        {/* Music Player */}
        <div className="px-4 pb-3" style={{ borderTop: '1px solid rgba(0, 240, 255, 0.22)' }}>
          <MusicPlayer
            tracks={[
              { src: '/seraph-track-1.mp3', title: 'SERAPHIM // BOOT.SEQUENCE' },
              { src: '/seraph-track-2.mp3', title: 'SERAPHIM // ARDA.PULSE' },
              { src: '/synth1.mp3', title: 'SYNTH1 // CELESTIAL.DRIFT' },
              { src: '/synth2.mp3', title: 'SYNTH2 // NEON.WARD' },
            ]}
          />
        </div>

        {/* System Status */}
        <div className="p-4" style={{ borderTop: '1px solid rgba(0, 240, 255, 0.22)' }}>
          <div className="rounded-xl p-4" style={{ backgroundColor: 'rgba(0, 240, 255, 0.08)', border: '1px solid rgba(0, 240, 255, 0.22)' }}>
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-5 h-5" style={{ color: '#00f0ff' }} />
              <span className="text-sm font-medium" style={{ color: '#00f0ff' }}>Seraphic Status</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full animate-pulse" style={{ backgroundColor: '#39ff14', boxShadow: '0 0 15px #39ff14' }} />
              <span className="text-sm font-mono font-bold" style={{ color: '#39ff14' }}>WATCHING</span>
            </div>
          </div>
        </div>

        {/* User Section */}
        <div className="p-4" style={{ borderTop: '1px solid rgba(0, 240, 255, 0.22)' }}>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(0, 240, 255, 0.14)', border: '1px solid rgba(0, 240, 255, 0.42)' }}>
              <span className="text-lg font-mono font-bold" style={{ color: '#c0f7ff' }}>
                {user?.name?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">{user?.name}</p>
              <p className="text-xs truncate" style={{ color: '#A5F3FC' }}>{user?.role}</p>
            </div>
          </div>
          <Button
            onClick={handleLogout}
            variant="ghost"
            className="w-full justify-start text-slate-400 hover:text-red-400 hover:bg-red-500/10"
            data-testid="logout-btn"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main
        className="flex-1 overflow-auto seraph-cyberpunk-main sophia-cyber-bg sophia-shell-gradient sophia-page-chevrons"
        style={{ backgroundColor: '#0a1624' }}
        data-sophia="true"
      >
        <div className="seraph-scanline-overlay" aria-hidden="true" />
        <div className="seraph-scan-bar" aria-hidden="true" />
        <div className="sophia-binary-rain" aria-hidden="true" />
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
