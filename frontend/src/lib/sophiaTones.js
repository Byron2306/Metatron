/**
 * Sophia tone palette + helpers — single source of truth for the
 * "neon cyber-angel command center" look defined in
 * docs/sophia-style-sheet.md.
 *
 * Every tone covers the spec's full semantic palette:
 *   cyan    — signal / clarity / live state / connectivity
 *   green   — online / healthy / verified / success
 *   magenta — mystique / intensity / danger / ritual energy
 *   purple  — depth / power / sophistication / advanced
 *   gold    — premium / hero / special
 *   amber   — caution / elevated attention / monitoring
 *   orange  — hero branding / dramatic emphasis
 *   yellow  — alert highlight / metric pop (sparingly)
 *   red     — critical / failure / explicit danger
 *
 * Use these helpers to render panels, buttons, badges, and rows whose
 * color carries meaning. Multi-tone-per-page is the goal; pages that
 * paint every panel in one color read flat.
 */

export const SOPHIA_TONES = {
  cyan:    { rgb: '0,240,255',   text: '#aef7ff' },
  green:   { rgb: '57,255,20',   text: '#b8ffca' },
  magenta: { rgb: '255,43,214',  text: '#ffb8e9' },
  purple:  { rgb: '124,58,237',  text: '#d6c4ff' },
  gold:    { rgb: '251,191,36',  text: '#ffe9a8' },
  amber:   { rgb: '255,176,32',  text: '#ffd78a' },
  orange:  { rgb: '255,154,31',  text: '#ffb38a' },
  yellow:  { rgb: '253,224,71',  text: '#fff3a8' },
  red:     { rgb: '255,91,91',   text: '#ffd4d4' },
};

const toneConfig = (tone) => SOPHIA_TONES[tone] || SOPHIA_TONES.cyan;

/**
 * Card / panel container — dark interior, neon 2px border, breathing glow.
 * Use for any "control surface" block: stat tile, telemetry panel, console
 * card, alert row, status module.
 */
export function sophiaPanel(tone = 'cyan') {
  const { rgb } = toneConfig(tone);
  return {
    backgroundImage: `linear-gradient(160deg, rgba(${rgb},0.16), rgba(10,18,34,0.96))`,
    border: `2px solid rgba(${rgb},0.62)`,
    boxShadow:
      `0 0 8px rgba(${rgb},0.16), 0 0 18px rgba(${rgb},0.10), inset 0 0 14px rgba(${rgb},0.10)`,
  };
}

/**
 * Button — tinted gradient on a 2px neon border. Reads as a "control
 * activation" instrument rather than a marketing button. Pair the tone with
 * the action's semantic: cyan for refresh/inspect, green for confirm/run,
 * magenta for alert/escalate, red for destructive, orange for hero CTA.
 */
export function sophiaButton(tone = 'cyan') {
  const { rgb, text } = toneConfig(tone);
  return {
    backgroundColor: `rgba(${rgb},0.24)`,
    backgroundImage: `linear-gradient(135deg, rgba(${rgb},0.34), rgba(${rgb},0.18))`,
    border: `2px solid rgba(${rgb},0.82)`,
    color: text,
    boxShadow: `0 0 10px rgba(${rgb},0.24), inset 0 0 12px rgba(${rgb},0.18)`,
    fontFamily: "'Rajdhani', 'IBM Plex Sans', sans-serif",
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
  };
}

/**
 * Pill / badge / chip — small system marker. Uppercase, tracked, thin
 * border, faint glow. Color encodes meaning (status / category / level).
 */
export function sophiaBadge(tone = 'cyan') {
  const { rgb, text } = toneConfig(tone);
  return {
    backgroundImage: `linear-gradient(135deg, rgba(${rgb},0.22), rgba(${rgb},0.10))`,
    border: `1px solid rgba(${rgb},0.68)`,
    color: text,
    boxShadow: `0 0 8px rgba(${rgb},0.18), inset 0 0 10px rgba(${rgb},0.10)`,
    fontFamily: "'JetBrains Mono', monospace",
    letterSpacing: '0.14em',
    textTransform: 'uppercase',
    fontSize: '0.7rem',
    padding: '0.18rem 0.55rem',
    borderRadius: 999,
  };
}

/**
 * Row stripe — alternating subtle tints for terminal-like readouts and
 * tables. Pair with `sophia-terminal-row` className for the scanline.
 */
export function sophiaRow(index = 0) {
  return {
    background:
      index % 2 === 0
        ? 'linear-gradient(90deg, rgba(0,240,255,0.06), rgba(255,43,214,0.03))'
        : 'linear-gradient(90deg, rgba(255,176,32,0.04), rgba(57,255,20,0.03))',
  };
}

/**
 * Text — phosphor-glow text in a chosen tone. Use sparingly: bold labels,
 * metric values, status words. Body copy stays neutral.
 */
export function sophiaText(tone = 'cyan') {
  const { rgb, text } = toneConfig(tone);
  return {
    color: text,
    textShadow: `0 0 8px rgba(${rgb},0.55), 0 0 18px rgba(${rgb},0.22)`,
  };
}

/**
 * Status pip — small pulsing dot for live indicators.
 */
export function sophiaPip(tone = 'cyan') {
  const { rgb, text } = toneConfig(tone);
  return {
    width: 8,
    height: 8,
    borderRadius: '50%',
    background: text,
    boxShadow: `0 0 8px rgba(${rgb},0.95), 0 0 18px rgba(${rgb},0.55)`,
    display: 'inline-block',
  };
}

/**
 * Heuristic: map a severity / status label to a Sophia tone.
 * Returns the tone NAME so callers can compose with sophiaPanel/etc.
 *
 *   critical → red,  high → magenta, medium → amber, low → green
 *   active   → magenta, contained → amber, resolved → green
 *   online   → green, offline → red,  unknown → cyan,  warning → amber
 *
 * Unknown labels fall back to cyan.
 */
export function toneForStatus(label) {
  if (!label) return 'cyan';
  const s = String(label).toLowerCase();
  if (/(critical|fatal|fail|down|offline|compromised|fallen)/.test(s)) return 'red';
  if (/(high|active|alert|danger|threat|unlawful)/.test(s)) return 'magenta';
  if (/(medium|warn|caution|monitor|standby|partial|strained|dissonant|simulation|mock|unverified)/.test(s)) return 'amber';
  if (/(advanced|premium|elevated|engaged|primary)/.test(s)) return 'orange';
  if (/(low|ok|good|healthy|online|active|resolved|verified|harmonic|armed|lawful|success)/.test(s)) return 'green';
  if (/(info|inspect|view|log|trace)/.test(s)) return 'cyan';
  return 'cyan';
}
