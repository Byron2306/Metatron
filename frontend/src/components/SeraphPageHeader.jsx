import { motion } from 'framer-motion';

// Accent prop is intentionally ignored at render time — the canonical
// CSS layer in index.css forces a single uniform look on every page header
// (rainbow-glitch title, neon pip, default status pill). The map below is
// retained so legacy callers passing accent="..." still compile, but it no
// longer drives the styling.
const ACCENTS = {
  cyan:    { eyebrow: '#7dd3fc', glow: 'rgba(0,240,255,0.5)',  pip: '#00f0ff', status: '#39ff14' },
  pink:    { eyebrow: '#ff8ad9', glow: 'rgba(255,43,214,0.55)', pip: '#ff2bd6', status: '#ff8ad9' },
  magenta: { eyebrow: '#ff7ae6', glow: 'rgba(255,0,170,0.6)',   pip: '#ff00aa', status: '#ff7ae6' },
  green:   { eyebrow: '#86efac', glow: 'rgba(57,255,20,0.5)',   pip: '#39ff14', status: '#39ff14' },
  purple:  { eyebrow: '#d4b4ff', glow: 'rgba(155,48,255,0.55)', pip: '#9b30ff', status: '#d4b4ff' },
  gold:    { eyebrow: '#fde68a', glow: 'rgba(253,224,71,0.55)', pip: '#fde047', status: '#fde047' },
  amber:   { eyebrow: '#fcd34d', glow: 'rgba(255,176,32,0.55)', pip: '#ffb020', status: '#ffd47a' },
  orange:  { eyebrow: '#fdba74', glow: 'rgba(255,154,31,0.55)', pip: '#ff9a1f', status: '#ffb38a' },
  yellow:  { eyebrow: '#fef08a', glow: 'rgba(253,224,71,0.55)', pip: '#facc15', status: '#fde047' },
  red:     { eyebrow: '#ffd4d4', glow: 'rgba(255,91,91,0.55)',  pip: '#ff5b5b', status: '#ff5b5b' },
};

export default function SeraphPageHeader({
  eyebrow,
  title,
  tagline,
  accent = 'cyan',
  actions,
  status,
  variant = 'page',
}) {
  const a = ACCENTS[accent] || ACCENTS.cyan;
  const resolvedTitle = typeof title === 'string'
    ? <span className="seraph-heading-flood-rtl">{title}</span>
    : title;
  const headerClassName = variant === 'compact'
    ? 'seraph-page-header seraph-page-header-compact'
    : 'seraph-page-header seraph-page-header-main';

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.25, 0.46, 0.45, 0.94] }}
      className={headerClassName}
    >
      <div>
        {eyebrow ? (
          <div className="seraph-page-eyebrow sophia-scan seraph-fx-flicker-soft" style={{ color: a.eyebrow, textShadow: `0 0 10px ${a.glow}` }}>
            <span
              className="seraph-fx-pulse-pip"
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: a.pip,
                boxShadow: `0 0 8px ${a.pip}, 0 0 18px ${a.glow}`,
                display: 'inline-block',
              }}
            />
            {eyebrow}
          </div>
        ) : null}

        <h1 className="seraph-heading-raw seraph-page-title" style={{ margin: 0 }}>{resolvedTitle}</h1>

        {tagline ? (
          <p className="seraph-page-tagline panel-subtext sophia-flicker">{tagline}</p>
        ) : null}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        {status ? (
          <div
            className="flex items-center gap-2 px-3 py-1.5"
            style={{
              background: `linear-gradient(90deg, ${a.glow.replace('0.5','0.12').replace('0.55','0.12')}, rgba(0,240,255,0.04))`,
              border: `1px solid ${a.glow}`,
              boxShadow: `0 0 14px ${a.glow.replace('0.5','0.18').replace('0.55','0.18')}`,
              clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
            }}
          >
            <span
              className="seraph-fx-pulse-pip"
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: a.status,
                boxShadow: `0 0 8px ${a.status}, 0 0 18px ${a.glow}`,
              }}
            />
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.7rem',
                letterSpacing: '0.32em',
                color: a.eyebrow,
                textShadow: `0 0 8px ${a.glow}`,
              }}
            >
              {status}
            </span>
          </div>
        ) : null}
        {actions}
      </div>
    </motion.div>
  );
}
