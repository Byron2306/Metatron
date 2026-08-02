import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { toast } from 'sonner';
import { Lock, Mail, User, Eye, EyeOff, AlertTriangle, ShieldCheck, Activity, Cpu, Network } from 'lucide-react';
import { motion } from 'framer-motion';
import MusicPlayer from '../components/MusicPlayer';

const LoginPage = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [bootText, setBootText] = useState('');
  const [bootstrapStatus, setBootstrapStatus] = useState({
    loading: true,
    setupRequired: false,
    setupTokenRequired: false,
  });
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: '',
    setupToken: '',
  });

  const { login, register, setupAdmin, getBootstrapStatus } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const lines = [
      '> SERAPH_OS // boot sequence initiated',
      '> watcher.kernel: ARDA ring-0 mounted',
      '> seraphic-link: handshake OK',
      '> awaiting guardian credentials_',
    ];
    let cancelled = false;
    let i = 0;
    let buf = '';
    const tick = () => {
      if (cancelled) return;
      if (i < lines.length) {
        buf += lines[i] + '\n';
        setBootText(buf);
        i += 1;
        setTimeout(tick, 280);
      }
    };
    tick();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;

    const loadBootstrapStatus = async () => {
      try {
        const status = await getBootstrapStatus();
        if (cancelled) return;
        const setupRequired = Boolean(status?.setup_required);
        setBootstrapStatus({
          loading: false,
          setupRequired,
          setupTokenRequired: Boolean(status?.setup_token_required),
        });
        if (setupRequired) {
          setIsLogin(false);
        }
      } catch {
        if (cancelled) return;
        setBootstrapStatus({
          loading: false,
          setupRequired: false,
          setupTokenRequired: false,
        });
      }
    };

    loadBootstrapStatus();
    return () => {
      cancelled = true;
    };
  }, [getBootstrapStatus]);

  const setupMode = bootstrapStatus.setupRequired;
  const modeLabel = setupMode ? 'FIRST GUARDIAN SETUP' : (isLogin ? 'GUARDIAN.LOGIN' : 'GUARDIAN.REGISTER');
  const headingLabel = setupMode ? 'Initialize Command' : (isLogin ? 'Guardian Access' : 'Register Guardian');
  const subheadingLabel = setupMode
    ? '> create the first administrator to unlock the seraphic console'
    : (isLogin
      ? '> credentials required to access seraphic console'
      : '> register a new guardian profile');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (setupMode) {
        await setupAdmin(formData.email, formData.password, formData.name, formData.setupToken);
        toast.success('First guardian initialized. Seraphic access granted.');
      } else if (isLogin) {
        await login(formData.email, formData.password);
        toast.success('Seraphic access granted. Welcome, Guardian.');
      } else {
        await register(formData.email, formData.password, formData.name);
        toast.success('Guardian registered. Seraphic access granted.');
      }
      navigate('/dashboard');
    } catch (error) {
      const message = error.response?.data?.detail || 'Authentication failed';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="login-seraph-shell min-h-screen w-full relative overflow-hidden seraph-cyberpunk-shell seraph-cyberpunk-main"
      style={{
        background: 'linear-gradient(180deg, #0b1827 0%, #091320 55%, #07101a 100%)',
        fontFamily: "'Rajdhani', 'IBM Plex Sans', sans-serif",
      }}
    >
      {/* === Atmospheric layers === */}
      <div className="seraph-aurora-bg" aria-hidden="true" />
      <div className="seraph-cyber-grid" aria-hidden="true" />
      <div className="seraph-scanline-overlay" aria-hidden="true" />
      <div className="seraph-scan-bar" aria-hidden="true" />

      {/* Vertical data streams */}
      <div className="absolute inset-0 pointer-events-none" aria-hidden="true">
        {[8, 22, 36, 51, 64, 78, 92].map((leftPct, i) => (
          <div
            key={leftPct}
            className="seraph-data-stream"
            style={{
              left: `${leftPct}%`,
              animationDelay: `${i * 0.7}s`,
              animationDuration: `${4 + (i % 3) * 1.2}s`,
            }}
          />
        ))}
      </div>

      {/* === Two-column grid === */}
      <div className="relative z-10 min-h-screen grid lg:grid-cols-[minmax(0,1.04fr)_minmax(400px,520px)] items-center">
        {/* ────────────────  LEFT: ANGEL HERO  ──────────────── */}
        <div className="seraph-login-left-column hidden lg:flex flex-col justify-center px-7 py-3 xl:px-9 xl:py-4 relative">
          {/* Top mark */}
          <motion.p
            initial={false}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="text-xs mb-3"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              letterSpacing: '0.32em',
              color: 'rgba(226, 232, 240, 0.78)',
              textShadow: '0 0 12px rgba(255,255,255,0.18)',
              paddingLeft: '0.32em',
            }}
          >
            CYBER · DEFENSE · ARCHITECTURE
          </motion.p>

          <motion.div
            initial={false}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45 }}
            className="max-w-[840px]"
          >
            <div
              className="seraph-login-hero-figure mx-auto"
              style={{
                width: 'min(100%, 840px)',
                height: 'clamp(210px, 25vw, 315px)',
                marginBottom: '0.2rem',
              }}
            >
              <div
                className="seraph-login-hero-orbit"
                aria-hidden="true"
                style={{
                  inset: '16% 8%',
                  borderRadius: '42% 58% 50% 50% / 58% 48% 52% 42%',
                }}
              />
              <img
                src="/angel-hero.png"
                alt="Seraph guardian"
                className="seraph-angel-figure"
                draggable={false}
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  objectPosition: 'center 20%',
                  filter: 'drop-shadow(0 0 42px rgba(0,240,255,0.26)) drop-shadow(0 0 70px rgba(255,43,214,0.18))',
                }}
              />
            </div>

            <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(250px,286px)] xl:items-start">
              <div className="flex-1">
                <div className="seraph-login-glow-wrap" style={{ textAlign: 'center' }}>
                  <h1 className="seraph-login-wordmark seraph-login-wordmark--centered" style={{ textAlign: 'center' }}>SERAPH</h1>
                </div>
                <p
                  className="mt-1 max-w-xl"
                  style={{
                    color: '#a8d8e6',
                    letterSpacing: '0.04em',
                    lineHeight: 1.45,
                    fontSize: '0.88rem',
                  }}
                >
                  Unified defensive command for threat telemetry, containment, orchestration, and guardian operations.
                </p>
                <div className="mt-2 grid grid-cols-3 gap-2">
                  {[
                    { icon: Activity, label: 'Telemetry', value: 'LIVE' },
                    { icon: Network, label: 'Network', value: 'MONITORED' },
                    { icon: Cpu, label: 'Inference', value: 'LOCAL' },
                  ].map(({ icon: Icon, label, value }) => (
                    <div
                      key={label}
                      className="seraph-login-metric"
                      style={{
                        background: 'linear-gradient(160deg, rgba(8,20,38,0.9), rgba(4,11,22,0.94))',
                        border: '1px solid rgba(0,240,255,0.24)',
                        boxShadow: '0 0 12px rgba(0,240,255,0.12), inset 0 0 12px rgba(255,255,255,0.02)',
                        borderRadius: '12px',
                        padding: '0.64rem 0.72rem',
                      }}
                    >
                      <div className="flex items-center gap-2.5 mb-1.5">
                        <div
                          style={{
                            width: 30,
                            height: 30,
                            display: 'grid',
                            placeItems: 'center',
                            border: '1px solid rgba(0,240,255,0.3)',
                            background: 'linear-gradient(135deg, rgba(0,240,255,0.12), rgba(188,19,254,0.08))',
                          }}
                        >
                          <Icon className="w-4 h-4" style={{ color: '#aef7ff' }} />
                        </div>
                        <span style={{ color: '#9ed3e6', fontFamily: "'JetBrains Mono', monospace", fontSize: '0.66rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                          {label}
                        </span>
                      </div>
                      <div style={{ color: '#f2fcff', fontFamily: "'Orbitron', sans-serif", fontSize: '0.84rem', letterSpacing: '0.08em' }}>
                        {value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div
                className="seraph-login-command-block"
                style={{
                  background: 'linear-gradient(160deg, rgba(5,14,28,0.9), rgba(2,8,19,0.96))',
                  border: '1px solid rgba(0,240,255,0.2)',
                  boxShadow: '0 0 20px rgba(0,240,255,0.08), inset 0 0 20px rgba(0,240,255,0.05)',
                  padding: '0.8rem 0.85rem',
                }}
              >
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div>
                    <p
                      style={{
                        color: '#8fefff',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.64rem',
                        letterSpacing: '0.24em',
                        textTransform: 'uppercase',
                      }}
                    >
                      Command Plane
                    </p>
                    <p
                      style={{
                        color: '#f2fcff',
                        fontFamily: "'Orbitron', sans-serif",
                        fontSize: '0.86rem',
                        letterSpacing: '0.08em',
                        marginTop: 4,
                      }}
                    >
                      Guardian Readiness
                    </p>
                  </div>
                  <div
                    style={{
                      width: 12,
                      height: 12,
                      borderRadius: '999px',
                      background: '#39ff14',
                      boxShadow: '0 0 12px rgba(57,255,20,0.85)',
                      flex: '0 0 auto',
                    }}
                  />
                </div>

                <div className="space-y-1.5">
                  {[
                    ['Threat Mesh', 'Synchronized'],
                    ['Identity Gate', 'Ready'],
                    ['Response Queue', 'Standby'],
                    ['Sensor Array', 'Online'],
                  ].map(([label, value]) => (
                    <div
                      key={label}
                      className="flex items-center justify-between gap-3 px-3 py-1.5"
                      style={{
                        border: '1px solid rgba(0,240,255,0.12)',
                        background: 'rgba(4,13,24,0.74)',
                      }}
                    >
                      <span
                        style={{
                          color: '#9ed3e6',
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.68rem',
                          letterSpacing: '0.08em',
                          textTransform: 'uppercase',
                        }}
                      >
                        {label}
                      </span>
                      <span
                        style={{
                          color: '#eafcff',
                          fontFamily: "'Orbitron', sans-serif",
                          fontSize: '0.7rem',
                          letterSpacing: '0.12em',
                          textTransform: 'uppercase',
                        }}
                      >
                        {value}
                      </span>
                    </div>
                  ))}
                </div>

                <div
                  className="mt-2"
                  style={{
                    paddingTop: '0.72rem',
                    borderTop: '1px solid rgba(0,240,255,0.14)',
                  }}
                >
                  <p
                    style={{
                      color: '#7fffd4',
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '0.68rem',
                      letterSpacing: '0.18em',
                      textTransform: 'uppercase',
                    }}
                  >
                    Uplink Stable
                  </p>
                  <div
                    className="mt-1.5"
                    style={{
                      height: 8,
                      background: 'rgba(255,255,255,0.06)',
                      border: '1px solid rgba(0,240,255,0.14)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: '82%',
                        height: '100%',
                        background: 'linear-gradient(90deg, rgba(0,240,255,0.9), rgba(188,19,254,0.72))',
                        boxShadow: '0 0 14px rgba(0,240,255,0.35)',
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={false}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.35 }}
            className="seraph-login-terminal-shell mt-1.5 w-full"
            style={{ maxWidth: 560 }}
          >
            <div
              className="relative px-4 py-2"
              style={{
                background: 'rgba(2, 8, 19, 0.78)',
                border: '1px solid rgba(0,240,255,0.22)',
                borderLeft: '3px solid var(--neon-green)',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.6rem',
                color: '#7fffd4',
                whiteSpace: 'pre',
                minHeight: 44,
                boxShadow: 'inset 0 0 20px rgba(57,255,20,0.05)',
                borderRadius: 2,
              }}
            >
              {bootText}
              <span
                style={{
                  display: 'inline-block',
                  width: 7,
                  height: 12,
                  marginLeft: 2,
                  background: 'var(--neon-green)',
                  boxShadow: '0 0 8px var(--neon-green)',
                  animation: 'seraph-pulse-neon 1.1s ease-in-out infinite',
                  verticalAlign: 'middle',
                }}
              />
            </div>
          </motion.div>
        </div>

        {/* ────────────────  RIGHT: LOGIN FORM  ──────────────── */}
        <div className="seraph-login-right-column flex items-center justify-center px-6 py-4 lg:py-4 lg:pr-10">
          <motion.div
            initial={false}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] }}
            className="w-full max-w-xl"
          >
            {/* Mobile mark */}
            <div className="lg:hidden mb-6 text-center">
              <div className="relative mx-auto mb-4 flex items-center justify-center" style={{ width: 180, height: 180 }}>
                <img
                  src="/angel-hero.png"
                  alt="Seraph"
                  className="seraph-angel-figure"
                  style={{ maxWidth: 170, filter: 'drop-shadow(0 0 22px rgba(0,240,255,0.22))' }}
                />
              </div>
              <h1
                className="seraph-gradient-text seraph-login-wordmark"
                style={{
                  fontFamily: "'Orbitron', sans-serif",
                  fontWeight: 900,
                  fontSize: '2.5rem',
                  letterSpacing: '0.12em',
                  lineHeight: 1,
                }}
              >
                SERAPH
              </h1>
            </div>

            {/* Section eyebrow */}
            <div className="flex items-center gap-3 mb-2">
              <span className="seraph-pip" />
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.7rem',
                  letterSpacing: '0.4em',
                  color: 'var(--neon-cyan)',
                  textTransform: 'uppercase',
                  textShadow: '0 0 10px rgba(0,240,255,0.5)',
                }}
              >
                {modeLabel}
              </span>
              <div className="flex-1 seraph-divider" />
            </div>

            <div className="seraph-corner-brackets relative seraph-fx-glitch-in">
              <span className="seraph-corner-tl" />
              <span className="seraph-corner-tr" />
              <span className="seraph-corner-bl" />
              <span className="seraph-corner-br" />

              <div
                className="seraph-login-panel relative p-7"
                style={{
                  background: 'linear-gradient(160deg, rgba(7,16,32,0.95), rgba(2,6,15,0.96))',
                  border: '1px solid rgba(0,240,255,0.32)',
                  boxShadow:
                    '0 0 60px rgba(0,240,255,0.16), 0 0 80px rgba(188,19,254,0.10), inset 0 0 24px rgba(0,240,255,0.06)',
                  backdropFilter: 'blur(18px)',
                }}
              >
                <div
                  aria-hidden="true"
                  className="absolute left-0 right-0"
                  style={{
                    top: 0,
                    height: 2,
                    background: 'linear-gradient(90deg, transparent, var(--neon-cyan), var(--neon-purple), transparent)',
                    opacity: 0.7,
                  }}
                />

                <div className="mb-6 space-y-3">
                  <h2
                    style={{
                      fontFamily: "'Orbitron', sans-serif",
                      fontWeight: 800,
                      fontSize: '1.6rem',
                      letterSpacing: '0.08em',
                      textTransform: 'uppercase',
                      background: 'linear-gradient(90deg, #ecfeff, #00f0ff 60%, #c084fc)',
                      WebkitBackgroundClip: 'text',
                      backgroundClip: 'text',
                      color: 'transparent',
                      filter: 'drop-shadow(0 0 12px rgba(0,240,255,0.4))',
                      margin: 0,
                    }}
                  >
                    {headingLabel}
                  </h2>
                  <p
                    className="text-xs"
                    style={{
                      color: '#9ed3e6',
                      fontFamily: "'JetBrains Mono', monospace",
                      letterSpacing: '0.04em',
                      lineHeight: 1.6,
                    }}
                  >
                    {subheadingLabel}
                  </p>
                  {bootstrapStatus.loading && (
                    <p
                      className="text-[11px]"
                      style={{
                        color: 'rgba(173, 235, 255, 0.72)',
                        fontFamily: "'JetBrains Mono', monospace",
                        letterSpacing: '0.03em',
                      }}
                    >
                      &gt; checking system bootstrap state...
                    </p>
                  )}
                </div>

                <form onSubmit={handleSubmit} className="space-y-5">
                  {(!isLogin || setupMode) && (
                    <div className="space-y-2">
                      <Label
                        htmlFor="name"
                        style={{
                          color: 'var(--neon-cyan)',
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.65rem',
                          letterSpacing: '0.32em',
                          textTransform: 'uppercase',
                        }}
                      >
                        Name
                      </Label>
                      <div className="relative">
                        <User
                          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 z-10"
                          style={{ color: 'var(--neon-cyan)', filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.6))' }}
                        />
                        <Input
                          id="name"
                          type="text"
                          placeholder="Your name"
                          value={formData.name}
                          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                          className="pl-10 seraph-input"
                          data-testid="register-name-input"
                          autoComplete="name"
                          required={!isLogin}
                        />
                      </div>
                    </div>
                  )}

                  <div className="space-y-2">
                    <Label
                      htmlFor="email"
                      style={{
                        color: 'var(--neon-cyan)',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.65rem',
                        letterSpacing: '0.32em',
                        textTransform: 'uppercase',
                      }}
                    >
                      Email
                    </Label>
                    <div className="relative">
                      <Mail
                        className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 z-10"
                        style={{ color: 'var(--neon-cyan)', filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.6))' }}
                      />
                      <Input
                        id="email"
                        type="email"
                        placeholder="analyst@defense.io"
                        value={formData.email}
                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                        className="pl-10 seraph-input"
                        data-testid="login-email-input"
                        autoComplete="username"
                        required
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label
                      htmlFor="password"
                      style={{
                        color: 'var(--neon-cyan)',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.65rem',
                        letterSpacing: '0.32em',
                        textTransform: 'uppercase',
                      }}
                    >
                      Password
                    </Label>
                    <div className="relative">
                      <Lock
                        className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 z-10"
                        style={{ color: 'var(--neon-purple)', filter: 'drop-shadow(0 0 6px rgba(188,19,254,0.6))' }}
                      />
                      <Input
                        id="password"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="••••••••"
                        value={formData.password}
                        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                        className="pl-10 pr-10 seraph-input"
                        data-testid="login-password-input"
                        autoComplete="current-password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 z-10"
                        style={{ color: 'rgba(0,240,255,0.6)' }}
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {setupMode && bootstrapStatus.setupTokenRequired && (
                    <div className="space-y-2">
                      <Label
                        htmlFor="setupToken"
                        style={{
                          color: 'var(--neon-cyan)',
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.65rem',
                          letterSpacing: '0.24em',
                          textTransform: 'uppercase',
                        }}
                      >
                        Setup Token
                      </Label>
                      <Input
                        id="setupToken"
                        type="password"
                        placeholder="X-Setup-Token"
                        value={formData.setupToken}
                        onChange={(e) => setFormData({ ...formData, setupToken: e.target.value })}
                        className="seraph-input"
                        autoComplete="one-time-code"
                        required
                      />
                    </div>
                  )}

                  <Button
                    type="submit"
                    disabled={loading}
                    className="seraph-btn seraph-btn-primary w-full py-5 mt-2"
                    data-testid="login-submit-btn"
                    style={{ borderRadius: 0 }}
                  >
                    {loading ? (
                      <span className="flex items-center justify-center gap-2">
                        <span
                          className="inline-block w-4 h-4 rounded-full border-2"
                          style={{
                            borderColor: 'rgba(0,0,0,0.3)',
                            borderTopColor: '#02050d',
                            animation: 'seraph-loader-spin 0.9s linear infinite',
                          }}
                        />
                        AUTHENTICATING...
                      </span>
                    ) : (
                      <span className="flex items-center justify-center gap-2">
                        <ShieldCheck className="w-5 h-5" />
                        {setupMode ? 'INITIALIZE SYSTEM' : (isLogin ? 'ACCESS SYSTEM' : 'CREATE GUARDIAN')}
                      </span>
                    )}
                  </Button>
                </form>

                {!setupMode && (
                  <div className="mt-5 pt-4" style={{ borderTop: '1px solid rgba(0,240,255,0.18)' }}>
                    <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                      <p
                        style={{
                          color: '#9ed3e6',
                          fontFamily: "'JetBrains Mono', monospace",
                          letterSpacing: '0.04em',
                        }}
                      >
                        {isLogin ? '// no guardian profile?' : '// already a guardian?'}
                      </p>
                      <button
                        type="button"
                        onClick={() => setIsLogin(!isLogin)}
                        data-testid="toggle-auth-mode"
                        className="seraph-auth-toggle"
                        style={{
                          color: 'var(--neon-cyan)',
                          fontWeight: 600,
                          textShadow: '0 0 10px rgba(0,240,255,0.5)',
                          textDecoration: 'underline',
                          textUnderlineOffset: 4,
                        }}
                      >
                        {isLogin ? 'REGISTER' : 'LOGIN'}
                      </button>
                    </div>
                  </div>
                )}

                <div
                  className="mt-3 p-3 flex items-start gap-2"
                  style={{
                    background: 'linear-gradient(90deg, rgba(188,19,254,0.10), rgba(0,240,255,0.04))',
                    border: '1px solid rgba(188,19,254,0.32)',
                    borderLeft: '2px solid var(--neon-purple)',
                    boxShadow: 'inset 0 0 12px rgba(188,19,254,0.05)',
                  }}
                >
                  <AlertTriangle
                    className="w-4 h-4 mt-0.5 flex-shrink-0"
                    style={{ color: '#e9b6ff', filter: 'drop-shadow(0 0 6px rgba(188,19,254,0.7))' }}
                  />
                  <p
                    className="text-[10px]"
                    style={{
                      color: '#d8b6ff',
                      fontFamily: "'JetBrains Mono', monospace",
                      letterSpacing: '0.03em',
                      lineHeight: 1.45,
                    }}
                    >
                    {setupMode
                      ? 'Initial guardian provisioning will create the first administrator account for this deployment.'
                      : 'Classified defense system. Unauthorized access attempts are logged and monitored.'}
                  </p>
                </div>
              </div>
            </div>

            <div
              className="mt-4 flex items-center justify-between text-[10px]"
              style={{
                color: 'rgba(174,217,232,0.55)',
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: '0.2em',
              }}
            >
              <div className="flex items-center gap-2">
                <span className="seraph-pip seraph-pip--green" style={{ width: 6, height: 6 }} />
                <span>UPLINK · ONLINE</span>
              </div>
              <span>v4.4.2 // ARDA</span>
            </div>

            <div className="mt-3 seraph-login-music-shell">
              <MusicPlayer
                tracks={[
                  { src: '/seraph-track-1.mp3', title: 'SERAPHIM // BOOT.SEQUENCE' },
                  { src: '/seraph-track-2.mp3', title: 'SERAPHIM // ARDA.PULSE' },
                  { src: '/synth1.mp3', title: 'SYNTH1 // CELESTIAL.DRIFT' },
                  { src: '/synth2.mp3', title: 'SYNTH2 // NEON.WARD' },
                ]}
              />
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
