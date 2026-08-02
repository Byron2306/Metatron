import { useEffect, useRef, useState } from 'react';
import { Play, Pause, SkipForward, Volume2, VolumeX, Music } from 'lucide-react';

const DEFAULT_TRACKS = [
  { src: '/seraph-track-1.mp3', title: 'SERAPHIM // BOOT.SEQUENCE' },
  { src: '/seraph-track-2.mp3', title: 'SERAPHIM // ARDA.PULSE' },
];

const STORAGE_KEY = 'seraph-music-state';

export default function MusicPlayer({ tracks = DEFAULT_TRACKS }) {
  const activeTracks = Array.isArray(tracks) && tracks.length ? tracks : DEFAULT_TRACKS;
  const audioRef = useRef(null);
  const [trackIdx, setTrackIdx] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [muted, setMuted] = useState(false);
  const [volume, setVolume] = useState(0.45);
  const [progress, setProgress] = useState(0);
  const [bars, setBars] = useState(() => Array(18).fill(0.2));

  // Refs to hold values from localStorage that need to be applied after audio loads
  const restoredPlayingRef = useRef(false);
  const restoredTimeRef = useRef(0);

  // Restore previous state
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const s = JSON.parse(raw);
        if (typeof s.volume === 'number') setVolume(s.volume);
        if (typeof s.muted === 'boolean') setMuted(s.muted);
        if (typeof s.trackIdx === 'number') setTrackIdx(s.trackIdx);
        restoredPlayingRef.current = s.playing === true;
        restoredTimeRef.current = typeof s.currentTime === 'number' ? s.currentTime : 0;
      }
    } catch { /* ignore */ }
  }, []);

  // Persist state (including playing)
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ volume, muted, trackIdx, playing }));
    } catch { /* ignore */ }
  }, [volume, muted, trackIdx, playing]);

  // Apply audio props
  useEffect(() => {
    const a = audioRef.current;
    if (!a) return;
    a.volume = volume;
    a.muted = muted;
  }, [volume, muted]);

  // Animated visualizer bars (synthetic — driven by playing state)
  useEffect(() => {
    if (!playing) {
      setBars(Array(18).fill(0.15));
      return;
    }
    const id = setInterval(() => {
      setBars(Array.from({ length: 18 }, () => 0.25 + Math.random() * 0.75));
    }, 110);
    return () => clearInterval(id);
  }, [playing]);

  // Progress tick + currentTime persistence
  useEffect(() => {
    const a = audioRef.current;
    if (!a) return;
    let lastSavedSecond = -1;
    const onTime = () => {
      if (a.duration) setProgress(a.currentTime / a.duration);
      // Save currentTime to localStorage every ~5 seconds
      const sec = Math.floor(a.currentTime);
      if (sec !== lastSavedSecond && sec % 5 === 0 && sec > 0) {
        lastSavedSecond = sec;
        try {
          const raw = localStorage.getItem(STORAGE_KEY);
          if (raw) {
            const s = JSON.parse(raw);
            localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...s, currentTime: a.currentTime }));
          }
        } catch { /* ignore */ }
      }
    };
    const onEnd = () => {
      // Clear saved time when track ends naturally
      try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) {
          const s = JSON.parse(raw);
          localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...s, currentTime: 0 }));
        }
      } catch { /* ignore */ }
      setTrackIdx((i) => (i + 1) % activeTracks.length);
    };
    const onPlay = () => setPlaying(true);
    const onPause = () => setPlaying(false);
    a.addEventListener('timeupdate', onTime);
    a.addEventListener('ended', onEnd);
    a.addEventListener('play', onPlay);
    a.addEventListener('pause', onPause);
    return () => {
      a.removeEventListener('timeupdate', onTime);
      a.removeEventListener('ended', onEnd);
      a.removeEventListener('play', onPlay);
      a.removeEventListener('pause', onPause);
    };
  }, [activeTracks.length]);

  // Clamp stored track index when playlist size changes.
  useEffect(() => {
    setTrackIdx((idx) => idx % activeTracks.length);
  }, [activeTracks.length]);

  // Auto-load new track when index changes; restore position + autoplay if needed
  useEffect(() => {
    const a = audioRef.current;
    if (!a) return;
    const wasPlaying = playing;
    const shouldAutoPlay = restoredPlayingRef.current || wasPlaying;
    const restoreTime = restoredTimeRef.current;
    // Consume restore refs (only apply once on initial mount)
    restoredPlayingRef.current = false;
    restoredTimeRef.current = 0;

    a.src = activeTracks[trackIdx % activeTracks.length].src;
    a.load();

    if (shouldAutoPlay) {
      const onReady = () => {
        if (restoreTime > 0) {
          try { a.currentTime = restoreTime; } catch { /* ignore */ }
        }
        a.play().catch(() => setPlaying(false));
        a.removeEventListener('canplay', onReady);
      };
      a.addEventListener('canplay', onReady);
      return () => a.removeEventListener('canplay', onReady);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trackIdx, activeTracks]);

  const togglePlay = () => {
    const a = audioRef.current;
    if (!a) return;
    if (a.paused) {
      a.play().catch(() => setPlaying(false));
    } else {
      a.pause();
    }
  };

  const nextTrack = () => setTrackIdx((i) => (i + 1) % activeTracks.length);

  return (
    <div
      className="seraph-music-player"
      style={{
        position: 'relative',
        padding: '12px 14px',
        background: 'linear-gradient(135deg, rgba(0,240,255,0.08), rgba(188,19,254,0.06))',
        border: '1px solid rgba(0,240,255,0.32)',
        boxShadow: 'inset 0 0 14px rgba(0,240,255,0.06), 0 0 18px rgba(0,240,255,0.08)',
        clipPath:
          'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
      }}
    >
      {/* Top accent line */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: 1,
          background:
            'linear-gradient(90deg, transparent, var(--neon-cyan), var(--neon-purple), transparent)',
          opacity: 0.55,
        }}
      />

      <div className="flex items-center gap-2 mb-2">
        <Music
          className="w-3.5 h-3.5 flex-shrink-0"
          style={{
            color: 'var(--neon-cyan)',
            filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.7))',
          }}
        />
        <span
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            letterSpacing: '0.18em',
            color: '#b6f5ff',
            textTransform: 'uppercase',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            flex: 1,
            textShadow: '0 0 8px rgba(0,240,255,0.4)',
          }}
        >
          {activeTracks[trackIdx % activeTracks.length].title}
        </span>
      </div>

      {/* Visualizer */}
      <div
        className="flex items-end gap-[2px] mb-2"
        style={{ height: 22, padding: '2px 0' }}
        aria-hidden="true"
      >
        {bars.map((b, i) => (
          <span
            key={i}
            style={{
              flex: 1,
              height: `${Math.max(8, b * 100)}%`,
              background: `linear-gradient(180deg, ${
                i % 3 === 0 ? '#ff2bd6' : i % 3 === 1 ? '#bc13fe' : '#00f0ff'
              }, rgba(0,240,255,0.2))`,
              boxShadow: `0 0 4px ${
                i % 3 === 0 ? 'rgba(255,43,214,0.7)' : 'rgba(0,240,255,0.7)'
              }`,
              transition: 'height 110ms ease-out',
            }}
          />
        ))}
      </div>

      {/* Progress bar */}
      <div
        style={{
          position: 'relative',
          height: 2,
          background: 'rgba(0,240,255,0.12)',
          marginBottom: 8,
          cursor: 'pointer',
        }}
        onClick={(e) => {
          const a = audioRef.current;
          if (!a || !a.duration) return;
          const rect = e.currentTarget.getBoundingClientRect();
          const pct = (e.clientX - rect.left) / rect.width;
          a.currentTime = pct * a.duration;
        }}
      >
        <span
          style={{
            position: 'absolute',
            left: 0,
            top: 0,
            bottom: 0,
            width: `${progress * 100}%`,
            background:
              'linear-gradient(90deg, var(--neon-cyan), var(--neon-purple), var(--neon-pink))',
            boxShadow: '0 0 8px rgba(0,240,255,0.8)',
          }}
        />
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={togglePlay}
            aria-label={playing ? 'Pause' : 'Play'}
            className="flex items-center justify-center transition-all"
            style={{
              width: 30,
              height: 30,
              background: playing
                ? 'linear-gradient(135deg, #00f0ff, #7c3aed, #ff2bd6)'
                : 'rgba(0,240,255,0.1)',
              border: '1px solid rgba(0,240,255,0.5)',
              color: playing ? '#02050d' : '#aef0ff',
              boxShadow: playing
                ? '0 0 16px rgba(0,240,255,0.6), 0 0 28px rgba(188,19,254,0.4)'
                : 'inset 0 0 8px rgba(0,240,255,0.08)',
              clipPath:
                'polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px)',
            }}
          >
            {playing ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5 ml-0.5" />}
          </button>

          <button
            type="button"
            onClick={nextTrack}
            aria-label="Next track"
            className="flex items-center justify-center transition-all"
            style={{
              width: 26,
              height: 26,
              background: 'rgba(0,240,255,0.06)',
              border: '1px solid rgba(0,240,255,0.32)',
              color: '#aef0ff',
              clipPath:
                'polygon(5px 0, 100% 0, 100% calc(100% - 5px), calc(100% - 5px) 100%, 0 100%, 0 5px)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = 'var(--neon-cyan)';
              e.currentTarget.style.boxShadow = '0 0 10px rgba(0,240,255,0.5)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'rgba(0,240,255,0.32)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            <SkipForward className="w-3 h-3" />
          </button>

          <button
            type="button"
            onClick={() => setMuted((m) => !m)}
            aria-label={muted ? 'Unmute' : 'Mute'}
            className="flex items-center justify-center transition-all"
            style={{
              width: 26,
              height: 26,
              background: muted ? 'rgba(255,43,214,0.1)' : 'rgba(0,240,255,0.06)',
              border: muted ? '1px solid rgba(255,43,214,0.5)' : '1px solid rgba(0,240,255,0.32)',
              color: muted ? '#ff8ad9' : '#aef0ff',
              clipPath:
                'polygon(5px 0, 100% 0, 100% calc(100% - 5px), calc(100% - 5px) 100%, 0 100%, 0 5px)',
            }}
          >
            {muted ? <VolumeX className="w-3 h-3" /> : <Volume2 className="w-3 h-3" />}
          </button>
        </div>

        <input
          type="range"
          min={0}
          max={1}
          step={0.02}
          value={volume}
          onChange={(e) => setVolume(parseFloat(e.target.value))}
          aria-label="Volume"
          className="seraph-music-vol"
          style={{
            flex: 1,
            height: 2,
            accentColor: '#00f0ff',
          }}
        />
      </div>

      <audio ref={audioRef} src={activeTracks[trackIdx % activeTracks.length].src} preload="metadata" loop={false} />
    </div>
  );
}
