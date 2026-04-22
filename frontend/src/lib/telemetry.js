const isDev = process.env.NODE_ENV !== 'production';

// Lightweight structured telemetry. Drop-in for Sentry/LogRocket later.
const telemetry = {
  /** General informational event */
  log(event, data = {}) {
    if (isDev) console.log(`[${event}]`, data);
  },

  /** Structured error with context */
  error(event, err, context = {}) {
    const entry = {
      event,
      message: err?.message || String(err),
      ...(isDev && { stack: err?.stack }),
      ...context,
      timestamp: new Date().toISOString(),
      path: typeof window !== 'undefined' ? window.location.pathname : '',
    };
    if (isDev) console.error(`[ERR:${event}]`, entry);
    // TODO: telemetry.error → POST /api/client-errors or Sentry.captureException(err)
  },

  /** User-initiated action tracking */
  action(action, data = {}) {
    if (isDev) console.log(`[ACTION:${action}]`, data);
    // TODO: send to analytics pipeline
  },

  /** API latency / performance mark */
  perf(label, ms) {
    if (isDev) console.log(`[PERF:${label}] ${ms}ms`);
    // TODO: send to APM
  },
};

export default telemetry;
