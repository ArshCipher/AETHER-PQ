// Live-feel hooks: ticking clock, jittered live values, animated counters,
// live time-series that append a new sample on a fixed cadence.
import { useEffect, useRef, useState } from "react";

/** Global monotonic tick — advances every `intervalMs`. */
export function useTicker(intervalMs = 1000) {
  const [t, setT] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setT((n) => n + 1), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return t;
}

/** Live wall-clock (UTC) formatted HH:mm:ssZ. Stable across SSR. */
export function useLiveClock() {
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    setNow(new Date());
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);
  if (!now) return "--:--:--Z";
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())}Z`;
}

/** Smoothly animate a numeric value using rAF. Good for KPI counters. */
export function useCountUp(target: number, durationMs = 700) {
  const [v, setV] = useState(target);
  const fromRef = useRef(target);
  const startRef = useRef<number | null>(null);
  const rafRef = useRef<number | null>(null);
  const targetRef = useRef(target);

  useEffect(() => {
    if (target === targetRef.current) return;
    fromRef.current = v;
    targetRef.current = target;
    startRef.current = null;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    const step = (ts: number) => {
      if (startRef.current == null) startRef.current = ts;
      const p = Math.min(1, (ts - startRef.current) / durationMs);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - p, 3);
      const next = fromRef.current + (target - fromRef.current) * eased;
      setV(next);
      if (p < 1) rafRef.current = requestAnimationFrame(step);
    };
    rafRef.current = requestAnimationFrame(step);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, durationMs]);

  return v;
}


/** True after client hydration — use to gate live-only UI safely. */
export function useHydrated() {
  const [h, setH] = useState(false);
  useEffect(() => setH(true), []);
  return h;
}
