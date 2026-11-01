'use client';

import { useEffect, useRef, useState } from 'react';
import { Flag } from './Flags';

// The demo, one cut per caption language. The files are served from outside the build (content/demo.js). The
// switch above the video picks the language, and ?lang=es opens it in that language.
export default function DemoVideo({ sources, title = 'demo · v0' }) {
  const [lang, setLang] = useState(sources[0].lang);
  const langRef = useRef(lang);
  langRef.current = lang;
  const pending = useRef(null);
  const ref = useRef(null);
  const current = sources.find((s) => s.lang === lang) || sources[0];

  // Both languages share one cut, so a switch keeps the position and the play state.
  function choose(next) {
    if (next === langRef.current || !sources.some((s) => s.lang === next)) return;
    const v = ref.current;
    pending.current = v ? { t: v.currentTime, play: !v.paused } : null;
    setLang(next);
  }

  useEffect(() => {
    const asked = new URLSearchParams(window.location.search).get('lang');
    if (asked) choose(asked);
    // choose reads only refs and the sources, so the first one stays valid.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function onLoaded(e) {
    const p = pending.current;
    if (!p) return;
    pending.current = null;
    e.currentTarget.currentTime = p.t;
    if (p.play) e.currentTarget.play().catch(() => {});
  }

  return (
    <figure className="frame demo">
      <figcaption className="frame-bar">
        <span className="frame-title">{title}</span>
        {sources.length > 1 ? (
          <span className="demo-langs" role="group" aria-label="Caption language">
            {sources.map((s) => (
              <button
                key={s.lang}
                type="button"
                className="demo-lang"
                data-lang={s.lang}
                aria-pressed={s.lang === lang}
                onClick={() => choose(s.lang)}
              >
                <Flag lang={s.lang} />
                {s.label}
              </button>
            ))}
          </span>
        ) : null}
      </figcaption>
      <video
        key={current.src}
        ref={ref}
        className="demo-video"
        src={current.src}
        poster={current.poster || undefined}
        controls
        preload="metadata"
        playsInline
        onLoadedMetadata={onLoaded}
      />
    </figure>
  );
}
