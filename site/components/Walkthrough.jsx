'use client';

import { useState } from 'react';

// The narrated walkthrough, served from outside the build (content/demo.js): English, subtitles in the picture. With
// more than one cut, a switch picks the length; each cut starts from the beginning and shows its own caption.
export default function Walkthrough({ cuts }) {
  const [id, setId] = useState(cuts[0].id);
  const cut = cuts.find((c) => c.id === id) || cuts[0];

  return (
    <>
      <figure className="frame demo">
        <figcaption className="frame-bar">
          <span className="frame-title">walkthrough</span>
          {cuts.length > 1 ? (
            <span className="demo-langs" role="group" aria-label="Length">
              {cuts.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className="demo-lang"
                  aria-pressed={c.id === cut.id}
                  onClick={() => setId(c.id)}
                >
                  {c.label}
                </button>
              ))}
            </span>
          ) : (
            <span>{cut.label}</span>
          )}
        </figcaption>
        <video
          key={cut.src}
          className="demo-video"
          src={cut.src}
          poster={cut.poster || undefined}
          controls
          preload="metadata"
          playsInline
        />
      </figure>
      {cut.caption ? <p className="caption">{cut.caption}</p> : null}
    </>
  );
}
