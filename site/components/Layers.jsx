'use client';

import { useEffect, useRef, useState } from 'react';
import { IconTerminal, IconNested, IconPolicy, IconChip, IconGlobe } from './Icons';

// The v0 enforcement path as designed, drawn as a stack of glass slabs in CSS 3D.
const LAYERS = [
  { key: 'process', name: 'Process', Icon: IconTerminal, text: 'fx, a test runner or an install, and every process they start.' },
  { key: 'scope', name: 'Task scope', Icon: IconNested, text: 'Created before exec. Every child process inherits it, and none can leave it.' },
  { key: 'policy', name: 'Policy', Icon: IconPolicy, text: 'A strict JSON file, loaded once: a mode, allowed names, subnets and ports.' },
  {
    key: 'enforce',
    name: 'Enforcement',
    Icon: IconChip,
    text: 'On macOS, the built-in sandbox. On Linux, eBPF on the task\'s cgroup. Either way the command can reach only a local proxy, which checks every name and address. A denied connection stops here.',
  },
  { key: 'net', name: 'Network', Icon: IconGlobe, text: 'Only destinations the policy names get through. Every proxy decision writes a receipt, or is counted as dropped if the write fails.' },
];

// Where the three connections cross the stack, in the planes' 230px space.
const ALLOW_A = [64, 150];
const ALLOW_B = [162, 72];
const DENY = [150, 168];

// A drawing on each plane, flat in the plane's own space.
function PlaneArt({ kind }) {
  if (kind === 'process') {
    return (
      <svg className="plane-art" viewBox="0 0 230 230">
        <path className="pa-tree" d={`M104 104 ${ALLOW_A.join(' ')}M104 104 ${ALLOW_B.join(' ')}M104 104 ${DENY.join(' ')}`} />
        <circle className="pa-root" cx="104" cy="104" r="5.5" />
        {[ALLOW_A, ALLOW_B, DENY].map(([x, y]) => (
          <circle key={x} className="pa-node" cx={x} cy={y} r="3.5" />
        ))}
      </svg>
    );
  }
  if (kind === 'scope') {
    return (
      <svg className="plane-art" viewBox="0 0 230 230">
        <path className="pa-corner" d="M10 38V10h28M192 10h28v28M220 192v28h-28M38 220H10v-28" />
      </svg>
    );
  }
  if (kind === 'policy') {
    return (
      <svg className="plane-art" viewBox="0 0 230 230">
        <path className="pa-rule" d="M48 52h92M48 76h116M48 100h76" />
        <path className="pa-rule pa-rule-deny" d="M48 124h104" />
        <circle className="pa-dot pa-dot-allow" cx="36" cy="52" r="2.5" />
        <circle className="pa-dot pa-dot-allow" cx="36" cy="76" r="2.5" />
        <circle className="pa-dot pa-dot-allow" cx="36" cy="100" r="2.5" />
        <circle className="pa-dot pa-dot-deny" cx="36" cy="124" r="2.5" />
      </svg>
    );
  }
  if (kind === 'enforce') {
    return (
      <svg className="plane-art" viewBox="0 0 230 230">
        {[ALLOW_A, ALLOW_B].map(([x, y]) => (
          <rect key={x} className="pa-gate pa-gate-ok" x={x - 8} y={y - 8} width="16" height="16" rx="3" />
        ))}
        <rect className="pa-gate pa-gate-deny" x={DENY[0] - 8} y={DENY[1] - 8} width="16" height="16" rx="3" />
        <path className="pa-gate-x" d={`M${DENY[0] - 4} ${DENY[1] - 4}l8 8m0-8-8 8`} />
      </svg>
    );
  }
  return (
    <svg className="plane-art" viewBox="0 0 230 230">
      {[ALLOW_A, ALLOW_B].map(([x, y]) => (
        <g key={x}>
          <circle className="pa-dest-ring" cx={x} cy={y} r="11" />
          <circle className="pa-dest" cx={x} cy={y} r="2.5" />
        </g>
      ))}
      <circle className="pa-dest-ring pa-dest-off" cx={DENY[0]} cy={DENY[1]} r="11" />
    </svg>
  );
}

const pos = ([x, y], extra) => ({ '--x': `${x}px`, '--y': `${y}px`, ...extra });

export default function Layers() {
  const rootRef = useRef(null);
  const stageRef = useRef(null);
  const tiltRef = useRef(null);
  const [active, setActive] = useState(null);
  const [pre, setPre] = useState(false);

  useEffect(() => {
    const root = rootRef.current;
    const stage = stageRef.current;
    const tilt = tiltRef.current;
    if (!root || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return undefined;

    // Below the fold, the stack waits collapsed and opens up when it scrolls into view.
    let io;
    if (root.getBoundingClientRect().top > window.innerHeight * 0.8) {
      setPre(true);
      io = new IntersectionObserver(
        ([entry]) => {
          if (!entry.isIntersecting) return;
          setPre(false);
          io.disconnect();
        },
        { threshold: 0.2 },
      );
      io.observe(root);
    }

    // The stack leans toward the pointer.
    const fine = !window.matchMedia('(pointer: coarse)').matches;
    const onMove = (e) => {
      const r = stage.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5;
      const y = (e.clientY - r.top) / r.height - 0.5;
      tilt.style.setProperty('--tilt-x', `${(x * 16).toFixed(2)}deg`);
      tilt.style.setProperty('--tilt-y', `${(-y * 10).toFixed(2)}deg`);
    };
    const onLeave = () => {
      tilt.style.setProperty('--tilt-x', '0deg');
      tilt.style.setProperty('--tilt-y', '0deg');
    };
    if (fine) {
      stage.addEventListener('pointermove', onMove);
      stage.addEventListener('pointerleave', onLeave);
    }
    return () => {
      io?.disconnect();
      stage.removeEventListener('pointermove', onMove);
      stage.removeEventListener('pointerleave', onLeave);
    };
  }, []);

  return (
    <div ref={rootRef} className={`layers${pre ? ' is-pre' : ''}`} data-active={active || undefined}>
      <div className="layers-stage" ref={stageRef} aria-hidden="true">
        <div className="layers-tilt" ref={tiltRef}>
          <div className="layers-3d">
            {LAYERS.map((l, i) => (
              <div
                className={`plane plane-${l.key}${active === l.key ? ' is-active' : ''}`}
                style={{ '--i': i }}
                key={l.key}
                onMouseEnter={() => setActive(l.key)}
                onMouseLeave={() => setActive(null)}
              >
                <span className="slab slab-b" />
                <span className="slab slab-l" />
                <PlaneArt kind={l.key} />
                {l.key === 'enforce' ? (
                  <>
                    <span className="plane-scan" />
                    <span className="plane-flash" />
                  </>
                ) : null}
                <span className="plane-tag">
                  <b>0{i + 1}</b>
                  <span className="pt-name">{l.name}</span>
                </span>
              </div>
            ))}
            <span className="beam-v" style={pos(ALLOW_A)} />
            <span className="beam-v" style={pos(ALLOW_B)} />
            <span className="beam-v beam-v-deny" style={pos(DENY)} />
            <span className="pkt pkt-allow" style={pos(ALLOW_A, { '--d': '0s' })} />
            <span className="pkt pkt-allow" style={pos(ALLOW_B, { '--d': '1.9s' })} />
            <span className="pkt pkt-deny" style={pos(DENY, { '--d': '3.8s' })} />
            <span className="ring" style={pos(DENY)} />
            <span className="ring ring-2" style={pos(DENY)} />
            <span className="pkt-tag pkt-tag-allow" style={pos(ALLOW_A)}>
              allowed_by_rule
            </span>
            <span className="pkt-tag pkt-tag-deny" style={pos(DENY)}>
              no_matching_rule
            </span>
          </div>
        </div>
      </div>
      <ol className="layers-list">
        {LAYERS.map(({ key, name, Icon, text }, i) => (
          <li
            key={key}
            className={[key === 'enforce' ? 'is-enforce' : '', active === key ? 'is-active' : ''].join(' ').trim() || undefined}
            onMouseEnter={() => setActive(key)}
            onMouseLeave={() => setActive(null)}
          >
            <span className="layer-icon">
              <Icon size={16} />
            </span>
            <div>
              <p className="layer-name">
                <span className="mono faint">0{i + 1}</span>
                {name}
              </p>
              <p className="layer-text">{text}</p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
