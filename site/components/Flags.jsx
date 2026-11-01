// Flags for the demo's two caption languages: Argentina for Spanish, the United States for English.

// Sol de Mayo: 16 rays around a disc, inside the white band.
const SUN = Array.from({ length: 32 }, (_, i) => {
  const r = i % 2 ? 1.75 : 2.75;
  const a = (Math.PI * i) / 16 - Math.PI / 2;
  return `${(15 + r * Math.cos(a)).toFixed(2)},${(10 + r * Math.sin(a)).toFixed(2)}`;
}).join(' ');

function FlagAR() {
  return (
    <svg viewBox="0 0 30 20" aria-hidden="true">
      <rect width="30" height="20" fill="#74acdf" />
      <rect y="6.67" width="30" height="6.66" fill="#fff" />
      <polygon points={SUN} fill="#f6b40e" />
      <circle cx="15" cy="10" r="1.45" fill="#f6b40e" stroke="#85340a" strokeWidth="0.25" />
    </svg>
  );
}

const STRIPE = 20 / 13;

function FlagUS() {
  return (
    <svg viewBox="0 0 30 20" aria-hidden="true">
      <rect width="30" height="20" fill="#fff" />
      {[0, 2, 4, 6, 8, 10, 12].map((i) => (
        <rect key={i} y={i * STRIPE} width="30" height={STRIPE} fill="#b22234" />
      ))}
      <rect width="12" height={7 * STRIPE} fill="#3c3b6e" />
      {[0, 1, 2, 3].flatMap((row) =>
        [0, 1, 2, 3, 4].map((col) => (
          <circle key={`${row}-${col}`} cx={1.5 + col * 2.25} cy={1.6 + row * 2.5} r="0.55" fill="#fff" />
        )),
      )}
    </svg>
  );
}

export function Flag({ lang }) {
  return <span className="flag">{lang === 'es' ? <FlagAR /> : <FlagUS />}</span>;
}
