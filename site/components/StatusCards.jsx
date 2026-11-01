import { MATRIX, STATE_LABEL } from '../content/status';
import { cellState } from '../lib/evidence';
import { IconCommand, IconPenguin, IconTerminal } from './Icons';

const OS_ICON = { macOS: IconCommand, Linux: IconPenguin };
const KINDS = [
  ['apps', 'Apps on the machine'],
  ['tasks', 'Tasks an agent runs'],
];

export function StatusDot({ state, label }) {
  return (
    <span className={`state state-${state}`}>
      <span className="state-dot" aria-hidden="true" />
      {label || STATE_LABEL[state]}
    </span>
  );
}

// One card per operating system. States are computed when the site builds.
export default function StatusCards() {
  return (
    <div className="os-cards">
      {MATRIX.map((row) => {
        const Icon = OS_ICON[row.os] || IconTerminal;
        return (
          <article className="os-card" key={row.os}>
            <header>
              <span className="os-icon">
                <Icon size={18} />
              </span>
              <h3>{row.os}</h3>
            </header>
            {KINDS.map(([k, label]) => (
              <div className="os-row" key={k}>
                <div className="os-row-head">
                  <span>{label}</span>
                  <StatusDot state={cellState(row[k])} />
                </div>
                <p>{row[k].how}</p>
                {row[k].note && <p>{row[k].note}</p>}
              </div>
            ))}
          </article>
        );
      })}
    </div>
  );
}
