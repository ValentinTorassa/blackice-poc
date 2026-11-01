import Link from 'next/link';
import { Nav, Footer } from '../components/Chrome';
import Scene from '../components/Scene';
import CopyCommand from '../components/CopyCommand';
import Spotlight from '../components/Spotlight';
import TypedTerminal from '../components/TypedTerminal';
import Layers from '../components/Layers';
import CubeMark from '../components/CubeMark';
import StatusCards from '../components/StatusCards';
import Corners from '../components/Corners';
import DemoVideo from '../components/DemoVideo';
import Walkthrough from '../components/Walkthrough';
import Install from '../components/Install';
import { RELEASE } from '../content/site';
import { IsoScope, IsoPolicy, IsoReceipt } from '../components/Iso';
import {
  Logo,
  IconArrowRight,
  IconBook,
  IconArrowInto,
  IconCommand,
  IconFlag,
  IconLines,
  IconNarrow,
  IconGitHub,
  IconNested,
  IconPenguin,
  IconPolicy,
  IconReceipt,
  IconScale,
  IconTerminal,
} from '../components/Icons';
import { SITE } from '../content/site';
import { DEMO, WALKTHROUGH } from '../content/demo';
import { CHECKPOINTS } from '../content/status';
import { findingsCheckpoints, recordedCheckpoints } from '../lib/evidence';

const NOUNS = [
  {
    name: 'Scope',
    Icon: IconNested,
    Art: IsoScope,
    text: 'What a policy applies to: one command and everything it starts, an app on the machine, or the whole host.',
  },
  {
    name: 'Policy',
    Icon: IconPolicy,
    Art: IsoPolicy,
    text: 'A JSON file. Anything it doesn\'t allow by name, subnet or port is refused, and every address a name resolves to is checked too.',
  },
  {
    name: 'Receipt',
    Icon: IconReceipt,
    Art: IsoReceipt,
    text: 'Flat JSON lines with a stable reason code: which scope, which version of the policy, where it was enforced, and why. tail, grep and jq work on them.',
  },
];

const SESSION = [
  ['cmd', `${SITE.name} run --policy policy.json -- sh`],
  ['out', 'scope s-7f3a91c2 armed  ·  policy cae35a3beb20  ·  gen 1'],
  ['cmd', "curl -so /dev/null -w '%{http_code}\\n' https://registry.npmjs.org", 'inside the scope'],
  ['ok', '200'],
  ['cmd', 'curl -sS https://paste.example'],
  ['deny', 'curl: (56) CONNECT tunnel failed, response 403'],
  ['cmd', "tail -1 ~/.local/state/blackice/scopes/s-7f3a91c2/receipts.jsonl | jq -c '{verdict,reason,host}'", 'as the owner'],
  ['out', '{"verdict":"deny","reason":"no_matching_rule","host":"paste.example"}'],
  ['cmd', `${SITE.name} grant s-7f3a91c2 api.example.com --for 10m`, 'as the owner'],
  ['out', 'granted api.example.com to scope s-7f3a91c2 until 2026-10-30T12:10:03.000Z'],
];

const UNIX = [
  {
    name: 'chroot',
    Icon: IconArrowInto,
    text: 'A chroot is set before the program runs. So is the policy: it is in place before the command runs its first instruction, so even its first connection is checked.',
  },
  {
    name: 'pledge(2)',
    Icon: IconNarrow,
    text: 'After pledge, a process can only give up access. Inside a scope it is the same: nothing can get more. The owner can widen it from outside, until a set time.',
  },
  {
    name: 'Rule of Repair',
    Icon: IconFlag,
    text: "Fail noisily and as soon as possible. If the policy doesn't load, or doesn't match its pinned hash, the command never starts.",
  },
  {
    name: 'Everything is a file',
    Icon: IconLines,
    text: 'The policy is a file, and each logged decision is a line appended to another one. grep and jq work on both, and tail -f follows the receipts.',
  },
];

export default function Home() {
  const recorded = recordedCheckpoints();
  const findings = findingsCheckpoints();

  return (
    <>
      <Nav />
      <main id="main">
        <section className="hero">
          <div className="hero-bg" aria-hidden="true" />
          <div className="hero-glow" aria-hidden="true" />
          <div className="container hero-inner">
            <Link href="/docs/status/" className="pill">
              <span className="pill-dot" aria-hidden="true" />
              v0 · Status
              <IconArrowRight size={13} className="pill-arrow" />
            </Link>
            <h1>
              Network permissions <br className="br" />
              for tasks, and soon apps.
            </h1>
            <p className="lede">
              blackice decides which hosts a command can reach, along with every process it starts. The rules are in
              place before the command runs, and nothing inside can loosen them.
            </p>
            <p className="hero-status">
              Task scopes work today on macOS (Apple silicon) and Debian 13 (x86_64). The macOS app filter is built in its pull
              request and needs Developer ID signing to run. The Linux app filter is in review.
            </p>
            <CopyCommand command={SITE.command} />
            <div className="actions">
              <Link className="btn btn-primary" href="/docs/">
                <IconBook size={16} />
                Read the docs
              </Link>
              <a className="btn btn-secondary" href={SITE.repo}>
                <IconGitHub size={16} />
                GitHub
              </a>
            </div>
            <ul className="chips" aria-label="Targets">
              <li>
                <IconCommand size={14} />
                macOS
              </li>
              <li>
                <IconPenguin size={14} />
                Debian 13
              </li>
              <li>
                <IconTerminal size={14} />
                Headless
              </li>
              <li>
                <IconScale size={14} />
                Apache-2.0
              </li>
            </ul>
          </div>
        </section>

        <section className="container">
          <div className="frame">
            <div className="frame-bar">
              <span className="frame-title">
                <Logo size={13} />
                scope graph
              </span>
              <span className="legend" aria-hidden="true">
                <span className="legend-scope">
                  <i className="lg lg-task" />
                  task scope
                </span>
                <span className="legend-scope">
                  <i className="lg lg-app" />
                  app scope
                </span>
                <span>
                  <i className="lg lg-allow" />
                  allowed
                </span>
                <span>
                  <i className="lg lg-deny" />
                  denied
                </span>
              </span>
            </div>
            <Scene />
            <Corners />
          </div>
          <p className="caption">Illustration with simulated traffic.</p>
        </section>

        <section className="container section about" aria-labelledby="about-title">
          <div className={WALKTHROUGH.length ? 'about-grid' : undefined}>
            <div className="about-text">
              <h2 className="h2" id="about-title">
                Why I built it
              </h2>
              <p className="sub">
                I'm <a href={SITE.authorUrl}>Valen Torassa</a>, a security and backend engineer in Rosario, Argentina. Most
                days an AI agent runs commands on my machine: tests, package installs, scripts. Each of those runs with my
                user's permissions, so any of them can connect to anywhere my user can reach.
              </p>
              <p className="sub">
                I wanted that limit in a file I can review in a pull request, in place before the command starts. The
                operating system lets the command connect only to a local proxy, and the proxy applies the file. My earlier
                project,{' '}
                <a href="https://github.com/ValentinTorassa/VT-Agent-Firewall">VT-Agent-Firewall</a>, checks which tools an
                agent calls. blackice works one layer down, on the connections the commands themselves open.
              </p>
            </div>
            {WALKTHROUGH.length ? (
              <div className="about-video">
                <Walkthrough cuts={WALKTHROUGH} />
              </div>
            ) : null}
          </div>
        </section>

        <section className="container section">
          <h2 className="h2">How it works</h2>
          <p className="sub">Tasks and apps use the same model: a scope, a policy and receipts.</p>
          <Spotlight className="nouns" tilt>
            {NOUNS.map(({ name, Icon, Art, text }, i) => (
              <article className="noun spot" key={name}>
                <div className="noun-art">
                  <Art />
                </div>
                <div className="noun-body">
                  <p className="noun-num">
                    <Icon size={14} />
                    0{i + 1}
                  </p>
                  <h3>{name}</h3>
                  <p>{text}</p>
                </div>
              </article>
            ))}
          </Spotlight>
        </section>

        <section className="container section">
          <div className="head-row">
            <h2 className="h2">Design</h2>
            <span className="badge">v0</span>
          </div>
          <p className="sub">
            Each connection passes these layers in order and stops at the first one that refuses it. A hostname hides
            the address behind it, so the proxy checks both: the name against the policy, then every address it
            resolves to. The proxy writes a receipt for each of its decisions.
          </p>
          <Layers />
        </section>

        <section className="container section">
          <h2 className="h2">A shell inside a scope</h2>
          <p className="sub">
            It goes in front of a command the way nice or timeout do: a shell, a test run or fx. Everything started
            inside stays in the scope. From another terminal, the owner can read the receipts and allow more, and that
            access expires on its own.
          </p>
          <TypedTerminal lines={SESSION} title="~/project" badge="Example · the CLI may change" />
        </section>

        <section className="container section">
          <h2 className="h2">Borrowed from Unix</h2>
          <Spotlight className="grid4">
            {UNIX.map(({ name, Icon, text }) => (
              <div className="cell spot" key={name}>
                <span className="cell-icon">
                  <Icon size={18} />
                </span>
                <h3>{name}</h3>
                <p>{text}</p>
              </div>
            ))}
            <Corners />
          </Spotlight>
        </section>

        <section className="container section">
          <div className="head-row">
            <h2 className="h2">What works today</h2>
            <Link className="link" href="/docs/status/">
              Status page
              <IconArrowRight size={14} />
            </Link>
          </div>
          <p className="sub">A part is marked Tested only when a recorded run in the repository backs it.</p>
          <div className="progress">
            <p className="progress-top">
              <span className="progress-count">
                {recorded.size}
                <span>/{CHECKPOINTS.length}</span>
              </span>
              <span className="faint">checkpoints with recorded evidence</span>
            </p>
            <ol className="segments">
              {CHECKPOINTS.map(([id, name]) => {
                // Same states as /docs/status: an entry that says it is a run, not a pass, is not lit like one.
                const state = !recorded.has(id) ? 'pending' : findings.has(id) ? 'findings' : 'on';
                const label = { pending: 'no entry yet', findings: 'recorded, with findings', on: 'recorded' }[state];
                return (
                  <li key={id} className={state === 'pending' ? undefined : state} title={`${id} · ${name} · ${label}`}>
                    <span className="seg" />
                    <span className="seg-id">{id.slice(3)}</span>
                    <span className="sr-only">
                      {id} {name}: {label}
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>
          <StatusCards />
        </section>

        <section className="container section" id="install" aria-labelledby="install-title">
          <div className="head-row">
            <h2 className="h2" id="install-title">
              Install
            </h2>
            <a className="link" href={RELEASE.url}>
              v{RELEASE.version} release notes
              <IconArrowRight size={14} />
            </a>
          </div>
          <p className="sub">
            v{RELEASE.version} is the first release. It is v0 and not ready for production. Each platform's CLI is one
            file attached to the release. Verify it before running it.
          </p>
          <Install />
        </section>

        {DEMO.length ? (
          <section className="container section" id="demo" aria-labelledby="demo-title">
            <h2 className="h2" id="demo-title">
              Demo
            </h2>
            <DemoVideo sources={DEMO} title="fx demo · 1 min" />
            <p className="caption">Recorded on macOS. Each demo carries a label that says what it shows.</p>
          </section>
        ) : null}

        <section className="container section">
          <div className="cta">
            <CubeMark />
            <h2 className="h2">Try it and tell me what broke</h2>
            <p className="sub">
              The code, the design, its limits and the evidence for each checkpoint are in the repository. If something
              doesn't behave the way this page says, open an issue.
            </p>
            <div className="actions">
              <Link className="btn btn-primary" href="/docs/">
                <IconBook size={16} />
                Read the docs
              </Link>
              <a className="btn btn-secondary" href={SITE.repo}>
                <IconGitHub size={16} />
                View on GitHub
              </a>
            </div>
            <Corners />
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
