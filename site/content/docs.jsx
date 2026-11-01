import Link from 'next/link';
import { RELEASE, SITE } from './site';
import { CHECKPOINTS, INVARIANTS } from './status';
import { highlight } from './highlight';
import CopyButton from '../components/CopyButton';
import StatusCards from '../components/StatusCards';
import { IconArrowRight, IconFlag, IconInfo, IconNested, IconPolicy, IconTerminal } from '../components/Icons';

// Docs content for v0. States come from status.js and evidence/, never typed here.

function textOf(node) {
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join('');
  return node?.props ? textOf(node.props.children) : '';
}

const slugOf = (s) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');

// A section heading that links to itself. The table of contents is built from these.
function H2({ children }) {
  const id = slugOf(textOf(children));
  return (
    <h2 id={id}>
      <a className="h-anchor" href={`#${id}`}>
        {children}
        <span className="h-hash" aria-hidden="true">
          #
        </span>
      </a>
    </h2>
  );
}

function Note({ children }) {
  return (
    <div className="note">
      <IconInfo size={16} className="note-icon" />
      <div>{children}</div>
    </div>
  );
}

// For a terminal block, copy only the commands, without the prompt or comments.
function copyText(text) {
  if (typeof text !== 'string') return null;
  const cmds = text.split('\n').filter((l) => l.startsWith('$ '));
  if (!cmds.length) return text;
  return cmds.map((l) => l.slice(2).replace(/\s+#.*$/, '')).join('\n');
}

function Code({ title, label, children }) {
  const copy = copyText(children);
  const caption = title || label;
  return (
    <figure className={`code${caption ? '' : ' code-bare'}`}>
      {caption ? (
        <figcaption>
          <span className="code-title">{title}</span>
          <span className="code-meta">
            {label ? <span className="code-label">{label}</span> : null}
            {copy ? <CopyButton text={copy} /> : null}
          </span>
        </figcaption>
      ) : copy ? (
        <CopyButton text={copy} floating />
      ) : null}
      <pre>{highlight(children)}</pre>
    </figure>
  );
}

const SCOPE = 's-7f3a91c2';

const POLICY_EXAMPLE = `{
  "version": "blackice.policy/v0",
  "network": {
    "mode": "allowlist",
    "allow": ["registry.npmjs.org", "*.github.com"],
    "subnets": { "allow": [], "deny": ["203.0.113.0/24"] },
    "ports": [443]
  }
}`;

const RECEIPT_EXAMPLE = `{"ts":"2026-10-30T14:36:01.279Z","scope":"s-1b1f4870","policy":"353b7e8328f9","gen":1,"point":"proxy","event":"connect","verdict":"allow","reason":"allowed_by_rule","rule":"example.com","host":"example.com","ip":"104.20.23.154","port":443,"detail":"sni_match"}
{"ts":"2026-10-30T14:36:01.427Z","scope":"s-f79c31a5","policy":"353b7e8328f9","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"github.com","port":443}`;

// v0 checkpoint states, from evidence/ (lib/evidence.js).
const CHECKPOINT_LABEL = { recorded: 'Recorded', findings: 'Recorded, with findings', pending: 'No entry yet' };

function checkpointState(id, recordedSet, findingsSet) {
  if (!recordedSet.has(id)) return 'pending';
  return findingsSet && findingsSet.has(id) ? 'findings' : 'recorded';
}

const RECEIPT_FIELDS = [
  ['ts', 'When the line was written, in UTC. For a kernel refusal, that can be after the refusal itself.'],
  ['scope', 'The scope ID.'],
  ['policy, gen', 'A short hash of the policy and its generation.'],
  ['point', 'Where it was enforced: proxy, kernel, relay, control or app_filter.'],
  ['event', 'scope_start, backend_armed, connect, http, grant, revoke, relay_call, kernel_drop, warning or scope_end.'],
  ['verdict, reason', 'allow or deny, and a stable reason code.'],
  ['rule', 'The policy entry that decided, as written in the file.'],
  ['host, ip, port, detail', 'The destination, and anything else worth keeping.'],
];

// policy.Reason: the codes the policy decides with.
const POLICY_ALLOW = ['allowed_by_rule', 'allowed_by_mode', 'allowed_subnet', 'allowed_port', 'public_address'];
const POLICY_DENY = [
  'no_matching_rule',
  'mode_deny_all',
  'ip_literal_needs_subnet',
  'denied_subnet',
  'local_or_private_address',
  'transition_address',
  'port_not_allowed',
  'invalid_host',
];

// The proxy's own codes, for grants and for connections it cannot complete.
const PROXY_CODES = [
  ['granted', 'Allowed by an active grant. rule names the grant.'],
  ['bad_request', 'The request could not be parsed (400).'],
  ['resolve_failed', 'An allowed name did not resolve (502).'],
  ['upstream_unreachable', 'No checked address accepted the connection (502).'],
  ['sni_mismatch', 'The TLS server name differs from the CONNECT host. The tunnel is closed.'],
  ['sni_missing', 'A TLS handshake for a name carried no server name. The tunnel is closed.'],
  ['tls_unparsed', 'The TLS handshake could not be parsed. The tunnel is closed.'],
  ['not_tls', 'The first bytes through CONNECT were not TLS. The tunnel is closed.'],
  ['grant_expired', 'A connection opened under a grant was closed when the grant expired.'],
  ['grant_revoked', 'A connection opened under a grant was closed when the owner revoked it.'],
  ['grant_watchdog_failed', 'The task that ends a grant could not start (503).'],
];

const NEXT = [
  ['/docs/scopes/', 'Scopes', 'Where a policy applies.', IconNested],
  ['/docs/policies/', 'Policies', 'What may connect, and how names and addresses are checked.', IconPolicy],
  ['/docs/fx/', 'fx integration', 'A scope for every command fx runs, or one around the whole agent.', IconTerminal],
  ['/docs/limits/', 'Limits', 'What it does not do.', IconFlag],
];

function Codes({ label, codes, tone }) {
  return (
    <div className="codes-group">
      <p className="codes-label">{label}</p>
      <p className="chip-list">
        {codes.map((c) => (
          <code key={c} className={`chip chip-${tone}`}>
            {c}
          </code>
        ))}
      </p>
    </div>
  );
}

export const DOCS = [
  {
    slug: '',
    group: 'Overview',
    title: 'Introduction',
    description: `${SITE.name} gives each task its own network permissions, decided by a policy file; apps are next. v0: task scopes work on macOS (experimental) and Debian 13 (x86_64).`,
    body: ({ recorded }) => (
      <>
        <Note>
          <strong>v0, not production-ready.</strong> {recorded} of {CHECKPOINTS.length} checkpoints have recorded
          evidence; see <Link href="/docs/status/">Status</Link>.
        </Note>
        <p>
          {SITE.name} gives each task its own network permissions, decided by a policy file, and apps are next. Task
          scopes run natively on macOS (experimental) and Debian 13 (x86_64), headless, with no per-connection
          prompts.
        </p>
        <p>
          Today it works for tasks. A coding agent runs commands on your machine: tests, installs, scripts. Each of
          those commands can connect anywhere your user can. {SITE.name} puts a network policy around a task before it
          starts. Every process the task spawns inherits that policy, and no process inside the task can grant itself
          more access.
        </p>
        <p>
          The same policy format will cover apps that are already on the machine, and a host ceiling will sit over
          everything. Nested scopes will only be able to narrow it.
        </p>
        <H2>Example</H2>
        <Code title="terminal" label="Illustrative">{`$ ${SITE.name} run --policy policy.json -- npm ci
# from outside the scope, as the owner:
$ ${SITE.name} grant ${SCOPE} api.example.com --for 10m
$ tail -f ~/.local/state/${SITE.name}/scopes/${SCOPE}/receipts.jsonl`}</Code>
        <H2>Next</H2>
        <div className="next-cards">
          {NEXT.map(([href, title, text, Icon]) => (
            <Link key={href} href={href} className="next-card">
              <span className="next-icon">
                <Icon size={16} />
              </span>
              <span className="next-title">
                {title}
                <IconArrowRight size={14} />
              </span>
              <span className="next-text">{text}</span>
            </Link>
          ))}
        </div>
      </>
    ),
  },
  {
    slug: 'install',
    group: 'Overview',
    title: 'Install',
    description: `Download the ${SITE.name} CLI from the v0.1.0 release and verify it. On Debian 13, task scopes also need a helper, set up separately with sudo.`,
    // Same wording as the Install and Verify sections of the v0.1.0 release notes.
    body: () => (
      <>
        <Note>
          <strong>v{RELEASE.version}</strong> is the first release. It is v0 and not ready for production.
        </Note>
        <H2>Download</H2>
        <p>
          Each platform's CLI is one file attached to the <a href={RELEASE.url}>v{RELEASE.version} release</a>. Verify
          it as described below before running it. npm and Homebrew packages are not published yet.
        </p>
        <H2>Verify</H2>
        <p>
          Two builders (Linux and macOS runners) produced byte-identical files: Zig 0.17.0, ReleaseSafe, stripped, macOS
          minimum 13.0. Before running a file:
        </p>
        <ol>
          <li>
            Integrity. On macOS, use <code>{RELEASE.integrityMac}</code>.
            <Code title="terminal">{`$ ${RELEASE.integrity}`}</Code>
          </li>
          <li>
            Provenance, with GitHub CLI 2.49 or later.
            <Code title="terminal">{`$ ${RELEASE.provenance}`}</Code>
          </li>
          <li>
            Independence: check out v{RELEASE.version}, install Zig 0.17.0, run{' '}
            <code>zig build release -Dmacos-min=13.0</code>, and compare the hashes.
          </li>
        </ol>
        <H2>Linux helper</H2>
        <p>
          On Debian 13 x86_64, task scopes also need the helper, set up from a checkout of v{RELEASE.version}. You verify
          the release, build the helper, check its hash against <code>SHA256SUMS</code> and run the setup script with
          sudo, again after each reboot. The steps are in <a href={RELEASE.linuxSetup}>docs/linux.md</a>.
        </p>
        <p>
          The helper keeps four file capabilities (<code>CAP_CHOWN</code>, <code>CAP_DAC_OVERRIDE</code>,{' '}
          <code>CAP_NET_ADMIN</code> and <code>CAP_BPF</code>). Only root and the primary group of the user named at setup
          can run it, and <code>sudo ./scripts/linux-teardown.sh</code> removes it.
        </p>
        <H2>Other platforms</H2>
        <p>
          Intel Macs and Linux arm64 get a CLI build, but task scopes have not been shown on them. Linux arm64 has no
          helper yet, so scopes do not run there. Other Linux distributions are untested. On Ubuntu 24.04 and later,
          where <code>kernel.apparmor_restrict_unprivileged_userns=1</code> is the default, scopes are expected to fail
          closed.
        </p>
      </>
    ),
  },
  {
    slug: 'status',
    group: 'Overview',
    title: 'Status',
    description: 'What works today and what is still in progress.',
    body: ({ recordedSet, findingsSet, entries }) => (
      <>
        <p>
          States are computed when this site is built. <strong>Tested</strong> needs a recorded run in{' '}
          <code>evidence/</code>; <strong>Built</strong> means the code is in the repository.
        </p>
        <StatusCards />
        <H2>v0 checkpoints</H2>
        <ol className="checklist">
          {CHECKPOINTS.map(([id, name]) => (
            <li key={id}>
              <span className="mono faint">{id}</span>
              <span>
                {name}
                {entries.has(id) && (
                  <span className="entries">
                    {entries.get(id).map((e) => (
                      <a key={e.file} href={`${SITE.repo}/blob/main/evidence/${e.file}`}>
                        {e.label}
                      </a>
                    ))}
                  </span>
                )}
              </span>
              <span className={`state state-${checkpointState(id, recordedSet, findingsSet)}`}>
                <span className="state-dot" aria-hidden="true" />
                {CHECKPOINT_LABEL[checkpointState(id, recordedSet, findingsSet)]}
              </span>
            </li>
          ))}
        </ol>
        <p className="checklist-legend">
          <strong>Recorded</strong>: <code>evidence/</code> has an entry for the checkpoint.{' '}
          <strong>Recorded, with findings</strong>: the entry says it is a run, not a pass, and lists what it found.
        </p>
        <H2>Release gap</H2>
        <p>Before a first usable release, beyond v0:</p>
        <ul>
          <li>App control on macOS: the Network Extension filter, signed with a Developer ID.</li>
          <li>App control on Linux: a first build is in review, not cleared.</li>
          <li>Owner authentication for grants, beyond &quot;same user, outside every scope&quot;.</li>
          <li>Protocols other than HTTP and TLS through the proxy.</li>
          <li>Listening inside a scope, for dev servers and tests that open a port.</li>
          <li>Recorded evidence for every cell above.</li>
        </ul>
        <H2>Design invariants</H2>
        <p>Every backend has to keep these.</p>
        <ol className="invariants">
          {INVARIANTS.map((text, i) => (
            <li key={text}>
              <span className="mono faint">{i + 1}</span>
              <span>{text}</span>
            </li>
          ))}
        </ol>
      </>
    ),
  },
  {
    slug: 'scopes',
    group: 'Concepts',
    title: 'Scopes',
    description: 'A scope is where a policy applies: a task, an app, or the whole host.',
    body: () => (
      <>
        <H2>Task scope</H2>
        <p>
          A command and every process it starts. {SITE.name} creates the scope and arms its policy before the command
          executes, so the first connection the command makes is already inside it. Children inherit the scope through
          fork and exec.
        </p>
        <p>
          Each scope has an ID, such as <code>{SCOPE}</code>, and a state directory under{' '}
          <code>~/.local/state/{SITE.name}/scopes/</code>. Only the {SITE.name} process writes there; inside a scope it
          is read-only.
        </p>
        <H2>App scope</H2>
        <p>
          An app that is already on the machine. On macOS, a Network Extension filter will identify apps by their
          code-signing identity, not their process name, and apply the same policy format and receipts. App scopes will
          not need {SITE.name} to launch the app. On Linux, a first build is in review, not cleared.
        </p>
        <H2>Host ceiling</H2>
        <p>One policy, administered by the owner, over the whole machine. Every other scope will sit under it.</p>
        <H2>Nesting</H2>
        <p>
          Scopes will nest, and a nested scope will only be able to narrow. The effective permission is the
          intersection of every ceiling that applies, so a narrower scope can never erase a mandatory deny.
        </p>
      </>
    ),
  },
  {
    slug: 'policies',
    group: 'Concepts',
    title: 'Policies',
    description: 'A strict JSON file: a mode, allowed names, subnets and ports.',
    body: () => (
      <>
        <Code title="policy.json" label="Policy v0 · example">
          {POLICY_EXAMPLE}
        </Code>
        <H2>Modes</H2>
        <p>
          <code className="nb">deny-all</code> refuses every destination. <code className="nb">allow-all</code> allows
          public addresses. <code className="nb">allowlist</code> allows only the names and subnets the file lists.
        </p>
        <H2>Names</H2>
        <p>
          <code>allow</code> takes exact names and names with one leading wildcard. <code>example.com</code> matches
          only example.com; <code>*.example.com</code> matches any name below it, but not example.com itself. Names are
          compared in lowercase, without a trailing dot. Forms such as <code>a.*.com</code> or a bare <code>*</code>{' '}
          are refused.
        </p>
        <H2>Addresses and DNS</H2>
        <p>
          A command inside a scope does not reach the network directly. It reaches only a local proxy outside the
          scope, which matches the host name against the policy and resolves allowed names itself.
        </p>
        <p>
          Every resolved address is checked again. Denied subnets always lose and allowed subnets win. Loopback,
          private, link-local, CGNAT and multicast addresses are refused unless an allowed subnet covers them, so an
          allowed name that resolves to 127.0.0.1 cannot reach local services. A destination written as an IP address
          is allowed only by an allowed subnet.
        </p>
        <H2>Ports</H2>
        <p>
          <code>ports</code> lists the destination ports a scope may reach. Without it, 80 and 443 are allowed. The port
          is checked first, before any name or DNS work, and a grant never lifts a port refusal.
        </p>
        <H2>A strict file</H2>
        <p>
          Unknown fields are rejected, so a typo cannot widen a policy. If a backend cannot enforce something a policy
          requires, activation fails. Nothing is silently downgraded.
        </p>
        <H2>Generations</H2>
        <p>
          The policy is loaded once, when the scope starts, and never read again from disk. Receipts name it by a short
          hash and a generation number. A policy change will commit as a new generation, all at once; if it fails, the
          previous generation will stay in force. In v0 the generation stays at 1: a grant does not change it.
        </p>
        <H2>Vercel Sandbox</H2>
        <p>
          An experimental importer reads a tested subset of the{' '}
          <a href="https://vercel.com/docs/sandbox/concepts/firewall">Vercel Sandbox network policy</a> and refuses what
          v0 cannot express, such as <code>www.*.com</code> or a bare <code>*</code>. Input outside that subset is
          rejected, not ignored. It produces a candidate policy for review. It is not part of the CLI yet, and it is not
          verified.
        </p>
      </>
    ),
  },
  {
    slug: 'grants',
    group: 'Concepts',
    title: 'Grants',
    description: 'Temporary access, given by the owner from outside the scope, that ends on its own.',
    body: () => (
      <>
        <Code title="terminal · outside the scope" label="Illustrative">{`$ ${SITE.name} grant ${SCOPE} api.example.com --for 10m
granted until 12:10:03`}</Code>
        <Code title="terminal · inside the scope" label="Illustrative">{`$ ${SITE.name} grant ${SCOPE} api.example.com --for 10m
error: the control socket is not reachable from inside a scope`}</Code>
        <H2>Who can grant</H2>
        <p>
          Grants travel over a control socket that the scope cannot reach. On macOS a sandbox rule keeps it out of
          reach; on Linux the command cannot create a filesystem or abstract Unix socket, so it cannot connect to it. A
          process inside a task cannot widen its own scope or anyone else&apos;s. In v0, any process of the same user
          outside every scope counts as the owner.
        </p>
        <H2>When access ends</H2>
        <p>
          At the earliest bound: the grant&apos;s timeout, the end of the task, or a revocation with{' '}
          <code>{SITE.name} revoke</code>. Both are enforced locally, by the proxy: when a grant ends or is revoked, the
          proxy resets the connections opened under it and refuses new ones.
        </p>
      </>
    ),
  },
  {
    slug: 'receipts',
    group: 'Concepts',
    title: 'Receipts',
    description: 'Flat JSON lines with a stable reason code.',
    body: () => (
      <>
        <Code title="receipts.jsonl" label="From a run on Linux">
          {RECEIPT_EXAMPLE}
        </Code>
        <p>
          Each receipt is one line of flat JSON. Fields without a value are left out, so <code>tail</code>,{' '}
          <code>grep</code> and <code>jq</code> work on them directly.
        </p>
        <div className="table-wrap" tabIndex={0} aria-label="Receipt fields, scrollable">
          <table>
            <thead>
              <tr>
                <th scope="col">Field</th>
                <th scope="col">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {RECEIPT_FIELDS.map(([field, meaning]) => (
                <tr key={field}>
                  <th scope="row">
                    <code>{field}</code>
                  </th>
                  <td>{meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <H2>Reason codes</H2>
        <p>
          Reason codes are part of the receipt contract: once v0 is frozen, they change only with a contract change.
          The policy decides with these.
        </p>
        <div className="codes">
          <Codes label="Allow" codes={POLICY_ALLOW} tone="allow" />
          <Codes label="Deny" codes={POLICY_DENY} tone="deny" />
        </div>
        <p>The proxy adds its own, for grants and for connections it cannot complete.</p>
        <div className="table-wrap" tabIndex={0} aria-label="Proxy reason codes, scrollable">
          <table>
            <thead>
              <tr>
                <th scope="col">Code</th>
                <th scope="col">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {PROXY_CODES.map(([code, meaning]) => (
                <tr key={code}>
                  <th scope="row">
                    <code className={code === 'granted' ? 'chip chip-allow' : 'chip chip-neutral'}>{code}</code>
                  </th>
                  <td>{meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>The relay and the control socket list their own codes in the source.</p>
        <H2>Where they live</H2>
        <p>
          In <code>~/.local/state/{SITE.name}/scopes/&lt;id&gt;/receipts.jsonl</code>. Each scope has a single writer,
          the {SITE.name} process. Backends report to it, so lines never interleave.
        </p>
        <H2>Gaps</H2>
        <p>
          Lines that could not be written are counted and reported in the scope&apos;s last receipt,{' '}
          <code>scope_end</code>, so a gap in the log is visible. If {SITE.name} itself exits before the scope
          ends, there is no <code>scope_end</code> and the count is not reported.
        </p>
        <p>
          On Linux, kernel refusals that overflow the scope&apos;s ring buffer are counted too, and the total is
          reported when the scope ends. On macOS some refusals leave no receipt, and those are not counted; see{' '}
          <Link href="/docs/limits/">Limits</Link>. A logging failure never widens access.
        </p>
        <H2>Privacy</H2>
        <p>Receipts stay on the machine. There is no account and no telemetry.</p>
      </>
    ),
  },
  {
    slug: 'cli',
    group: 'Reference',
    title: 'CLI',
    description: 'The commands in v0. The contract is not frozen yet.',
    body: () => (
      <>
        <H2>
          <code>{SITE.name} run</code>
        </H2>
        <Code>{`${SITE.name} run --policy <file> [--policy-sha256 <hex>] [--protect <path>]... [--env <name>]...
             [--relay --model <id>... [--upstream <url>] [--max-requests <n>]] -- <command> [args...]`}</Code>
        <p>
          Creates a task scope, starts its proxy and the owner&apos;s control socket outside the scope, and only then
          launches the command, already confined. Receipts go to the scope&apos;s state directory. {SITE.name} never
          starts the command without a backend that enforces the policy. On Linux, a scope whose helper is killed
          while it runs is the exception; see <Link href="/docs/limits/">Limits</Link>.
        </p>
        <p>
          The command gets a clean environment: a short list of variables such as <code>PATH</code> and{' '}
          <code>HOME</code>, the ones named with <code>--env</code>, <code>BLACKICE_SCOPE</code>, and{' '}
          <code>HTTP_PROXY</code>, <code>HTTPS_PROXY</code> and <code>ALL_PROXY</code> pointing at the proxy. Nothing
          else from the caller&apos;s environment passes.
        </p>
        <ul>
          <li>
            <code>--policy-sha256</code> pins the policy. If the file does not hash to that value, nothing runs.
          </li>
          <li>
            <code>--protect</code> names a file, by absolute path, that the command cannot change, just as it cannot
            change {SITE.name} itself or the policy.
          </li>
          <li>
            <code>--relay</code> also starts the model relay, for the models named with <code>--model</code>. It reads
            the provider key from stdin; the command gets only{' '}
            <code>BLACKICE_RELAY_URL</code> and a per-scope <code>BLACKICE_RELAY_TOKEN</code>.
          </li>
        </ul>
        <p>
          Exit status: the command&apos;s own, 125 when the scope could not be set up, and 127 when the command could
          not start. Linux does not match this yet: a failed helper setup exits 127, and so does a command whose
          helper was killed while it ran.
        </p>
        <H2>
          <code>{SITE.name} grant</code> and <code>revoke</code>
        </H2>
        <Code>{`${SITE.name} grant <scope> <host> [--for <duration>]
${SITE.name} revoke <scope> <host>`}</Code>
        <p>
          A grant gives a running scope access to one more host for a while: a duration such as 90s, 10m or 1h, 10
          minutes by default and 1 hour at most. It never lifts the port, address or local-network checks.{' '}
          <code>revoke</code> ends it early. Owner only, over a control socket the scope cannot reach.
        </p>
        <H2>
          <code>{SITE.name} policy check</code>
        </H2>
        <Code>{`${SITE.name} policy check <file>`}</Code>
        <p>
          Reads a policy the way <code>run</code> does, and prints its mode, counts, ports and short hash, or the first
          error.
        </p>
        <Note>Until the CLI is frozen, flags and output may change. App-scope commands will come with app scopes.</Note>
      </>
    ),
  },
  {
    slug: 'platforms',
    group: 'Reference',
    title: 'Platforms',
    description: 'How each operating system enforces a scope, and what is tested.',
    body: () => (
      <>
        <StatusCards />
        <H2>macOS</H2>
        <p>
          <strong>Tasks.</strong> Experimental. The command runs under the built-in sandbox (Seatbelt, started through{' '}
          <code>sandbox-exec</code>). The profile denies outbound
          connections except to the scope&apos;s local proxy and relay, and denies writes to {SITE.name}&apos;s state
          directory. The sandbox cannot filter by host name, so names go through the proxy.
        </p>
        <p>
          <strong>Apps.</strong> A Network Extension filter, written in Swift, will decide per app, by code-signing
          identity, and per destination, with the same policy format and receipts. It needs Apple&apos;s networking
          entitlement and a Developer ID signature to run, so until then its state can be at most{' '}
          <em>Built, unsigned</em>. Session mode never counts as app control.
        </p>
        <H2>Linux</H2>
        <p>
          <strong>Tasks.</strong> Each task gets a root-owned cgroup v2 before it executes. eBPF programs on that
          cgroup admit only TCP connections to the scope&apos;s local proxy; UDP and IPv6 have no allow path. Refusals
          go to a per-scope ring buffer and become receipts. Ring-buffer loss is counted and never allows traffic.
        </p>
        <p>
          A small helper with file capabilities, never {SITE.name} itself, starts the command, holds it until the
          programs are attached, and only then lets it run. A private mount namespace hides resolver and daemon
          sockets and makes the state directory read-only. Seccomp and Landlock refuse raw sockets, filesystem and
          abstract Unix sockets, new namespaces and io_uring. Host nftables rules are not changed. The owner installs the helper with a short
          setup script run with sudo, once per boot. See{' '}
          <a href="https://github.com/ValentinTorassa/blackice/blob/main/docs/linux.md">docs/linux.md</a>.
        </p>
        <p>
          <strong>Apps.</strong> In review, not cleared: a first build and the fixes from its security review. Kernel
          tests in a virtual machine and a security clearance come before any install. The hard part is telling apps
          apart without trusting process names or racing PIDs.
        </p>
      </>
    ),
  },
  {
    slug: 'fx',
    group: 'Reference',
    title: 'fx integration',
    description: 'A scope for every command fx runs, or one scope around the whole agent.',
    body: () => (
      <>
        <Note>The per-command mode is recorded on macOS with a scripted test model (P0-07).</Note>
        <H2>A scope per command</H2>
        <Code title="fx with the blackice hook patch" label="Illustrative">{`# fx's shell tool asks to run:
npm ci
# the hook runs it as:
${SITE.name} run --policy policy.json -- npm ci`}</Code>
        <p>
          A small patch, not part of fx upstream, adds a built-in PreToolUse handler to{' '}
          <a href="https://github.com/vercel-labs/fx">fx</a>. For the shell tool, it rewrites each call to run through{' '}
          <code>{SITE.name} run</code>, so every shell command fx launches gets its own scope and its own receipts.
          fx&apos;s <code>write_file</code> outside the workspace and its <code>web_fetch</code> are blocked. Each scope
          starts with a clean environment: in P0-07, a test variable set in fx&apos;s environment did not reach the
          command.
        </p>
        <p>
          The patch lives in this repository under <code>integrations/fx/</code>, for fx 0.0.16. fx is Apache-2.0.
        </p>
        <H2>One scope around fx</H2>
        <Code title="terminal" label="Illustrative">{`$ ${SITE.name} run --policy policy.json -- fx`}</Code>
        <p>
          fx and everything it starts in one task scope, with no changes to fx. This mode is not finished yet. In it,
          fx will reach its model through the relay that <code>{SITE.name} run --relay</code> starts outside the
          scope, so the model key never enters it. The relay is built and has no evidence entry yet.
        </p>
        <p>What the relay does not do:</p>
        <ul>
          <li>
            A tool inside the scope can still send any content to the allowed model endpoint through the relay. The
            relay keeps the key out of the scope, nothing more.
          </li>
          <li>
            In this first version the key is protected from the scope, not from other processes of the same user that
            run outside every scope.
          </li>
        </ul>
        <H2>Why use it with fx</H2>
        <p>
          In its default <code>auto</code> mode, fx runs recognized project commands such as tests, builds and local
          installs directly, and sends unfamiliar commands to a reviewer model (
          <a href="https://fx.sh/docs/configure-fx/permissions">fx permissions</a>). Since 0.0.5, approved commands run
          as ordinary host subprocesses (
          <a href="https://github.com/vercel-labs/fx/blob/main/CHANGELOG.md">changelog</a>). A network policy limits
          where any of those commands can connect, whatever approved them.
        </p>
        <H2>Limits</H2>
        <ul>
          <li>
            In the per-command mode, fx starts no MCP servers, and its own network and MCP tools are blocked, not
            scoped.
          </li>
          <li>
            In the per-command mode, fx itself, its own file reads, its writes inside the workspace and its own
            connections, model traffic included, are outside every scope. What fx reads goes to the model&apos;s
            provider.
          </li>
        </ul>
      </>
    ),
  },
  {
    slug: 'limits',
    group: 'Project',
    title: 'Limits',
    description: `What ${SITE.name} does not do.`,
    body: () => (
      <>
        <ul className="limits">
          <li>
            <strong>Network only.</strong> Files, processes and credentials need their own controls.
          </li>
          <li>
            <strong>HTTP and TLS only, in v0.</strong> Allowed destinations are reached through the local proxy, so
            only HTTP and TLS over CONNECT can be allowed. Other protocols are refused.
          </li>
          <li>
            <strong>Clients only, in v0.</strong> Nothing inside a task scope can listen for connections, not even on
            loopback, on macOS or Linux. Dev servers and tests that open a port cannot run inside a scope, and a scoped
            command reaches no loopback port except its own proxy and relay.
          </li>
          <li>
            <strong>Same-user owner, in v0.</strong> Processes of the same user outside every scope count as the
            owner, and can reach the model relay&apos;s port.
          </li>
          <li>
            <strong>Not a prompt-injection detector.</strong> It blocks connections the policy does not allow. Data
            sent to an allowed destination is out of scope.
          </li>
          <li>
            <strong>Outside daemons.</strong> Work handed to a service outside the task (launchd, <code>open</code>,{' '}
            <code className="nb">systemd-run --user</code>, Docker, a tmux server) is refused only where a test shows
            it.
          </li>
          <li>
            <strong>Shared CDNs.</strong> An allowed name on a shared CDN can reach other sites on that CDN through
            domain fronting inside TLS: the proxy checks the TLS server name, not the encrypted request.
          </li>
          <li>
            <strong>Local receipts.</strong> Receipts are a local record for diagnosis. Other programs of the same
            user, and administrators, can change them.
          </li>
          <li>
            <strong>Inherited sockets.</strong> Sockets and file descriptors opened before the task, or passed in from
            outside, are not covered by its policy.
          </li>
          <li>
            <strong>Same-user isolation.</strong> A network policy does not isolate a hostile process from files or
            other IPC owned by the same user.
          </li>
          <li>
            <strong>macOS task scopes.</strong> They rely on <code>sandbox-exec</code>, which Apple marks as
            deprecated, so they stay experimental. App control on macOS needs a signed Network Extension.
          </li>
          <li>
            <strong>macOS receipts.</strong> A kernel refusal gets a receipt only when macOS logs it, and it logs
            refusals of programs signed by Apple. An ad-hoc-signed program, such as one you built yourself, is refused
            the same way but leaves no receipt. Programs signed with a Developer ID were not tested. Under a burst some
            receipts are lost, and a process that outlives the command gets none.
          </li>
          <li>
            <strong>Linux.</strong> Ping, SCTP and raw sockets are refused when they are created, so they leave no
            receipt. Only x86_64 was run.
          </li>
          <li>
            <strong>Linux helper killed.</strong> If the helper is killed while a scope runs, processes that detached
            from the command keep running with access only to the dead proxy&apos;s local port, which another local
            program can later listen on; removing them needs root, and the receipts wrongly say the command did not
            start.
          </li>
          <li>
            <strong>Failure behavior.</strong> What happens when a broker, proxy or extension fails is stated per fault
            and backend. There is no blanket fail-closed claim.
          </li>
        </ul>
      </>
    ),
  },
];

export const GROUPS = ['Overview', 'Concepts', 'Reference', 'Project'];
