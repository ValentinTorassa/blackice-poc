// Project status shown on the site. Cell states are computed when the site builds (lib/evidence.js):
// "verified" (shown as Tested) needs a recorded run in evidence/, "built" needs the code in the repository.

export const MATRIX = [
  {
    os: 'macOS',
    apps: {
      base: 'pending',
      code: 'macos',
      builtAs: 'unsigned',
      how: 'A Network Extension filter that decides per app, by code signature, and per destination, with the same policies and receipts. It can\'t run until it is signed with an Apple Developer ID.',
    },
    tasks: {
      base: 'designed',
      code: 'src/macos',
      evidence: /^P0-02-.*macos/i,
      how: 'Experimental. The built-in macOS sandbox lets the command reach only a local proxy, which applies the policy.',
    },
  },
  {
    os: 'Linux',
    apps: {
      base: 'pending',
      how: 'Per-app control across the whole machine, which needs a reliable way to tell which app opened each connection. A first build is in review, not cleared, and runs only in a virtual machine so far.',
    },
    tasks: {
      base: 'designed',
      // main holds a placeholder backend.zig (available = false) until the real Linux backend lands.
      code: 'src/linux/backend.zig',
      builtWhen: /^pub const available = true;/m,
      evidence: /^P0-02-.*linux/i,
      how: 'A cgroup v2 per task, with eBPF programs that let the command reach only a local proxy, which applies the policy.',
      note: 'Tested on Debian 13 (kernel 6.12). On Ubuntu 24.04 and later, where kernel.apparmor_restrict_unprivileged_userns=1 is the default, scopes are expected to fail closed (not tested on Ubuntu).',
    },
  },
];

export const CHECKPOINTS = [
  ['P0-01', 'Policy before execution'],
  ['P0-02', 'Real deny'],
  ['P0-03', 'Small explicit allow'],
  ['P0-04', 'Authorized change'],
  ['P0-05', 'Bounded session grant'],
  ['P0-06', 'Fault and recovery'],
  ['P0-07', 'Useful fx contract'],
  ['P0-08', 'Second-platform evidence'],
  ['P0-09', 'Forwardable proof'],
  ['P0-10', 'Release gap visible'],
];

export const INVARIANTS = [
  'A strict command starts only after its exact policy generation and required capabilities are armed.',
  'Widening needs an independent, authorized owner. Untrusted code cannot approve its own escape.',
  'Effective permission is the intersection of every ceiling that applies. A narrower scope cannot erase a mandatory deny.',
  'No model or remote service takes part in an enforcement verdict.',
  'If a policy needs semantics a backend cannot enforce, activation fails. Missing identity never satisfies an allow.',
  'A domain rule names its evidence, destination binding, protocol and limits. DNS is part of the boundary.',
  'An update commits as one acknowledged generation. Errors never leave a partial policy.',
  'Temporary access ends locally at its earliest bound. What a revocation covers is explicit.',
  'Gaps in observability are counted. A logging failure never widens access.',
  'Protection and recovery are stated per fault, OS, backend and scope.',
  'The first usable release needs app and task control on both macOS and Linux, each claim backed by evidence.',
  'The local product works without an account or telemetry. Dependencies and exports are explicit.',
];

export const STATE_LABEL = {
  pending: 'Pending',
  designed: 'Designed',
  built: 'Built, not tested',
  unsigned: 'Built, unsigned',
  verified: 'Tested',
};
