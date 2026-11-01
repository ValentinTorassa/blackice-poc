export const SITE = {
  name: 'blackice',
  headline: 'Network permissions for tasks, and soon apps.',
  description:
    'Network permissions for tasks, and soon apps. blackice decides which hosts a command, and every process it starts, can reach. Native and headless. v0: task scopes work on macOS and Debian 13 (x86_64).',
  repo: 'https://github.com/ValentinTorassa/blackice',
  author: 'Valen Torassa',
  authorUrl: 'https://valentorassa.com',
  command: 'blackice run --policy policy.json -- npm ci',
};

// The current release. The Install section on the landing page and the Install docs page read it.
// It ships as one file per platform on the release page. A package manager gets a line here only once its package
// is published and checked.
const VERSION = '0.1.0';

export const RELEASE = {
  version: VERSION,
  url: `${SITE.repo}/releases/tag/v${VERSION}`,
  integrity: 'sha256sum -c SHA256SUMS --ignore-missing',
  integrityMac: 'shasum -a 256 -c SHA256SUMS --ignore-missing',
  provenance:
    'gh attestation verify <file> --repo ValentinTorassa/blackice --signer-workflow ValentinTorassa/blackice/.github/workflows/release.yml',
  linuxSetup: `${SITE.repo}/blob/v${VERSION}/docs/linux.md#build-and-install`,
};
