import CopyCommand from './CopyCommand';
import { IconArrowRight, IconPenguin } from './Icons';
import { RELEASE } from '../content/site';

// The release ships one file per platform. Download, then the two checks from the release notes, then the Linux
// step the file does not cover.
export default function Install() {
  return (
    <div className="install">
      <div className="install-row">
        <p className="install-label">
          Download <span>one file per platform</span>
        </p>
        <a className="install-download" href={RELEASE.url}>
          <span>The CLI for macOS and Linux, on the v{RELEASE.version} release page</span>
          <IconArrowRight size={14} />
        </a>
      </div>
      <div className="install-row">
        <p className="install-label">
          Integrity <span>on macOS: shasum -a 256</span>
        </p>
        <CopyCommand command={RELEASE.integrity} />
      </div>
      <div className="install-row">
        <p className="install-label">
          Provenance <span>GitHub CLI 2.49 or later</span>
        </p>
        <CopyCommand command={RELEASE.provenance} />
      </div>
      <div className="install-note">
        <IconPenguin size={16} />
        <p>
          On Debian 13 (x86_64), task scopes also need a small helper, set up from a checkout of v{RELEASE.version}. You
          verify the release, build the helper, check its hash against SHA256SUMS and run the setup script with sudo,
          again after each reboot.{' '}
          <a href={RELEASE.linuxSetup}>
            Steps in docs/linux.md
            <IconArrowRight size={13} />
          </a>
        </p>
      </div>
    </div>
  );
}
