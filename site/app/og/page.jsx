import { Logo, LogoFull, Wordmark } from '../../components/Icons';
import { SITE } from '../../content/site';

// Rendered at 1280x640 and captured as public/og.png.
export const metadata = { title: 'Social card', robots: { index: false } };

export default function OgCard() {
  return (
    <div className="og">
      <div className="og-left">
        <div className="og-top">
          <Logo size={40} />
          <Wordmark />
        </div>
        <h1 className="og-title">{SITE.headline}</h1>
        <code className="og-cmd">$ {SITE.command}</code>
      </div>
      <div className="og-art">
        <LogoFull size={380} line={1.5} guides />
      </div>
      <style>{`
        .og { position: relative; width: 1280px; height: 640px; overflow: hidden; display: grid; grid-template-columns: minmax(0, 1fr) 420px;
          align-items: center; gap: 24px; padding: 76px 72px 76px 84px; background: #000; }
        .og::before { content: ''; position: absolute; inset: 0;
          background-image: linear-gradient(#161616 1px, transparent 1px), linear-gradient(90deg, #161616 1px, transparent 1px); background-size: 64px 64px;
          -webkit-mask-image: radial-gradient(55% 75% at 78% 50%, #000, transparent 78%); mask-image: radial-gradient(55% 75% at 78% 50%, #000, transparent 78%); }
        .og::after { content: ''; position: absolute; right: 40px; top: 50%; width: 600px; height: 600px; transform: translateY(-50%);
          background: radial-gradient(closest-side, rgba(255, 255, 255, 0.1), transparent); }
        .og > * { position: relative; z-index: 1; }
        .og-left { display: flex; flex-direction: column; height: 100%; }
        .og-top { display: flex; align-items: center; gap: 16px; font-size: 38px; color: #ededed; }
        .og-title { margin: auto 0 0; font-size: 60px; line-height: 1; letter-spacing: -0.055em; font-weight: 600;
          background: linear-gradient(180deg, #fff 40%, rgba(255, 255, 255, 0.6)); -webkit-background-clip: text; background-clip: text; color: transparent; padding-bottom: 0.06em; }
        .og-cmd { margin-top: 40px; align-self: flex-start; font-family: var(--mono); font-size: 21px; color: #a1a1a1; padding: 14px 20px;
          border: 1px solid #262626; border-radius: 10px; background: #0a0a0a; }
        .og-art { display: grid; place-items: center; color: #ededed; }
      `}</style>
    </div>
  );
}
