import { GeistSans } from 'geist/font/sans';
import { GeistMono } from 'geist/font/mono';
import { SITE } from '../content/site';
import './globals.css';

export const metadata = {
  metadataBase: new URL('https://blackice-sh.vercel.app'),
  title: { default: `${SITE.name}: ${SITE.headline}`, template: `%s · ${SITE.name}` },
  description: SITE.description,
  icons: { icon: '/logo.svg' },
  openGraph: { title: `${SITE.name}: ${SITE.headline}`, description: SITE.description, images: ['/og.png'] },
  twitter: {
    card: 'summary_large_image',
    title: `${SITE.name}: ${SITE.headline}`,
    description: SITE.description,
    images: ['/og.png'],
  },
};

export const viewport = { themeColor: '#000000', colorScheme: 'dark' };

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
