// The demo videos are not in the repository or the build: they are served from a Vercel Blob store. The walkthrough
// has two English cuts with the subtitles in the picture, about 4 minutes and about 1 minute; each carries its own
// caption, since the short one has only the macOS takes. The fx demo has two cuts, one with English captions and
// one with Spanish captions. A cut shows once its URL is set, and a block once it has a cut.
const BLOB = {
  walkthrough: [
    {
      id: 'long',
      label: '4 min',
      src: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/blackice-narrated-en.mp4',
      poster: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/poster-narrated-en.jpg',
      caption: 'Recorded on macOS, on Debian 13 and in a Debian 13 virtual machine.',
    },
    {
      id: 'short',
      label: '1 min',
      src: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/blackice-minute-en.mp4',
      poster: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/poster-minute-en.jpg',
      caption: 'Recorded on macOS.',
    },
  ],
  fx: {
    en: {
      src: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/blackice-short-en.mp4',
      poster: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/poster-short-en.jpg',
    },
    es: {
      src: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/blackice-short-es.mp4',
      poster: 'https://wvrrnw987csns1in.public.blob.vercel-storage.com/blackice/poster-short-es.jpg',
    },
  },
};

export const WALKTHROUGH = BLOB.walkthrough.filter((c) => c.src);

export const DEMO = [
  { lang: 'en', label: 'English', ...BLOB.fx.en },
  { lang: 'es', label: 'Español', ...BLOB.fx.es },
].filter((s) => s.src);
