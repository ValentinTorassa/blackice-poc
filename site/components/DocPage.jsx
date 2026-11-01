import Link from 'next/link';
import { DOCS, GROUPS } from '../content/docs';
import { SITE } from '../content/site';
import { evidenceEntries, findingsCheckpoints, recordedCheckpoints } from '../lib/evidence';
import { IconArrowRight, IconGitHub } from './Icons';
import DocToc from './DocToc';

const ORDERED = GROUPS.flatMap((g) => DOCS.filter((d) => d.group === g));
const hrefOf = (d) => (d.slug ? `/docs/${d.slug}/` : '/docs/');

export default function DocPage({ slug }) {
  const i = ORDERED.findIndex((d) => d.slug === slug);
  const doc = ORDERED[i];
  const prev = ORDERED[i - 1];
  const next = ORDERED[i + 1];
  const recordedSet = recordedCheckpoints();
  const Body = doc.body;

  return (
    <div className="doc-wrap">
      <article className="doc">
        <p className="doc-crumbs">
          <Link href="/docs/">Docs</Link>
          <span aria-hidden="true">/</span>
          <span>{doc.group}</span>
        </p>
        <h1 className="doc-title">{doc.title}</h1>
        <p className="doc-desc">{doc.description}</p>
        <div className="doc-body">
          <Body
            recorded={recordedSet.size}
            recordedSet={recordedSet}
            findingsSet={findingsCheckpoints()}
            entries={evidenceEntries()}
          />
        </div>
        <a className="doc-source" href={`${SITE.repo}/blob/main/site/content/docs.jsx`}>
          <IconGitHub size={14} />
          View source
        </a>
        <nav className="pager" aria-label="Previous and next page">
          {prev ? (
            <Link href={hrefOf(prev)} className="pager-link">
              <span className="faint">Previous</span>
              <span className="pager-title">
                <IconArrowRight size={14} className="flip" />
                {prev.title}
              </span>
            </Link>
          ) : (
            <span />
          )}
          {next ? (
            <Link href={hrefOf(next)} className="pager-link pager-next">
              <span className="faint">Next</span>
              <span className="pager-title">
                {next.title}
                <IconArrowRight size={14} />
              </span>
            </Link>
          ) : null}
        </nav>
      </article>
      <aside className="doc-toc-aside">
        <DocToc key={slug || 'intro'} />
      </aside>
    </div>
  );
}

export function docMeta(slug) {
  const d = DOCS.find((x) => x.slug === slug);
  return { title: d.title, description: d.description };
}
