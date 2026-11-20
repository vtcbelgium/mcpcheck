import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const read = (relativePath: string) => readFileSync(resolve(__dirname, '..', relativePath), 'utf-8');

describe('Live vitals assets', () => {
  describe('public/_headers', () => {
    const headers = read('public/_headers');

    it('sets HSTS, nosniff, and X-Frame-Options', () => {
      expect(headers).toMatch(/^\/*\s*$/m);
      expect(headers).toContain('Strict-Transport-Security: max-age=31536000; includeSubDomains');
      expect(headers).toContain('X-Content-Type-Options: nosniff');
      expect(headers).toContain('X-Frame-Options: DENY');
      expect(headers).toContain('Referrer-Policy: strict-origin-when-cross-origin');
    });
  });

  describe('public/sitemap.xml', () => {
    const sitemap = read('public/sitemap.xml');

    it('is a valid urlset referencing the canonical URL', () => {
      expect(sitemap.trimStart().startsWith('<?xml')).toBe(true);
      expect(sitemap).toContain('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');
      expect(sitemap).toContain('<loc>https://mcpcheck.othrys.be/</loc>');
      expect(sitemap).toContain('</urlset>');
    });
  });

  describe('public/robots.txt', () => {
    const robots = read('public/robots.txt');

    it('allows crawling and references the sitemap', () => {
      expect(robots).toContain('User-agent: *');
      expect(robots).toContain('Allow: /');
      expect(robots).toContain('Sitemap: https://mcpcheck.othrys.be/sitemap.xml');
    });
  });

  describe('public/og-image.svg', () => {
    const ogImage = read('public/og-image.svg');

    it('is a 1200x630 local SVG with no external references', () => {
      expect(ogImage).toContain('<svg');
      expect(ogImage).toContain('width="1200"');
      expect(ogImage).toContain('height="630"');
      expect(ogImage).not.toMatch(/https?:\/\/(?!www\.w3\.org)/);
    });
  });

  describe('index.html', () => {
    const html = read('index.html');

    it('declares social tags with a local og:image', () => {
      expect(html).toContain('property="og:title"');
      expect(html).toContain('property="og:description"');
      expect(html).toContain('property="og:type"');
      expect(html).toContain('property="og:url"');
      expect(html).toContain('property="og:image" content="https://mcpcheck.othrys.be/og-image.svg"');
      expect(html).toContain('name="twitter:card" content="summary_large_image"');
      expect(html).toContain('name="twitter:image" content="https://mcpcheck.othrys.be/og-image.svg"');
    });

    it('keeps WebApplication and adds a valid FAQPage JSON-LD block', () => {
      expect(html).toContain('"@type": "WebApplication"');
      expect(html).toContain('"@type": "FAQPage"');

      const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
      expect(blocks.length).toBeGreaterThanOrEqual(2);

      const types = blocks.map((block) => JSON.parse(block[1])['@type']);
      expect(types).toContain('WebApplication');
      expect(types).toContain('FAQPage');
    });

    it('contains no Person schema or anti-ad claims', () => {
      expect(html).not.toContain('"@type": "Person"');
      expect(html).not.toMatch(/Zero Ads/i);
      expect(html).not.toMatch(/Never Ads/i);
    });
  });
});
