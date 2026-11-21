import { describe, expect, it } from 'vitest';
import { assetTreeToSVG, buildAssetTree, filterAssetTree } from './assetTree';

describe('asset tree model', () => {
  it('groups subdomains, services, web findings and CVE clues under a root', () => {
    const entries = [
      { id: 1, scanType: 'subdomain', target: 'example.com', result: JSON.stringify({ domain: 'example.com', names: ['api.example.com'], takeoverClues: [{ subdomain: 'api.example.com', status: 'potential', provider: 'Vercel' }] }) },
      { id: 2, scanType: 'port', target: 'example.com', result: JSON.stringify([{ port: 443, protocol: 'tcp', service: 'HTTPS', version: 'nginx 1.25' }]) },
      { id: 3, scanType: 'http', target: 'https://example.com', result: JSON.stringify([{ url: 'https://example.com', grade: 'C', riskScore: 55, technologies: ['Next.js'], advisoryMatches: [{ cve: 'CVE-2024-0001', severity: 'high' }], findings: [{ id: 'csp-missing', title: 'CSP missing', severity: 'medium' }] }]) },
    ];
    const tree = buildAssetTree(entries);
    expect(tree).toHaveLength(1);
    const labels = JSON.stringify(tree[0]);
    expect(labels).toContain('api.example.com');
    expect(labels).toContain('443/tcp');
    expect(labels).toContain('Next.js');
    expect(labels).toContain('CVE-2024-0001');
    expect(labels).toContain('CSP missing');
  });

  it('filters while preserving matching ancestors', () => {
    const tree = buildAssetTree([{ id: 1, scanType: 'port', target: 'example.com', result: JSON.stringify([{ port: 22, service: 'SSH' }, { port: 443, service: 'HTTPS' }]) }]);
    const filtered = filterAssetTree(tree, 'ssh');
    expect(JSON.stringify(filtered)).toContain('SSH');
    expect(JSON.stringify(filtered)).not.toContain('HTTPS');
  });

  it('exports a readable SVG without leaking HTML markup', () => {
    const tree = buildAssetTree([{ id: 1, scanType: 'port', target: 'example.com', result: JSON.stringify([{ port: 443, service: '<HTTPS>' }]) }]);
    const svg = assetTreeToSVG(tree);
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain('&lt;HTTPS&gt;');
    expect(svg).not.toContain('<HTTPS>');
  });
});
