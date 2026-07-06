// VibeSafe marketplace reach — public install/download counts from both stores.
// No auth needed; numbers are public on the store listings anyway.

const EXT_ID = 'vibesafe-info.vibesafe-scanner';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  res.setHeader('Cache-Control', 's-maxage=3600, stale-while-revalidate');

  let vscode_installs = null, openvsx_downloads = null, version = null;

  try {
    const r = await fetch('https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery', {
      method: 'POST',
      headers: {
        'Accept': 'application/json;api-version=3.0-preview.1',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        filters: [{ criteria: [{ filterType: 7, value: EXT_ID }] }],
        flags: 914,
      }),
    });
    if (r.ok) {
      const d = await r.json();
      const ext = d.results?.[0]?.extensions?.[0];
      const stat = (ext?.statistics || []).find(s => s.statisticName === 'install');
      vscode_installs = stat ? Math.round(stat.value) : null;
      version = ext?.versions?.[0]?.version || null;
    }
  } catch (e) { /* best effort */ }

  try {
    const r = await fetch(`https://open-vsx.org/api/${EXT_ID.replace('.', '/')}`);
    if (r.ok) {
      const d = await r.json();
      openvsx_downloads = d.downloadCount ?? null;
    }
  } catch (e) { /* best effort */ }

  return res.status(200).json({ vscode_installs, openvsx_downloads, version });
}
