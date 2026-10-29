// Execute the actual dashboard handler with mocked browser APIs.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '..', 'web', 'index.html'), 'utf8');
const handler = html.split('const handleExportCbom = async () => {')[1].split('// Filtered assessments')[0];
function setup(scanData, response = {ok: true, blob: async () => 'blob'}) {
  const urls = [], errors = [], clicks = [];
  const run = new Function('scanData', 'setErrorMessage', 'fetch', 'URL', 'document',
    'return (async () => {' + handler.replace(/;\s*$/, '') + ')()');
  return {urls, errors, clicks, run: () => run(scanData, e => errors.push(e),
    async url => {urls.push(url); if (response instanceof Error) throw response; return response;},
    {createObjectURL: () => 'blob:local', revokeObjectURL: () => {}},
    {createElement: () => ({click: () => clicks.push(true)})})};
}
test('history export binds the displayed scan ID and encodes it', async () => {
  const mock = setup({metadata: {scan_id: 'older & scan'}});
  await mock.run();
  assert.deepEqual(mock.urls, ['/api/export?format=cbom&id=older%20%26%20scan']);
  assert.equal(mock.clicks.length, 1);
  assert.deepEqual(mock.errors, []);
});
test('unsaved/demo report cannot export unrelated server history', async () => {
  const mock = setup({metadata: {}});
  await mock.run();
  assert.deepEqual(mock.urls, []);
  assert.equal(mock.errors.length, 1);
});
for (const [name, response] of [['expired scan', {ok: false}], ['network failure', new Error('offline')]]) {
  test(name + ' shows an error without fallback to latest', async () => {
    const mock = setup({metadata: {scan_id: 'old'}}, response);
    await mock.run();
    assert.equal(mock.urls.length, 1);
    assert.equal(mock.errors.length, 1);
    assert.equal(mock.clicks.length, 0);
  });
}
