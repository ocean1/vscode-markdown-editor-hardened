#!/usr/bin/env node
/**
 * Test runner — runs every PoC + integration test, aggregates exit codes.
 *
 * Spawns each test as a subprocess so a hard crash in one doesn't take down
 * the runner. Aggregates exit codes; runner exits non-zero on any failure.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const TEST_DIRS = ['pocs', 'integration'];

function findTests() {
  const tests = [];
  for (const dir of TEST_DIRS) {
    const fullDir = path.join(__dirname, dir);
    if (!fs.existsSync(fullDir)) continue;
    for (const f of fs.readdirSync(fullDir)) {
      if (f.endsWith('.js') && !f.startsWith('_')) {
        tests.push(path.join(fullDir, f));
      }
    }
  }
  return tests.sort();
}

(async () => {
  const tests = findTests();
  if (tests.length === 0) {
    console.log('[run-all] no tests found');
    process.exit(0);
  }

  console.log(`[run-all] running ${tests.length} test(s)`);
  const results = [];
  for (const t of tests) {
    const rel = path.relative(__dirname, t);
    console.log(`\n${'='.repeat(60)}\n[run-all] ${rel}\n${'='.repeat(60)}`);
    const r = spawnSync(process.execPath, [t], { stdio: 'inherit' });
    results.push({ test: rel, code: r.status });
  }

  console.log(`\n${'='.repeat(60)}\n[run-all] summary\n${'='.repeat(60)}`);
  let failed = 0;
  for (const r of results) {
    const tag = r.code === 0 ? '✓ PASS' : `✗ FAIL (exit ${r.code})`;
    console.log(`  ${tag}: ${r.test}`);
    if (r.code !== 0) failed++;
  }
  console.log(`\n${failed === 0 ? 'all tests passed' : `${failed}/${results.length} test(s) failed`}`);
  process.exit(failed === 0 ? 0 : 1);
})();
