/* Web Worker: brute-force a bcrypt hash against 5-digit numeric PINs.
   Uses the vendored bcrypt.js (dcodeIO) loaded via importScripts. */
importScripts('../../vendor/bcrypt.min.js');

const TOTAL = 100000;
const BATCH = 250; // report progress every N checks

self.onmessage = function (e) {
  const hash = e.data.hash;
  const start = e.data.start || 0;

  if (typeof self.dcodeIO === 'undefined' || !self.dcodeIO.bcrypt) {
    self.postMessage({ type: 'error', message: 'bcrypt library failed to load' });
    return;
  }
  const bc = self.dcodeIO.bcrypt;

  try {
    for (let i = start; i < TOTAL; i++) {
      const cand = String(i).padStart(5, '0');
      if (bc.compareSync(cand, hash)) {
        self.postMessage({ type: 'found', pin: cand, checked: i + 1 });
        return;
      }
      if (i % BATCH === 0) {
        self.postMessage({ type: 'progress', checked: i + 1 });
      }
    }
    self.postMessage({ type: 'notfound', checked: TOTAL });
  } catch (err) {
    self.postMessage({ type: 'error', message: err && err.message ? err.message : String(err) });
  }
};
