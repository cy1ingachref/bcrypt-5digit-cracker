/* ---------------------------------------------------------------
   BCrypt 5-digit PIN cracker — UI + starfield + demo hash loader
   --------------------------------------------------------------- */
(function () {
  "use strict";

  // ---- demo data ----------------------------------------------------
  // The demo hash is generated at runtime in the browser: we hash PIN "00042"
  // at cost 4 with the vendored bcrypt.js, then the worker brute-forces it back.
  // This keeps the demo honest and cost-accurate without shipping a precomputed
  // value. (The same PIN/algorithm is recoverable with the Python cracker.py.)
  let DEMO_READY = false;
  function ensureDemoHash() {
    return new Promise((resolve) => {
      if (DEMO_READY) return resolve(window.__demoHash);
      try {
        const bc = window.dcodeIO && window.dcodeIO.bcrypt;
        if (!bc) return resolve(null);
        // hash "00042" with cost 4
        window.__demoHash = bc.hashSync("00042", bc.genSaltSync(4));
        DEMO_READY = true;
        resolve(window.__demoHash);
      } catch (e) { resolve(null); }
    });
  }

  // ---- elements -----------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const hashInput = $("hash");
  const startBtn = $("startBtn");
  const stopBtn = $("stopBtn");
  const demoBtn = $("demoBtn");
  const statusEl = $("status");
  const bar = $("bar");
  const checkedEl = $("checked");
  const elapsedEl = $("elapsed");
  const rateEl = $("rate");
  const resultEl = $("result");
  const costHint = $("costHint");
  const codeBlock = $("codeBlock");

  let worker = null;
  let startTime = 0;
  let timerId = null;
  let running = false;

  // ---- status helpers ----------------------------------------------
  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = "status " + (cls || "idle");
  }

  function costOf(hash) {
    const m = /^\$2[aby]\$(\d{1,2})\$/.exec(hash || "");
    return m ? parseInt(m[1], 10) : null;
  }

  function warnCost(hash) {
    const c = costOf(hash);
    if (c === null) { costHint.textContent = ""; return; }
    if (c >= 10) {
      costHint.textContent =
        "⚠ Cost " + c + ": at this cost factor the browser may take hours " +
        "to check all 100k candidates. The demo hash (cost 4) is recommended.";
      costHint.style.color = "var(--danger)";
    } else if (c >= 6) {
      costHint.textContent =
        "ℹ Cost " + c + ": expect roughly " + (c <= 6 ? "10 minutes" :
        c <= 8 ? "an hour" : "a few hours") + " in-browser. Demo hash is cost 4.";
      costHint.style.color = "var(--muted)";
    } else {
      costHint.textContent = "✓ Cost " + c + ": low — finishes in seconds.";
      costHint.style.color = "var(--ok)";
    }
  }

  // ---- run ----------------------------------------------------------
  function start() {
    const hash = (hashInput.value || "").trim();
    if (!hash) { setStatus("Enter a hash first (or click 'Use demo hash').", "error"); return; }
    if (!/^\$2[aby]\$/.test(hash)) {
      setStatus("That doesn't look like a bcrypt hash (should start with $2a$/$2b$/$2y$).", "error");
      return;
    }
    if (!window.dcodeIO || !window.dcodeIO.bcrypt) {
      setStatus("bcrypt library didn't load — check vendor/bcrypt.min.js.", "error");
      return;
    }

    stop(); // clear any prior run
    running = true;
    startTime = performance.now();
    setStatus("Running… brute-forcing 00000 → 99999", "running");
    bar.style.width = "0%";
    checkedEl.textContent = "0";
    elapsedEl.textContent = "0.0";
    rateEl.textContent = "0";
    resultEl.className = "result hidden";
    resultEl.innerHTML = "";
    startBtn.disabled = true;
    stopBtn.disabled = false;

    worker = new Worker("assets/js/worker.js");
    worker.onmessage = onWorkerMsg;
    worker.onerror = (e) => {
      setStatus("Worker error: " + (e.message || "unknown"), "error");
      stop();
    };
    worker.postMessage({ hash: hash, start: 0 });

    timerId = setInterval(tick, 200);
  }

  function tick() {
    const elapsed = (performance.now() - startTime) / 1000;
    elapsedEl.textContent = elapsed.toFixed(1);
    const checked = parseInt(checkedEl.textContent, 10) || 0;
    if (checked > 0) rateEl.textContent = Math.round(checked / elapsed).toLocaleString();
  }

  function onWorkerMsg(e) {
    const d = e.data;
    if (d.type === "progress") {
      checkedEl.textContent = d.checked.toLocaleString();
      bar.style.width = (d.checked / 100000 * 100).toFixed(2) + "%";
    } else if (d.type === "found") {
      checkedEl.textContent = d.checked.toLocaleString();
      bar.style.width = "100%";
      const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
      setStatus("FOUND after " + elapsed + "s", "done");
      resultEl.className = "result";
      resultEl.innerHTML =
        "<div>Recovered PIN:</div><div class='pin'>" + d.pin + "</div>" +
        "<div class='muted'>checked " + d.checked.toLocaleString() +
        " candidates in " + elapsed + "s</div>";
      stop();
    } else if (d.type === "notfound") {
      checkedEl.textContent = "100,000";
      bar.style.width = "100%";
      setStatus("Exhausted all 100,000 candidates — not found.", "error");
      resultEl.className = "result fail";
      resultEl.innerHTML = "<div class='pin'>NOT FOUND</div>" +
        "<div class='muted'>No 5-digit PIN matches this hash.</div>";
      stop();
    } else if (d.type === "error") {
      setStatus("Error: " + d.message, "error");
      stop();
    }
  }

  function stop() {
    running = false;
    if (worker) { try { worker.terminate(); } catch (e) {} worker = null; }
    if (timerId) { clearInterval(timerId); timerId = null; }
    startBtn.disabled = false;
    stopBtn.disabled = true;
  }

  // ---- demo hash ----------------------------------------------------
  demoBtn.addEventListener("click", function () {
    ensureDemoHash().then((h) => {
      if (!h) { setStatus("Could not generate demo hash (no bcrypt lib).", "error"); return; }
      hashInput.value = h;
      warnCost(h);
      setStatus("Demo hash loaded — click 'Start crack'. It's PIN 00042 at cost 4.", "idle");
    });
  });

  hashInput.addEventListener("input", () => warnCost(hashInput.value));
  startBtn.addEventListener("click", start);
  stopBtn.addEventListener("click", stop);

  // ---- load python source into the page -----------------------------
  fetch("cracker.py")
    .then((r) => r.ok ? r.text() : "cracker.py not found in this deployment.")
    .then((t) => { codeBlock.textContent = t; })
    .catch(() => { codeBlock.textContent = "cracker.py not found in this deployment."; });

  // ---- starfield ----------------------------------------------------
  const canvas = document.getElementById("stars");
  const ctx = canvas.getContext("2d");
  let stars = [];
  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const n = Math.min(160, Math.floor(window.innerWidth / 9));
    stars = [];
    for (let i = 0; i < n; i++) {
      stars.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        r: Math.random() * 1.4 + 0.2,
        s: Math.random() * 0.25 + 0.04,
        a: Math.random() * 0.6 + 0.2
      });
    }
  }
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const st of stars) {
      st.y += st.s;
      if (st.y > canvas.height) { st.y = 0; st.x = Math.random() * canvas.width; }
      ctx.beginPath();
      ctx.arc(st.x, st.y, st.r, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(180,200,255," + st.a + ")";
      ctx.fill();
    }
    requestAnimationFrame(draw);
  }
  window.addEventListener("resize", resize);
  resize();
  draw();

  // pre-generate demo hash so the button is instant
  ensureDemoHash();
})();
