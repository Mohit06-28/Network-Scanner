/**
 * Critical / high-risk scan alerts: full-screen red beacon + cyber-style alarm tone.
 * Uses dual square-wave oscillators in alternating “SOC / IDS” siren pattern.
 */
(function (global) {
  'use strict';

  var audioCtx = null;
  var alarmTimer = null;
  var sirenInterval = null;
  var nodes = [];

  function ensureAudio() {
    if (!audioCtx) {
      var Ctx = global.AudioContext || global.webkitAudioContext;
      if (Ctx) audioCtx = new Ctx();
    }
    return audioCtx;
  }

  function disconnectAll() {
    nodes.forEach(function (n) {
      try {
        if (n.stop) n.stop();
        n.disconnect();
      } catch (e) {
        /* ignore */
      }
    });
    nodes = [];
  }

  function stopAlarm() {
    if (alarmTimer) {
      clearTimeout(alarmTimer);
      alarmTimer = null;
    }
    if (sirenInterval) {
      clearInterval(sirenInterval);
      sirenInterval = null;
    }
    disconnectAll();
    var overlay = document.getElementById('critical-alert-overlay');
    if (overlay) overlay.classList.remove('active');
  }

  /** Alternating high/low “intrusion” tones (classic security panel style). */
  function startAlarm(durationMs) {
    var ctx = ensureAudio();
    if (!ctx) return;

    if (ctx.state === 'suspended') {
      ctx.resume().catch(function () {});
    }

    var gain = ctx.createGain();
    gain.gain.setValueAtTime(0.0001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + 0.06);
    gain.connect(ctx.destination);
    nodes.push(gain);

    var phase = 0;
    function playBlip() {
      disconnectAll();
      var g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, ctx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.16, ctx.currentTime + 0.04);
      g.connect(ctx.destination);
      nodes.push(g);

      var o1 = ctx.createOscillator();
      var o2 = ctx.createOscillator();
      o1.type = 'square';
      o2.type = 'square';
      var hi = phase === 0;
      phase = 1 - phase;
      o1.frequency.setValueAtTime(hi ? 1240 : 420, ctx.currentTime);
      o2.frequency.setValueAtTime(hi ? 620 : 210, ctx.currentTime);
      o1.connect(g);
      o2.connect(g);
      o1.start();
      o2.start();
      o1.stop(ctx.currentTime + 0.22);
      o2.stop(ctx.currentTime + 0.22);
      nodes.push(o1, o2);

      var noise = ctx.createBufferSource();
      var buf = ctx.createBuffer(1, ctx.sampleRate * 0.08, ctx.sampleRate);
      var data = buf.getChannelData(0);
      for (var i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;
      noise.buffer = buf;
      var ng = ctx.createGain();
      ng.gain.setValueAtTime(0.06, ctx.currentTime);
      noise.connect(ng);
      ng.connect(g);
      noise.start();
      noise.stop(ctx.currentTime + 0.08);
      nodes.push(noise, ng);
    }

    playBlip();
    sirenInterval = setInterval(playBlip, 280);

    alarmTimer = setTimeout(function () {
      stopAlarm();
    }, durationMs || 14000);
  }

  function injectOverlay() {
    if (document.getElementById('critical-alert-overlay')) return;

    var wrap = document.createElement('div');
    wrap.id = 'critical-alert-overlay';
    wrap.setAttribute('role', 'alertdialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.innerHTML =
      '<div class="alert-beacon" aria-hidden="true"></div>' +
      '<div class="alert-panel">' +
      '  <div class="alert-title" id="critical-alert-title">Critical exposure detected</div>' +
      '  <div class="alert-body" id="critical-alert-body"></div>' +
      '  <button type="button" class="btn btn-danger btn-dismiss" id="critical-alert-dismiss">Acknowledge &amp; silence alarm</button>' +
      '</div>';

    document.body.appendChild(wrap);
    document.getElementById('critical-alert-dismiss').addEventListener('click', stopAlarm);
  }

  function triggerCritical(opts) {
    opts = opts || {};
    injectOverlay();

    var title = opts.title || 'High / critical risk on scanned target';
    var body =
      opts.body ||
      'Open services were classified as HIGH or CRITICAL. Investigate immediately, restrict exposure, and patch or harden affected systems.';

    var titleEl = document.getElementById('critical-alert-title');
    var bodyEl = document.getElementById('critical-alert-body');
    if (titleEl) titleEl.textContent = title;
    if (bodyEl) bodyEl.textContent = body;

    var overlay = document.getElementById('critical-alert-overlay');
    if (overlay) overlay.classList.add('active');

    try {
      if (global.navigator && global.navigator.vibrate) {
        global.navigator.vibrate([500, 200, 500, 200, 500, 200, 500]);
      }
    } catch (e) {
      /* ignore */
    }

    startAlarm(opts.durationMs || 14000);
  }

  global.SecurityAlerts = {
    triggerCritical: triggerCritical,
    stopAlarm: stopAlarm,
  };
})(window);
