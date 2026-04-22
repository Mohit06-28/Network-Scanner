/* Register service worker for installable web app (Add to Home Screen). */
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/static/sw.js').catch(function () {});
  });
}
