// Service worker: shows check alerts and opens the right page when one is tapped.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: 'Human ID', body: event.data?.text() };
  }
  event.waitUntil(self.registration.showNotification(data.title || 'Human ID', {
    body: data.body || '',
    tag: data.tag,
    renotify: true,
    requireInteraction: true,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: { url: data.url || '/home' },
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = new URL(event.notification.data?.url || '/home', self.location.origin).href;
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windows) {
      if ('focus' in client) {
        await client.navigate(url).catch(() => {});
        return client.focus();
      }
    }
    return self.clients.openWindow(url);
  })());
});
