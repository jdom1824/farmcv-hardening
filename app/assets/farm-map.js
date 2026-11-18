'use strict';
(() => {
  const element = document.getElementById('farm-map');
  if (!element) return;
  const status = document.getElementById('map-status');
  try {
    const polygon = JSON.parse(element.dataset.polygon);
    const map = L.map(element, {scrollWheelZoom: false});
    const shape = L.geoJSON(polygon, {style: {color: '#245c3a', weight: 3, fillColor: '#94b93a', fillOpacity: 0.3}}).addTo(map);
    map.fitBounds(shape.getBounds(), {padding: [30, 30], maxZoom: 17});
    const tiles = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);
    status.textContent = 'Polígono registrado. Usa + y − para acercar o alejar el mapa.';
    tiles.on('tileerror', () => {
      status.textContent = 'El mapa base no pudo cargarse completamente. El contorno registrado sigue visible; comprueba la conexión.';
    });
  } catch (_) {
    status.textContent = 'No se pudo visualizar el polígono. Intenta recargar la página.';
  }
})();
