"""Read-only public projection and protected admin surface."""

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.admin_portal import app
from app import admin_farms as inventory, public_home


class PublicHomeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        settings = SimpleNamespace(transaction_db_file=Path(temporary.name) / 'outbox.sqlite3',
                                   chain_id=84532, contract_address='0x' + 'ab' * 20)
        self.enterContext(patch.object(inventory, 'settings', settings))
        self.enterContext(patch.object(public_home, 'settings', settings))
        self.key = Fernet.generate_key()
        self.enterContext(patch.object(public_home, 'load_server_key', return_value=self.key))
        inventory.initialize_index()
        self.client = TestClient(app, base_url='https://testserver')
        self.addCleanup(self.client.close)

    def save(self, number, name, *, status=0, consent=True, age=0):
        fid = '0x' + f'{number:064x}'
        cv = {'identification': {'farmName': name, 'producerName': 'DATO_PRIVADO'},
              'location': {'municipality': 'Rionegro', 'department': 'Santander'},
              'quality': {'publicProfileConsent': consent}, 'photos': [{'sha256': 'cd' * 32}]}
        record = {'encryptedCV': Fernet(self.key).encrypt(json.dumps(cv).encode()).decode(),
                  'status': status, 'version': 1}
        inventory.save_record(fid, number, record, time.time() - age)
        return fid

    def test_visitor_routes_and_admin_boundary(self):
        home = self.client.get('/')
        self.assertEqual(home.status_code, 200)
        self.assertIn('Explorar fincas', home.text)
        self.assertNotIn('id="password"', home.text)
        self.assertIn("script-src", self.client.get('/admin').headers['content-security-policy'])
        self.assertIn('Volver a Oriká', self.client.get('/admin').text)
        self.assertEqual(self.client.get('/assets/orika-home.css').status_code, 200)
        self.assertEqual(self.client.get('/admin/farms').status_code, 401)
        self.assertEqual(self.client.get('/docs').status_code, 401)
        self.assertEqual(self.client.post('/fincas').status_code, 401)
        self.assertEqual(self.client.post('/farm-cv', json={}).status_code, 401)

    def test_catalog_checks_consent_and_state_escapes_names(self):
        visible = self.save(1, 'Finca Águila <script>hola</script>')
        private = self.save(2, 'PRIVADA', consent=False)
        revoked = self.save(3, 'REVOCADA', status=2)
        suspended = self.save(4, 'SUSPENDIDA', status=1)
        stale = self.save(5, 'ANTIGUA', age=public_home.MAX_AGE + 5)
        pending = self.save(6, 'POR ACTUALIZAR')
        with patch.object(inventory, 'confirmed_hints_snapshot', return_value=({pending: (time.time() + 1, None)}, None)):
            response = self.client.get('/fincas', params={'q': 'aguila Rionegro'})
            full = self.client.get('/fincas').text
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'href="/fincas/{visible}"', response.text)
        self.assertIn('&lt;script&gt;hola&lt;/script&gt;', response.text)
        self.assertIn(f'/fincas/{visible}/fotos/{"cd" * 32}.jpg', response.text)
        self.assertIn('Demostración', response.text)
        for hidden in (private, revoked, suspended, stale, pending, 'DATO_PRIVADO'):
            self.assertNotIn(hidden, full)

    def test_pagination_and_empty_search(self):
        for number in range(1, 9):
            self.save(number, f'Finca del catálogo {number}')
        first = self.client.get('/fincas').text
        second = self.client.get('/fincas?page=2').text
        self.assertEqual(first.count('class="farm-card"'), 6)
        self.assertEqual(second.count('class="farm-card"'), 2)
        self.assertIn('Siguiente', first)
        self.assertIn('Anterior', second)
        self.assertIn('No hay fincas', self.client.get('/fincas?q=otra').text)
