import time
import requests
from datetime import datetime
from typing import Optional
from core.base import ConectorBase


class ConectorCrowdStrike(ConectorBase):
    BASE_URL = 'https://api.crowdstrike.com'

    def __init__(self, client_id: str, client_secret: str, use_mock: bool = True):
        super().__init__('crowdstrike', use_mock)
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None

    def verificar_salud(self) -> bool:
        if self.use_mock:
            return True
        try:
            self._obtener_token()
            return self._token is not None
        except Exception:
            return False

    def _obtener_token(self):
        if self.use_mock:
            self._token = 'mock_token_cs_abc123'
            return
        resp = requests.post(
            f'{self.BASE_URL}/oauth2/token',
            data={'client_id': self.client_id, 'client_secret': self.client_secret}
        )
        self._token = resp.json()['access_token']

    def buscar_dispositivo(self, hostname: str) -> dict:
        self._log(f'Buscando dispositivo: {hostname}')
        if self.use_mock:
            return {
                'device_id': 'abc123def456',
                'hostname': hostname,
                'os': 'Windows 10',
                'ip_local': '10.0.1.45',
                'estado': 'normal',
                'ultimo_visto': datetime.now().isoformat()
            }
        if not self._token:
            self._obtener_token()
        headers = {'Authorization': f'Bearer {self._token}'}
        resp = requests.get(
            f'{self.BASE_URL}/devices/queries/devices/v1',
            headers=headers,
            params={'filter': f'hostname:"{hostname}"'}
        )
        return resp.json()

    def aislar_dispositivo(self, device_id: str) -> bool:
        self._log(f'Aislando dispositivo: {device_id}')
        if self.use_mock:
            time.sleep(0.3)
            self._log('Dispositivo aislado exitosamente (mock)')
            return True
        if not self._token:
            self._obtener_token()
        headers = {'Authorization': f'Bearer {self._token}'}
        resp = requests.post(
            f'{self.BASE_URL}/devices/entities/devices/actions/contain/v1',
            headers=headers,
            params={'action_name': 'contain'},
            json={'ids': [device_id]}
        )
        return resp.status_code == 200
