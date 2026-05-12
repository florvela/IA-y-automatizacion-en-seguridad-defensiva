import requests
from core.base import ConectorBase

MOCK_VT = {
    'hash': {
        '44d88612fea8a8f36de82e1278abb02f': {
            'malicious': 58, 'suspicious': 3, 'undetected': 12,
            'tipo': 'Win32 EXE', 'nombre': 'EICAR-Test-File',
            'veredicto': 'MALICIOSO'
        },
        'd41d8cd98f00b204e9800998ecf8427e': {
            'malicious': 0, 'suspicious': 0, 'undetected': 71,
            'tipo': 'empty', 'nombre': '',
            'veredicto': 'LIMPIO'
        },
    },
    'ip': {
        '173.234.31.186': {
            'malicious': 12, 'pais': 'US', 'asn': 'AS14618 AMAZON-AES',
            'veredicto': 'MALICIOSA'
        },
        '45.33.32.156': {
            'malicious': 8, 'pais': 'US', 'asn': 'AS63949 LINODE-AP',
            'veredicto': 'SOSPECHOSA'
        },
    },
    'dominio': {
        'ns.marryaldkfaczcz.com': {
            'malicious': 22, 'categorias': ['malware', 'c2'],
            'veredicto': 'MALICIOSO'
        },
    }
}


class ConectorVirusTotal(ConectorBase):
    BASE_URL = 'https://www.virustotal.com/api/v3'

    def __init__(self, api_key: str, use_mock: bool = True):
        super().__init__('virustotal', use_mock)
        self.api_key = api_key
        self.headers = {'x-apikey': api_key}

    def verificar_salud(self) -> bool:
        if self.use_mock:
            self._log('Health check OK (mock)')
            return True
        try:
            r = requests.get(f'{self.BASE_URL}/ip_addresses/8.8.8.8', headers=self.headers, timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def analizar_hash(self, hash_valor: str) -> dict:
        self._log(f'Analizando hash: {hash_valor[:16]}...')
        if self.use_mock:
            return MOCK_VT['hash'].get(hash_valor, {
                'malicious': 0, 'veredicto': 'NO_ENCONTRADO',
                'nota': 'Hash no visto antes — puede ser nuevo malware o archivo legítimo'
            })
        url = f'{self.BASE_URL}/files/{hash_valor}'
        def _llamar(): return requests.get(url, headers=self.headers, timeout=10).json()
        data = self._reintentar(_llamar)
        stats = data['data']['attributes']['last_analysis_stats']
        return {'malicious': stats['malicious'], 'veredicto': 'MALICIOSO' if stats['malicious'] > 0 else 'LIMPIO'}

    def analizar_ip(self, ip: str) -> dict:
        self._log(f'Analizando IP: {ip}')
        if self.use_mock:
            return MOCK_VT['ip'].get(ip, {'malicious': 0, 'veredicto': 'SIN_DATOS'})
        url = f'{self.BASE_URL}/ip_addresses/{ip}'
        def _llamar(): return requests.get(url, headers=self.headers, timeout=10).json()
        data = self._reintentar(_llamar)
        stats = data['data']['attributes']['last_analysis_stats']
        return {'malicious': stats['malicious'], 'veredicto': 'MALICIOSA' if stats['malicious'] > 5 else 'LIMPIA'}

    def analizar_dominio(self, dominio: str) -> dict:
        self._log(f'Analizando dominio: {dominio}')
        if self.use_mock:
            return MOCK_VT['dominio'].get(dominio, {'malicious': 0, 'veredicto': 'SIN_DATOS'})
        url = f'{self.BASE_URL}/domains/{dominio}'
        def _llamar(): return requests.get(url, headers=self.headers, timeout=10).json()
        data = self._reintentar(_llamar)
        stats = data['data']['attributes']['last_analysis_stats']
        return {'malicious': stats['malicious'], 'veredicto': 'MALICIOSO' if stats['malicious'] > 3 else 'LIMPIO'}
