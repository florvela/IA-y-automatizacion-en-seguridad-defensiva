import requests
from datetime import datetime
from core.base import ConectorBase


class ConectorJira(ConectorBase):

    def __init__(self, url: str, user: str, token: str, use_mock: bool = True):
        super().__init__('jira', use_mock)
        self.url = url
        self.auth = (user, token)
        self._ticket_counter = 1000

    def verificar_salud(self) -> bool:
        if self.use_mock:
            return True
        try:
            resp = requests.get(f'{self.url}/rest/api/3/myself', auth=self.auth, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def crear_ticket(self, titulo: str, descripcion: str, prioridad: str = 'Medium') -> dict:
        self._log(f'Creando ticket: {titulo[:50]}')
        if self.use_mock:
            self._ticket_counter += 1
            ticket_id = f'SOC-{self._ticket_counter}'
            return {
                'id': ticket_id,
                'url': f'{self.url}/browse/{ticket_id}',
                'estado': 'Open',
                'creado': datetime.now().isoformat()
            }
        payload = {
            'fields': {
                'project': {'key': 'SOC'},
                'summary': titulo,
                'description': {
                    'type': 'doc', 'version': 1,
                    'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text': descripcion}]}]
                },
                'issuetype': {'name': 'Incident'},
                'priority': {'name': prioridad}
            }
        }
        resp = requests.post(f'{self.url}/rest/api/3/issue', json=payload, auth=self.auth)
        return resp.json()

    def actualizar_estado(self, ticket_id: str, comentario: str) -> bool:
        self._log(f'Actualizando {ticket_id}: {comentario[:50]}')
        if self.use_mock:
            return True
        payload = {
            'body': {
                'type': 'doc', 'version': 1,
                'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text': comentario}]}]
            }
        }
        resp = requests.post(
            f'{self.url}/rest/api/3/issue/{ticket_id}/comment',
            json=payload,
            auth=self.auth
        )
        return resp.status_code == 201
