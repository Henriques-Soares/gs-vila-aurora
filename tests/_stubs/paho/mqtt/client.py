"""Substituto mínimo do paho-mqtt para os testes: um 'broker' em memória.

Reproduz só o que o projeto usa (publish/subscribe com curingas '+'), para testar
simulador e agente de ponta a ponta sem rede. Em produção usa-se o paho-mqtt real.
"""
import enum
import threading

MQTT_ERR_SUCCESS = 0
_trava = threading.Lock()
_clientes: list["Client"] = []


class CallbackAPIVersion(enum.Enum):
    VERSION2 = 2


class _Codigo:
    is_failure = False

    def __str__(self):
        return "Success"


class _Msg:
    def __init__(self, topic, payload):
        self.topic = topic
        self.payload = payload if isinstance(payload, bytes) else str(payload).encode("utf-8")


def _casa(filtro: str, topico: str) -> bool:
    f, t = filtro.split("/"), topico.split("/")
    return len(f) == len(t) and all(a == "+" or a == b for a, b in zip(f, t))


def reiniciar():
    with _trava:
        _clientes.clear()


class Client:
    def __init__(self, _versao=None, client_id="", clean_session=True):
        self.client_id = client_id
        self.on_connect = self.on_disconnect = self.on_message = None
        self._filtros: list[str] = []
        self.tls = None

    def tls_set(self, **kwargs):
        self.tls = kwargs

    def reconnect_delay_set(self, **_kwargs):
        pass

    def connect_async(self, *_a, **_k):
        pass

    def connect(self, *_a, **_k):
        self.loop_start()

    def loop_start(self):
        with _trava:
            _clientes.append(self)
        if self.on_connect:
            self.on_connect(self, None, None, _Codigo(), None)

    def loop_stop(self):
        with _trava:
            if self in _clientes:
                _clientes.remove(self)

    def loop(self, timeout=0):
        return MQTT_ERR_SUCCESS

    def disconnect(self):
        pass

    def subscribe(self, filtro, qos=0):
        self._filtros.append(filtro)

    def publish(self, topico, payload, qos=0):
        with _trava:
            destinos = [c for c in _clientes if any(_casa(f, topico) for f in c._filtros)]
        for cliente in destinos:
            if cliente.on_message:
                cliente.on_message(cliente, None, _Msg(topico, payload))
