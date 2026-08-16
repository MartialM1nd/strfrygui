import pytest

from config import Config
from utils import metrics


class FakeResponse:
    def __init__(self, status=200, body=b'metric 1\n', headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.released = False

    def read(self, limit):
        return self.body[:limit]

    def release_conn(self):
        self.released = True


class FakePool:
    response = FakeResponse()
    calls = []

    def __init__(self, host, **kwargs):
        self.host = host
        self.kwargs = kwargs

    def request(self, method, path, **kwargs):
        self.calls.append((self.host, method, path, kwargs))
        return self.response


def loopback_resolution(*args, **kwargs):
    return [(2, 1, 6, '', ('127.0.0.1', 7777))]


def test_fetch_metrics_pins_loopback_and_bounds_request(monkeypatch):
    response = FakeResponse(body=b'example_metric 3\n')
    FakePool.response = response
    FakePool.calls = []
    monkeypatch.setattr(Config, 'STRFRY_METRICS_URL', 'http://metrics.local:7777/metrics')
    monkeypatch.setattr(metrics.socket, 'getaddrinfo', loopback_resolution)
    monkeypatch.setattr(metrics.urllib3, 'HTTPConnectionPool', FakePool)

    result = metrics.fetch_metrics()

    assert result == 'example_metric 3\n'
    host, method, path, request = FakePool.calls[0]
    assert (host, method, path) == ('127.0.0.1', 'GET', '/metrics')
    assert request['headers']['Host'] == 'metrics.local:7777'
    assert request['headers']['Accept-Encoding'] == 'identity'
    assert request['redirect'] is False
    assert response.released is True


def test_fetch_metrics_rejects_non_loopback_before_connect(monkeypatch):
    monkeypatch.setattr(Config, 'STRFRY_METRICS_URL', 'http://metrics.local:7777/metrics')
    monkeypatch.setattr(
        metrics.socket,
        'getaddrinfo',
        lambda *args, **kwargs: [(2, 1, 6, '', ('169.254.169.254', 7777))],
    )
    monkeypatch.setattr(
        metrics.urllib3,
        'HTTPConnectionPool',
        lambda *args, **kwargs: pytest.fail('unsafe address must not be connected'),
    )

    with pytest.raises(metrics.MetricsError, match='loopback'):
        metrics.fetch_metrics()


@pytest.mark.parametrize('response', [
    FakeResponse(status=302, headers={'Location': 'http://127.0.0.1/admin'}),
    FakeResponse(body=b'x' * 20, headers={'Content-Length': '20'}),
    FakeResponse(body=b'compressed', headers={'Content-Encoding': 'gzip'}),
])
def test_fetch_metrics_rejects_redirects_oversized_and_encoded_responses(
    monkeypatch, response
):
    FakePool.response = response
    FakePool.calls = []
    monkeypatch.setattr(Config, 'STRFRY_METRICS_URL', 'http://localhost:7777/metrics')
    monkeypatch.setattr(Config, 'STRFRY_METRICS_MAX_RESPONSE_BYTES', 10)
    monkeypatch.setattr(metrics.socket, 'getaddrinfo', loopback_resolution)
    monkeypatch.setattr(metrics.urllib3, 'HTTPConnectionPool', FakePool)

    with pytest.raises(metrics.MetricsError):
        metrics.fetch_metrics()

    assert len(FakePool.calls) == 1
    assert response.released is True
