import importlib.util
import os
from pathlib import Path

import pytest


CONFIG_PATH = Path(__file__).resolve().parents[1] / 'config.py'


def load_config(public_base_url):
    old = os.environ.get('PUBLIC_BASE_URL')
    os.environ['PUBLIC_BASE_URL'] = public_base_url
    try:
        spec = importlib.util.spec_from_file_location('test_auth_config_module', CONFIG_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.Config
    finally:
        if old is None:
            os.environ.pop('PUBLIC_BASE_URL', None)
        else:
            os.environ['PUBLIC_BASE_URL'] = old


def test_public_base_url_normalizes_default_port_and_host_case():
    assert load_config('https://EXAMPLE.COM:443').PUBLIC_BASE_URL == 'https://example.com'


@pytest.mark.parametrize('value', [
    'http://example.com',
    'https://user:pass@example.com',
    'https://example.com/path',
    'https://example.com:notaport',
])
def test_public_base_url_rejects_noncanonical_origins(value):
    with pytest.raises(ValueError):
        load_config(value)
