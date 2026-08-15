import importlib.util
import os
from pathlib import Path

import pytest


CONFIG_PATH = Path(__file__).resolve().parents[1] / 'config.py'


def load_config_module(public_base_url):
    old = os.environ.get('PUBLIC_BASE_URL')
    os.environ['PUBLIC_BASE_URL'] = public_base_url
    try:
        spec = importlib.util.spec_from_file_location('test_auth_config_module', CONFIG_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old is None:
            os.environ.pop('PUBLIC_BASE_URL', None)
        else:
            os.environ['PUBLIC_BASE_URL'] = old


def load_config(public_base_url):
    return load_config_module(public_base_url).Config


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


def test_secret_validation_rejects_weak_values():
    old = os.environ.get('SECRET_KEY')
    os.environ['SECRET_KEY'] = 'too-short'
    try:
        with pytest.raises(ValueError, match='at least 32 characters'):
            load_config('https://example.com')
    finally:
        if old is None:
            os.environ.pop('SECRET_KEY', None)
        else:
            os.environ['SECRET_KEY'] = old


def test_dotenv_validation_rejects_world_readable_file(tmp_path):
    config_module = load_config_module('https://example.com')
    dotenv = tmp_path / '.env'
    dotenv.write_text('SECRET_KEY=not-read\n')
    dotenv.chmod(0o644)

    with pytest.raises(ValueError, match='accessible by other users'):
        config_module._validate_dotenv(dotenv)


def test_dotenv_validation_allows_documented_group_read_mode(tmp_path):
    config_module = load_config_module('https://example.com')
    dotenv = tmp_path / '.env'
    dotenv.write_text('SECRET_KEY=not-read\n')
    dotenv.chmod(0o640)

    config_module._validate_dotenv(dotenv)


def test_dotenv_validation_rejects_symlinks(tmp_path):
    config_module = load_config_module('https://example.com')
    target = tmp_path / 'target'
    target.write_text('SECRET_KEY=not-read\n')
    dotenv = tmp_path / '.env'
    dotenv.symlink_to(target)

    with pytest.raises(ValueError, match='not a symlink'):
        config_module._validate_dotenv(dotenv)
