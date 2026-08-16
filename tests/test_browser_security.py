import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_templates_use_only_self_hosted_assets_and_no_inline_handlers():
    templates = '\n'.join(
        path.read_text()
        for path in (ROOT / 'templates').rglob('*.html')
    )

    assert 'cdn.jsdelivr.net' not in templates
    assert 'onclick=' not in templates
    assert 'script-src-attr' not in templates


def test_vendored_asset_hashes_match_reviewed_files():
    expected = {
        'static/vendor/bootstrap-5.3.2/bootstrap.min.css': '3017df4a76db5f01c2b99b603d88b03106df13bcfe18e67b7c13c2341d3a67df',
        'static/vendor/bootstrap-5.3.2/bootstrap.bundle.min.js': '82f64f62bb03c1bc1824b0f9c9e05f70dba33e146818e63cdf5c306c8cf3dedd',
        'static/vendor/bootstrap-icons-1.11.1/bootstrap-icons.css': 'bb6fd8cd85394cb367e8ac58e47292f2d68eb288fa12fab68e65430a5ddfce48',
        'static/vendor/bootstrap-icons-1.11.1/fonts/bootstrap-icons.woff2': 'bacd70afda7da1deac2bbd49b5717a4dd133bcd59c379525d705b8492f678e95',
        'static/vendor/bootstrap-icons-1.11.1/fonts/bootstrap-icons.woff': '4d4572ef314e1b734cdd6485f913b0396d81bedf4d216a47cfde0cdf32a9316e',
        'static/vendor/chart.js-4.4.1/chart.umd.min.js': 'd2af8974e95271638772e9e9524db5b9a6f58d6ec2d5d781400447b4a31c681e',
    }

    for relative_path, digest in expected.items():
        assert hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest() == digest
