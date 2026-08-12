import importlib.util
from pathlib import Path
from unittest.mock import Mock


SCRIPT = Path(__file__).parents[1] / '.github' / 'scripts' / 'best-cf-ipv4-collector.py'
SPEC = importlib.util.spec_from_file_location('collector', SCRIPT)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def test_extract_ipv4_preserves_and_normalizes_ports():
    text = '1.2.3.4 1.2.3.4:080 1.2.3.4:8443 1.2.3.4:65536'

    assert collector.extract_ipv4(text) == {
        ('1.2.3.4', '443'),
        ('1.2.3.4', '80'),
        ('1.2.3.4', '8443'),
    }


def test_extract_ipv4_ignores_cidr_and_script_content():
    text = '''
    <script>const example = "192.0.2.1:9000";</script>
    <div>198.51.100.2:8443</div>
    203.0.113.4/32
    '''

    assert collector.extract_ipv4(text) == {('198.51.100.2', '8443')}


def test_extract_ipv4_reads_only_ip_fields_from_json():
    text = '''\ufeff{
        "ip": "198.51.100.2:8443",
        "description": "example 192.0.2.1:9000",
        "nested": [{"ip": "203.0.113.4"}]
    }'''

    assert collector.extract_ipv4(text) == {
        ('198.51.100.2', '8443'),
        ('203.0.113.4', '443'),
    }


def test_extract_ipv4_rejects_malformed_json_instead_of_scanning_it():
    text = '{"description": "example 192.0.2.1:9000"'

    assert collector.extract_ipv4(text) == set()


def test_sort_endpoints_uses_ip_then_numeric_port():
    endpoints = {
        ('10.0.0.2', '443'),
        ('10.0.0.1', '8443'),
        ('10.0.0.1', '80'),
    }

    assert collector.sort_endpoints(endpoints) == [
        ('10.0.0.1', '80'),
        ('10.0.0.1', '8443'),
        ('10.0.0.2', '443'),
    ]


def test_close_browser_closes_browser_and_playwright():
    class Resource:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        def stop(self):
            self.closed = True

    browser = Resource()
    playwright = Resource()
    setattr(collector, '_browser', browser)
    setattr(collector, '_pw', playwright)

    collector.close_browser()

    assert browser.closed
    assert playwright.closed
    assert collector._browser is None
    assert collector._pw is None


def test_get_browser_stops_playwright_when_launch_fails(monkeypatch):
    class Chromium:
        def launch(self, *, headless):
            raise RuntimeError('launch failed')

    class Playwright:
        def __init__(self):
            self.chromium = Chromium()
            self.stopped = False

        def stop(self):
            self.stopped = True

    playwright = Playwright()

    class Starter:
        def start(self):
            return playwright

    monkeypatch.setattr(collector, 'sync_playwright', lambda: Starter())
    monkeypatch.setattr(collector, '_browser', None)
    monkeypatch.setattr(collector, '_pw', None)

    try:
        collector._get_browser()
    except RuntimeError as error:
        assert str(error) == 'launch failed'
    else:
        raise AssertionError('Expected browser launch to fail')

    assert playwright.stopped
    assert collector._browser is None
    assert collector._pw is None


def test_main_closes_resources_when_collection_fails(monkeypatch):
    session = Mock()
    browser = Mock()
    playwright = Mock()
    monkeypatch.setattr(collector, '_session', lambda: session)
    monkeypatch.setattr(collector, '_browser', browser)
    monkeypatch.setattr(collector, '_pw', playwright)
    monkeypatch.setattr(
        collector,
        'collect_ips',
        lambda current_session: (_ for _ in ()).throw(RuntimeError('collection failed')),
    )

    try:
        collector.main()
    except RuntimeError as error:
        assert str(error) == 'collection failed'
    else:
        raise AssertionError('Expected collection to fail')

    session.close.assert_called_once_with()
    browser.close.assert_called_once_with()
    playwright.stop.assert_called_once_with()


def test_fetch_rendered_closes_context_when_page_creation_fails(monkeypatch):
    context = Mock()
    context.new_page.side_effect = RuntimeError('page creation failed')
    browser = Mock()
    browser.new_context.return_value = context
    monkeypatch.setattr(collector, '_get_browser', lambda: browser)

    try:
        collector.fetch_rendered('https://example.com')
    except RuntimeError as error:
        assert str(error) == 'page creation failed'
    else:
        raise AssertionError('Expected page creation to fail')

    context.close.assert_called_once_with()
