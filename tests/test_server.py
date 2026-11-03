"""无桌面入口的进程退出与现有数据保护。"""
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from peach import server, settings_file
from starlette.requests import Request


class ProxyConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from fastapi import FastAPI
        from peach import routes_auth, routes_configuration

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = settings_file.load_config(environ={"PEACH_DATA_ROOT": str(Path(temporary.name).resolve())})
        settings_file.write(self.config)
        self.enterContext(patch.dict("os.environ", {
            "PEACH_HEADLESS_MANAGED": "1", "PEACH_CONFIG_PUBLIC_ORIGIN": "https://media.example.com",
            "FORWARDED_ALLOW_IPS": "192.0.2.10",
        }))
        self.enterContext(patch.object(settings_file, "load_config", return_value=self.config))
        self.enterContext(patch.object(settings_file, "active", return_value=self.config))
        self.app = FastAPI()
        self.app.state.settings = SimpleNamespace(token="test-secret", access_path=self.config.directory("secrets") / "access.json",
                                                  configured=True)
        self.app.state.tunnel = SimpleNamespace(snapshot=lambda: SimpleNamespace())
        self.app.state.automatic_updates = SimpleNamespace(snapshot=lambda: {})
        self.app.include_router(routes_auth.router)
        self.app.include_router(routes_configuration.router)

    def client(self, peer="192.0.2.10", *, wrapped=True):
        import httpx
        from peach.proxy_headers import ConfigurationProxyHeadersMiddleware

        app = ConfigurationProxyHeadersMiddleware(self.app) if wrapped else self.app
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 1234)),
                                 base_url="https://media.example.com", headers={
                                     "X-Forwarded-Proto": "https", "X-Forwarded-For": "8.8.8.8",
                                     "Origin": "https://media.example.com", "X-Token": "test-secret",
                                 })

    async def test_trusted_proxy_can_read_and_persist_configuration_after_login(self):
        from peach import remote_reporting
        from peach.routes_configuration import configurable

        async with self.client() as client:
            login = await client.post("/login", data={"token": "test-secret"})
            self.assertEqual(login.status_code, 303)
            del client.headers["X-Token"]
            read = await client.get("/api/configuration/automatic-updates")
            self.assertEqual(read.status_code, 200)
            saved = await client.post("/api/configuration/remote-reporting", json={
                "usage": False, "errors": False,
            })
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertFalse(remote_reporting.snapshot(self.config)["usage"])

        request = Request({"type": "http", "client": ("8.8.8.8", 0), "server": ("0.0.0.0", 8900),
                           "scheme": "https", "path": "/", "headers": [(b"host", b"media.example.com"),
                           (b"x-forwarded-for", b"8.8.8.8")], "app": self.app,
                           "peach.transport_client": ("192.0.2.10", 1234)})
        from peach.web_local_access import local_client
        self.assertTrue(configurable(request))
        self.assertFalse(local_client(request), "公网配置授权不开放宿主机播放器")

    async def test_management_rejects_untrusted_peer_wrong_host_http_and_missing_transport(self):
        async with self.client("8.8.4.4") as client:
            self.assertEqual((await client.get("/api/configuration/automatic-updates")).status_code, 403)
        async with self.client(wrapped=False) as client:
            self.assertEqual((await client.get("/api/configuration/automatic-updates")).status_code, 403)
        async with self.client() as client:
            for headers in ({"Host": "other.example.com"}, {"X-Forwarded-Proto": "http"}):
                with self.subTest(headers=headers):
                    self.assertEqual((await client.get("/api/configuration/automatic-updates", headers=headers)).status_code, 403)
            for environment in ({"PEACH_CONFIG_PUBLIC_ORIGIN": ""}, {"PEACH_HEADLESS_MANAGED": "0"},
                                {"FORWARDED_ALLOW_IPS": "*"}):
                with self.subTest(environment=environment), patch.dict("os.environ", environment):
                    self.assertEqual((await client.get("/api/configuration/automatic-updates")).status_code, 403)

    async def test_management_keeps_authentication_and_cross_origin_rejection(self):
        from peach import access

        async with self.client() as client:
            del client.headers["X-Token"]
            self.assertEqual((await client.get("/api/configuration/automatic-updates")).status_code, 401)
            client.headers["X-Token"] = "test-secret"
            for headers in ({"Origin": "https://other.example.com"}, {"Sec-Fetch-Site": "cross-site"}):
                with self.subTest(headers=headers):
                    saved = await client.post("/api/configuration/remote-reporting", json={}, headers=headers)
                    self.assertEqual(saved.status_code, 403)
            access.save(self.app.state.settings.access_path, "")
            self.assertEqual((await client.get("/api/configuration/automatic-updates")).status_code, 403)


class ServerTests(unittest.TestCase):
    def test_reader_initialization_does_not_launch_a_ledger_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = settings_file.load_config(environ={'PEACH_DATA_ROOT': str(Path(directory).resolve())})
            settings_file.write(config)
            config.directory('database').mkdir()
            database = config.directory('database') / 'ledger.db'
            database.write_bytes(b'unchanged reader ledger')
            config = settings_file.load_config(environ={'PEACH_DATA_ROOT': str(config.data_root)})
            with patch.object(server.settings_file, 'load_config', return_value=config), patch(
                    'peach.runtime_prepare.configured_ledger_writer', return_value=(False, '读取端')), \
                    patch.object(server, 'launch') as launch:
                server.initialize()
            launch.assert_not_called()
            self.assertEqual(database.read_bytes(), b'unchanged reader ledger')

    def test_headless_configuration_accepts_private_peers_and_rejects_forwarding(self):
        from peach.routes_configuration import local_client, managed_configuration
        with patch.dict("os.environ", {"PEACH_HEADLESS_MANAGED": "1"}):
            self.assertTrue(managed_configuration())
            for peer, headers, allowed in (
                ("192.0.2.1", [], True), ("198.51.100.10", [], True),
                ("8.8.8.8", [], False), ("169.254.1.1", [], False),
                ("0.0.0.0", [], False), ("240.0.0.1", [], False),
                ("127.0.0.1", [], True), ("fd00::1", [], True),
                ("192.0.2.1", [(b"x-forwarded-for", b"8.8.8.8")], False),
                ("192.0.2.1", [(b"x-forwarded-host", b"example.com")], False),
            ):
                request = Request({"type": "http", "client": (peer, 1234),
                                   "server": ("0.0.0.0", 8900), "headers": headers,
                                   "app": SimpleNamespace(state=SimpleNamespace(tunnel=None))})
                with self.subTest(peer=peer, headers=headers):
                    self.assertEqual(local_client(request), allowed)

    def test_cli_without_mdns_or_tunnel_needs_no_network_route(self):
        from peach import cli
        with patch.object(cli, "_require_readable_settings"), \
                patch.object(cli, "_serve_token", return_value="test"), \
                patch.object(cli, "_build_sync", return_value=None), \
                patch.object(cli, "create_app"), patch.object(cli, "TUNNEL_ENABLED", False), \
                patch("peach.mdns.lan_ipv4", side_effect=OSError("no route")) as route, \
                patch("uvicorn.run"):
            self.assertEqual(cli.main(["serve", "--host", "0.0.0.0", "--no-mdns"]), 0)
        route.assert_not_called()

    def test_headless_proxy_keeps_transport_peer_before_forwarded_headers(self):
        from peach import cli
        from peach.proxy_headers import ConfigurationProxyHeadersMiddleware
        with patch.dict("os.environ", {"PEACH_HEADLESS_MANAGED": "1",
                                      "PEACH_CONFIG_PUBLIC_ORIGIN": "https://media.example.com"}), \
                patch.object(cli, "_require_readable_settings"), \
                patch.object(cli, "_serve_token", return_value="test"), \
                patch.object(cli, "_build_sync", return_value=None), \
                patch.object(cli, "create_app"), patch.object(cli, "TUNNEL_ENABLED", False), \
                patch("uvicorn.run") as run:
            self.assertEqual(cli.main(["serve", "--host", "0.0.0.0", "--no-mdns"]), 0)
            self.assertIsInstance(run.call_args.args[0], ConfigurationProxyHeadersMiddleware)
            self.assertFalse(run.call_args.kwargs["proxy_headers"])

    def test_initialization_preserves_existing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = settings_file.load_config(environ={"PEACH_DATA_ROOT": str(root)})
            settings_file.write(config)
            config.directory('database').mkdir()
            config.directory('database').joinpath('ledger.db').touch()
            existing = config.path.read_bytes()
            with patch.object(server.settings_file, "load_config", return_value=settings_file.load_config(
                    environ={"PEACH_DATA_ROOT": str(root)})), patch.object(server, "launch") as launch:
                launch.return_value.wait.return_value = 0
                server.initialize()
            launch.assert_called_once_with('migrate', 'upgrade', '--yes', '--db', str(config.directory('database') / 'ledger.db'))
            self.assertEqual(config.path.read_bytes(), existing)

    def test_initialization_rejects_database_without_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = settings_file.load_config(environ={"PEACH_DATA_ROOT": str(root)})
            config.directory("database").mkdir()
            config.directory("database").joinpath("ledger.db").write_bytes(b"existing")
            with patch.object(server.settings_file, "load_config", return_value=config), \
                    patch.object(server, "launch") as launch:
                with self.assertRaisesRegex(RuntimeError, "已有数据库"):
                    server.initialize()
            launch.assert_not_called()

    def test_stop_waits_for_child_exit(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                   stdin=subprocess.DEVNULL)
        try:
            server.stop_process(process)
            self.assertIsNotNone(process.poll())
        finally:
            server.stop_process(process)

    def test_relocation_restarts_the_service_on_the_new_data_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = settings_file.load_config(environ={"PEACH_DATA_ROOT": str(root)})
            process = subprocess.Popen([sys.executable, "-c", "raise SystemExit(17)"], stdin=subprocess.DEVNULL)
            process.wait(timeout=15)
            calls = []

            def relocation(stop, restart):
                if calls:
                    return False
                calls.append(True)
                stop()
                restart({"PEACH_DATA_ROOT": str(root / "moved")})
                return True

            with patch.dict(server.os.environ, {}), \
                    patch.object(server.settings_file, "load_config", return_value=config), \
                    patch("peach.data_storage.poll_headless", side_effect=relocation), \
                    patch.object(server, "launch", return_value=process) as launch:
                self.assertEqual(server.supervise("127.0.0.1", 8900, threading.Event()), 17)
                # 迁移后看守进程自己也按新位置读设置，拉起的服务继承这个位置。
                self.assertEqual(server.os.environ["PEACH_DATA_ROOT"], str(root / "moved"))
            self.assertEqual(launch.call_count, 1)

    def test_service_failure_exits_supervisor(self):
        with tempfile.TemporaryDirectory() as directory:
            config = settings_file.load_config(environ={"PEACH_DATA_ROOT": str(Path(directory).resolve())})
            process = subprocess.Popen([sys.executable, "-c", "raise SystemExit(17)"],
                                       stdin=subprocess.DEVNULL)
            process.wait(timeout=15)
            with patch.object(server.settings_file, "load_config", return_value=config), \
                    patch.object(server, "launch", return_value=process):
                self.assertEqual(server.supervise("127.0.0.1", 8900, threading.Event()), 17)
