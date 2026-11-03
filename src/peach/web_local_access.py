"""Web 请求的本机访问判断；配置与本地播放器共用。"""
from __future__ import annotations

import ipaddress
import os

from fastapi import Request

from . import access, distribution, tunnel


def configuration_client(request: Request) -> bool:
    """允许本机管理，或显式授权的无桌面 HTTPS 反代管理。"""
    if local_client(request):
        return True
    origin = os.environ.get("PEACH_CONFIG_PUBLIC_ORIGIN", "").strip().rstrip("/")
    if (os.environ.get("PEACH_HEADLESS_MANAGED") != "1" or not origin.startswith("https://")
            or str(request.base_url).rstrip("/") != origin):
        return False
    transport = request.scope.get("peach.transport_client")
    if not transport:
        return False
    try:
        peer = ipaddress.ip_address(transport[0])
        proxies = [ipaddress.ip_address(item.strip()) for item in
                   os.environ.get("FORWARDED_ALLOW_IPS", "").split(",") if item.strip()]
    except ValueError:
        return False
    if peer not in proxies:
        return False
    settings = request.app.state.settings
    return bool(settings.token) and access.load(settings.access_path)["mode"] in {"legacy", "password"}


def managed_configuration() -> bool:
    """托盘或无桌面入口负责消费配置保存后的重载标记。"""
    return (distribution.standalone() or os.environ.get("PEACH_TRAY_MANAGED") == "1"
            or os.environ.get("PEACH_HEADLESS_MANAGED") == "1")


def tunnel_forwarded(request: Request) -> bool:
    """隧道转发请求按公网来源处理。"""
    return tunnel.from_edge(getattr(request.app.state, "tunnel", None), request.headers)


def local_client(request: Request) -> bool:
    """桌面限本机，Docker 允许本机与私有网络，拒绝代理转发。"""
    if not request.client or tunnel_forwarded(request):
        return False
    server = request.scope.get("server")
    try:
        peer = ipaddress.ip_address(request.client.host)
        bound = ipaddress.ip_address(server[0]) if server else None
    except ValueError:
        bound = None
        try:
            peer = ipaddress.ip_address(request.client.host)
        except ValueError:
            return False
    if os.environ.get("PEACH_HEADLESS_MANAGED") == "1":
        if any(header.startswith("x-forwarded-") or header in {"forwarded", "cf-connecting-ip"}
               for header in request.headers):
            return False
        return peer.is_loopback or (peer.is_private and not any((
            peer.is_link_local, peer.is_reserved, peer.is_unspecified, peer.is_multicast,
        )))
    if not peer.is_loopback and (peer != bound or peer.is_unspecified):
        return False
    if managed_configuration():
        name = request.app.state.settings.mdns_name.lower().removesuffix(".local")
        hosts = {"127.0.0.1", "localhost", "::1", f"{name}.local"}
        if bound and not bound.is_unspecified:
            hosts.add(str(bound))
        if (request.url.hostname or "").lower().rstrip(".") not in hosts:
            return False
    return True
