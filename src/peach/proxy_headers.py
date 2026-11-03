"""保留代理连接的传输身份，再由 Uvicorn 处理转发头。"""
from __future__ import annotations

import os

from starlette.types import ASGIApp, Receive, Scope, Send
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware


class ConfigurationProxyHeadersMiddleware:
    """供显式开启公网管理的无桌面入口使用，外层不能再处理代理头。"""

    def __init__(self, app: ASGIApp):
        self.app = ProxyHeadersMiddleware(app, trusted_hosts=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1,::1"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in {"http", "websocket"}:
            scope = {**scope, "peach.transport_client": scope.get("client")}
        await self.app(scope, receive, send)
