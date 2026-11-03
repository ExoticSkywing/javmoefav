"""本机配置的 JSON 契约：读取、校验、原子保存与托盘重启请求。

页面整个是 `frontend/src/react/settings/` 下的 React 子树（入口 `configuration-page.tsx`），
挂在主站的 `/configuration` 路由里（ADR-0031）；这里只回数据。桌面由托盘管理，无桌面服务由专用入口管理；调用方范围与配置写入都在服务端校验。
桌面部署只允许本机管理；Docker 部署还允许私有网络与显式授权的 HTTPS 反代客户端管理，均须登录。
`/healthz` 的 `configurable` 只控制入口显隐；这里负责实际访问检查。
"""
from __future__ import annotations

from dataclasses import replace
from collections import deque
import hashlib
import ipaddress
import os
import shutil
import threading
import json
import time
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from filelock import FileLock, Timeout

from . import (access, data_storage, distribution, entry_links, error_reporting, folder_picker, media_libraries, onboarding,
               push_discovery, settings_file, media_configuration, tunnel, web_downloads)
from .routes_auth import require_auth, require_authenticated_client, same_origin
from .web_entry import runtime_fact_entries
from .web_local_access import configuration_client, local_client, managed_configuration
from . import release_updates, standalone_update, peach_proxy, desktop_startup, desktop_uninstall

router = APIRouter()
_SAVE_LOCK = threading.Lock()
RELOAD_NAME = onboarding.RELOAD_NAME
#: 直接由 CLI 管理的服务使用设置文件。
FILE_MANAGED_NOTICE = "这个部署由配置文件管理服务；在本机编辑下方的设置文件。"


def dev_environment() -> bool:
    """调试用的裸 serve：`--no-auth` 启动时由 CLI 置上 `PEACH_DEV=1`。

    未过初始配置、也没有托盘接管时，配置页不该再要求「先在托管主机上打开」——
    调试期间的这台本身就是主机。这个标记只免掉「托盘接管且已配置」那两条前提，
    本机调用方那一条仍要成立：环境变量会被子进程继承，光凭它放行等于把配置写
    接口交给能连上这个端口的任何设备。保存后的重载由重启这份服务的调用方负责。"""
    return os.environ.get("PEACH_DEV") == "1"


def revision(config) -> str:
    return hashlib.sha256(config.path.read_bytes()).hexdigest()


def local_only(request: Request) -> None:
    if not configuration_client(request):
        raise HTTPException(403, "请在运行 Peach 的电脑上打开配置")


@router.get("/api/diagnostics")
def system_diagnostics(request: Request, args: dict[str, str] = Depends(require_auth)):
    """本机诊断与 doctor JSON 共用报告；媒体来源只读后台快照。"""
    from . import diagnostics
    if not configuration_client(request):
        raise HTTPException(403, "请在运行 Peach 的电脑上打开系统诊断")
    return diagnostics.report(request.app.state.settings, request.app.state.mount_reachability.summary())


@router.get("/api/diagnostics/bundle")
def diagnostic_bundle(request: Request, args: dict[str, str] = Depends(require_auth)):
    from . import diagnostic_context, diagnostics, support_bundle
    local_only(request)
    try:
        report = diagnostics.report(request.app.state.settings, request.app.state.mount_reachability.summary())
    except Exception as error:
        from .error_reporting import event
        event("diagnostics-report", error)
        report = None
    browser = diagnostic_context.browser_header(request.headers.get('x-peach-browser-diagnostics', ''),
                                                 user_agent=request.headers.get('user-agent', ''))
    from .error_reporting import local_event
    local_event('browser-context', browser=browser, user_agent=browser.get('user_agent', ''))
    return Response(support_bundle.bundle_bytes(report=report, browser=browser, include_scraping=False), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="peach-support.zip"',
                             "Cache-Control": "no-store"})


@router.get('/api/diagnostics/exports')
def diagnostic_export_status(request: Request, _args=Depends(require_auth)):
    from .diagnostic_exports import manager
    local_only(request)
    return manager(request).snapshot()


@router.post('/api/diagnostics/exports')
def diagnostic_export_start(request: Request, body: dict = Body(default_factory=dict), _args=Depends(require_auth)):
    from . import diagnostic_context, diagnostic_exports, diagnostics
    local_only(request)
    same_origin(request)
    kind, codes = body.get('kind'), body.get('codes', '')
    if not isinstance(codes, str):
        raise HTTPException(400, '请填写有效番号')
    browser = diagnostic_context.browser_header(request.headers.get('x-peach-browser-diagnostics', ''),
                                                 user_agent=request.headers.get('user-agent', ''))
    try:
        return diagnostic_exports.manager(request).start(kind, codes, browser=browser,
            report=lambda: diagnostics.report(request.app.state.settings, request.app.state.mount_reachability.summary()))
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@router.post('/api/diagnostics/exports/{identity}/cancel')
def diagnostic_export_cancel(request: Request, identity: str, _args=Depends(require_auth)):
    from .diagnostic_exports import manager
    local_only(request)
    same_origin(request)
    try:
        return manager(request).cancel(identity)
    except ValueError as error:
        raise HTTPException(409, str(error)) from error


@router.get('/api/diagnostics/exports/{identity}/download')
def diagnostic_export_download(request: Request, identity: str, _args=Depends(require_auth)):
    from .diagnostic_exports import manager
    from .streaming import BufferedFileResponse
    local_only(request)
    try:
        path, name = manager(request).download(identity)
    except FileNotFoundError as error:
        raise HTTPException(404, str(error)) from error
    return BufferedFileResponse(path, filename=name, media_type='application/zip', headers={'Cache-Control': 'no-store'})


_CLIENT_ERROR_LOCK = threading.Lock()


def _client_error_budget(request: Request) -> None:
    with _CLIENT_ERROR_LOCK:
        recent = getattr(request.app.state, 'client_error_times', deque(maxlen=20))
        request.app.state.client_error_times = recent
        now = time.monotonic()
        while recent and now - recent[0] >= 60:
            recent.popleft()
        if len(recent) >= 20:
            raise HTTPException(429, '错误记录过于频繁')
        recent.append(now)


def _record_browser_context(request: Request, context: dict) -> bool:
    """同一份环境每分钟保留一次，环境快照独立于错误记录预算。"""
    from .error_reporting import local_event
    key = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
    with _CLIENT_ERROR_LOCK:
        recent = getattr(request.app.state, 'client_context_times', deque(maxlen=64))
        request.app.state.client_context_times = recent
        now = time.monotonic()
        while recent and now - recent[0][0] >= 60:
            recent.popleft()
        if any(saved == key for _, saved in recent):
            return False
        if local_event('browser-context', **context) is None:
            raise HTTPException(503, '错误日志无法写入')
        recent.append((now, key))
    return True


@router.post("/api/diagnostics/client-error")
async def client_error(request: Request):
    """浏览器错误取证；本机首启与登录页允许上报，远程须登录。"""
    from . import error_reporting
    same_origin(request)
    if not local_client(request):
        require_authenticated_client(request)
    body = bytearray()
    async for part in request.stream():
        body.extend(part)
        if len(body) > 16 * 1024:
            raise HTTPException(413, "错误记录过长")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "错误记录格式无效") from None
    if not isinstance(data, dict) or not isinstance(data.get("message"), str):
        raise HTTPException(400, "错误记录缺少原因")
    fields = {key: value[:6000] for key in ("message", "stack", "kind", "page", "source_file", "error_name")
              if isinstance(value := data.get(key), str)}
    fields.update({key: value for key in ('line', 'column')
                   if type(value := data.get(key)) is int and value >= 0})
    identities = data.get('bundle_debug_ids')
    if isinstance(identities, dict):
        from .diagnostic_browser import shipped
        fields['bundle_debug_ids'] = {key: value for key, value in identities.items()
            if shipped(key) and isinstance(value, str) and len(value) == 36}
    fields['user_agent'] = request.headers.get('user-agent', '')[:512]
    from . import diagnostic_context
    context = {'browser': diagnostic_context.browser(data.get('browser'), user_agent=fields['user_agent'])}
    if data.get('kind') == 'context':
        return {'recorded': _record_browser_context(request, context)}
    _client_error_budget(request)
    if isinstance(data.get('playback'), dict):
        context['playback'] = diagnostic_context.playback(data['playback'])
        recorded = error_reporting.local_event('browser', **fields, **context)
    else:
        recorded = error_reporting.event('browser', **fields)
        error_reporting.local_event('browser-context', **context)
    if recorded is None:
        raise HTTPException(503, "错误日志无法写入")
    return {"recorded": True}


def configurable(request: Request) -> bool:
    """已配置的托管服务向获准的管理客户端开放配置入口。"""
    if dev_environment():
        return configuration_client(request)
    return (managed_configuration() and bool(request.app.state.settings.configured)
            and configuration_client(request))


def _read_section(result: dict, key: str, title: str, reader) -> None:
    """各配置区域独立读取；故障留痕并提供重试信息。"""
    try:
        result[key] = reader()
    except Exception as error:
        error_id = uuid.uuid4().hex
        result.setdefault("section_errors", {})[key] = {
            "title": f"{title}未取得", "message": "请重新读取；持续失败时导出诊断报告。",
            "error_id": error_id,
        }
        error_reporting.event("logging", error, logger=__name__, level="ERROR",
                              message=f"配置区域 {key} 读取失败", section=key, error_id=error_id)


def snapshot(config) -> dict[str, Any]:
    """配置页首屏要的一切：当前值、修订号、可写与否，以及这台机器的运行信息。"""
    editable = managed_configuration()
    from . import remote_reporting, library_sharing
    media = config.mounts.get("local") or config.locations.get("local", ())
    result = {
        "editable": editable,
        "notice": "" if editable else FILE_MANAGED_NOTICE,
        "revision": revision(config),
        "media_dirs": list(media),
        # 媒体库按持久身份计数，与侧栏切换器和 `/api/libraries` 共用分组。
        "library_count": 0,
        "windows": os.name == "nt",
        "port": config.server.port,
        "port_editable": distribution.standalone(),
        "facts": [],
    }
    readers = (
        ("remote_reporting", "错误诊断设置", lambda: remote_reporting.snapshot(config)),
        ("library_sharing", "馆藏上传设置", lambda: library_sharing.snapshot(config)),
        ("startup", "开机启动设置", lambda: desktop_startup.snapshot(config)),
        ("uninstall", "卸载信息", lambda: desktop_uninstall.snapshot(config)),
        ("storage", "存储空间", lambda: data_storage.snapshot(config)),
        ("peach_proxy", "Peach 代理", lambda: peach_proxy.describe(config.directory("secrets"))),
        ("entry_links", "外部入口", lambda: entry_links.snapshot(config.directory("state"))),
        ("updates", "版本更新", release_updates.snapshot),
        ("update_job", "更新任务", standalone_update.public),
        ("access", "访问设置", lambda: access.public(access.load(config.directory("secrets") / "access.json"))),
        ("media_sources", "媒体目录", lambda: media_configuration.rows(config, windows=os.name == "nt", probe=True)),
        ("library_count", "媒体库状态", lambda: len(media_libraries.libraries(config))),
        ("mount_dependencies", "挂载依赖", media_configuration.mount_dependencies),
        ("facts", "运行信息", lambda: runtime_fact_entries(config)),
    )
    for key, title, reader in readers:
        _read_section(result, key, title, reader)
    return result


def tunnel_payload(config, state: tunnel.TunnelSnapshot, enabled: bool) -> dict[str, Any]:
    """读接口和写回接口用同一份形状。

    页面收到写回响应后整块替换本地状态，少一个字段就等于把它置空：`available`
    缺席时「找不到 cloudflared」会和刚拿到的随机链接一起显示。
    """
    return {
        "enabled": enabled,
        "state": state.state,
        "url": state.url,
        "error": state.error,
        "available": tunnel.resolve_binary(config.tunnel.binary) is not None,
        "mode": (getattr(config.tunnel, "mode", "") or tunnel.QUICK_MODE).strip().lower(),
        "hostname": getattr(config.tunnel, "hostname", ""),
        # 令牌是凭据，只回报存没存过。页面据此显示「已保存」，不回显任何字符。
        "token_set": bool((getattr(config.tunnel, "token", "") or "").strip()),
        # 命名隧道要一份自建隧道的后台配置，独立包给不出，这一块在那里根本不渲染。
        "named_available": not distribution.standalone(),
    }


def push_discovery_payload(request: Request, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """推送发现的状态，外加一段能整个抄进 CloudDrive2 的配置。

    读接口和两条写回接口用同一份形状：页面收到写回响应后整块替换本地状态，这里少一个
    字段就等于把刚换完的密钥那段配置置空。

    地址不取这次请求的 origin：配置页多半是从回环地址打开的，而 TLS 那条服务只绑在
    局域网地址上，把 `127.0.0.1` 抄过去 CloudDrive2 连不上。取这台机器对外公布的那个
    地址，也就是 mDNS 登记的同一个。协议与端口取实际应用服务的设置；独立版的局域网
    服务使用 HTTP，启用 TLS 的服务使用 HTTPS。不知道自己的地址时给空串。
    """
    if payload is None:
        payload = request.app.state.push_discovery.snapshot(reveal=True)
    mdns = getattr(request.app.state, "mdns", None)
    settings = request.app.state.settings
    address = str(getattr(mdns, "address", "") or settings.mdns_address or "").strip()
    port = int(settings.mdns_port or 0)
    origin = ""
    if address:
        scheme, default_port = ("https", 443) if settings.tls_enabled else ("http", 80)
        origin = str(httpx.URL(scheme=scheme, host=address, port=port or default_port))
    payload["origin"] = origin
    payload["config_toml"] = push_discovery.clouddrive_config(origin, payload.get("secret", ""))
    return payload


def network_payload(request: Request, config) -> dict[str, Any]:
    """连接地址来自实际监听信息，编辑值来自托盘配置。"""
    settings = request.app.state.settings
    standalone = distribution.standalone()
    try:
        local = ipaddress.ip_address(settings.host).is_loopback
    except ValueError:
        local = settings.host.lower() == 'localhost'
    scheme = 'https' if settings.tls_enabled else 'http'
    port = settings.mdns_port if settings.mdns_enabled else settings.port
    suffix = '' if port == (443 if settings.tls_enabled else 80) else f':{port}'
    mdns = getattr(request.app.state, 'mdns', None)
    address = str(getattr(mdns, 'address', '') or settings.mdns_address or '')
    try:
        ip = ipaddress.ip_address(address)
        address = f'[{ip}]' if ip.version == 6 else str(ip)
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
            address = ''
    except ValueError:
        address = ''
    hostname = settings.mdns_name.removesuffix('.local')
    return {'editable': managed_configuration() and standalone,
            'host': config.server.host, 'mdns_name': config.server.mdns_name,
            'scope': 'local' if local else 'lan',
            'local_url': f'http://127.0.0.1:{settings.port}/' if standalone else str(request.base_url),
            'lan_url': f'{scheme}://{hostname}.local{suffix}/' if not local and settings.mdns_enabled else '',
            'ip_url': f'{scheme}://{address}{suffix}/' if not local and address and not settings.tls_enabled else ''}


@router.get("/api/configuration")
def read_configuration(request: Request, _args=Depends(require_auth)):
    local_only(request)
    config = settings_file.load_config()
    if not config.present:
        raise HTTPException(409, "请先完成首次设置")
    result = snapshot(config)
    _read_section(result, 'network', '访问地址', lambda: network_payload(request, config))
    sync = getattr(request.app.state, "sync", None)
    result["ledger_read_only"] = bool(sync is not None and sync.read_only)
    _read_section(result, "tunnel", "公网入口", lambda: tunnel_payload(
        config, request.app.state.tunnel.snapshot(), config.tunnel.enabled))
    _read_section(result, "automatic_updates", "自动更新", lambda: request.app.state.automatic_updates.snapshot())
    # 这一路已经过了 `local_only`，密钥可以给出来：用户要把它抄进 CloudDrive2。
    _read_section(result, "push_discovery", "推送发现", lambda: push_discovery_payload(request))
    _read_section(result, "downloads", "下载设置", lambda: web_downloads.settings_payload(*_downloads(request)))
    if result.get("automatic_updates", {}).get("result"):
        result["updates"] = result["automatic_updates"]["result"]
    return result


@router.get("/api/configuration/automatic-updates")
def read_automatic_updates(request: Request, _args=Depends(require_auth)):
    local_only(request)
    return request.app.state.automatic_updates.snapshot()


@router.post("/api/configuration/remote-reporting")
def save_remote_reporting(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    from . import remote_reporting
    try:
        return remote_reporting.save(body)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@router.get("/api/configuration/library-sharing/preview")
def preview_library_sharing(request: Request, _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    try:
        return JSONResponse(request.app.state.library_sharing.preview(), headers={"Cache-Control": "no-store"})
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@router.post("/api/configuration/library-sharing")
def save_library_sharing(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    try:
        return request.app.state.library_sharing.save(body)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@router.post("/api/configuration/automatic-updates")
def save_automatic_updates(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    try:
        return request.app.state.automatic_updates.save(body)
    except (ValueError, OSError, Timeout) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/peach-proxy")
def save_peach_proxy(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    try:
        saved = peach_proxy.save(settings_file.load_config().directory("secrets"), body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    request.app.state.network_reachability.refresh()
    return saved


@router.get("/api/network-status")
def network_status(request: Request, _args=Depends(require_auth)):
    """外网连通的后台快照；探测按 Peach 代理设置出网，请求本身不出网。

    探测线程在第一次有页面来读时才启动：没人打开界面的实例不出这份流量。
    """
    monitor = request.app.state.network_reachability
    monitor.start()
    return monitor.summary()


@router.post("/api/network-status/check")
def network_status_check(request: Request, _args=Depends(require_auth)):
    """当场再探一次外网，回探完的快照。任务中心「网络不通」那一行的「立即重试」走这里。"""
    monitor = request.app.state.network_reachability
    monitor.start()
    monitor.tick()
    return monitor.summary()


@router.post("/api/configuration/entry-links")
def save_entry_links(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    try:
        return entry_links.save(settings_file.load_config().directory("state"), body)
    except (ValueError, OSError, Timeout) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/push-discovery")
def save_push_discovery(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    try:
        return push_discovery_payload(request, request.app.state.push_discovery.save(body))
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/push-discovery/secret")
def rotate_push_discovery_secret(request: Request, _args=Depends(require_auth)):
    """换一份共享密钥。换完之后 CloudDrive2 那一侧要跟着填新的，否则它推来的一律被拒。"""
    local_only(request)
    same_origin(request)
    try:
        return push_discovery_payload(request, request.app.state.push_discovery.rotate_secret())
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


def _downloads(request: Request):
    """取得云下载服务，以及推送发现使用的同一份数据库路径前缀配置。"""
    return (request.app.state.downloads,
            getattr(request.app.state.push_discovery, "declared_roots", {}))


@router.get("/api/configuration/cloud-proxies")
def read_cloud_proxies(request: Request, _args=Depends(require_auth)):
    from . import clouddrive_proxy
    from .downloads import DownloadError
    local_only(request)
    try:
        result = clouddrive_proxy.read(settings_file.load_config())
    except DownloadError:
        raise HTTPException(502, "无法读取 CloudDrive2 代理配置，请检查连接和令牌权限") from None
    except (ValueError, OSError) as error:
        raise HTTPException(400, str(error)) from None
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.post("/api/configuration/cloud-proxies")
def save_cloud_proxies(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    from . import clouddrive_proxy
    from .downloads import DownloadError
    local_only(request)
    same_origin(request)
    try:
        result = clouddrive_proxy.save(settings_file.load_config(), body)
    except clouddrive_proxy.ProxyConflict as error:
        raise HTTPException(409, str(error)) from None
    except DownloadError:
        raise HTTPException(502, "未能确认 CloudDrive2 已保存，请重新读取配置后核对") from None
    except (ValueError, OSError) as error:
        raise HTTPException(400, str(error)) from None
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("/api/configuration/indexers")
def get_indexers(request: Request, _args=Depends(require_auth)):
    from .resource_search import Indexers
    local_only(request)
    try:
        return Indexers(request.app.state.downloads.credentials).public()
    except (ValueError, OSError):
        raise HTTPException(400, "索引器配置读不出来") from None


@router.post("/api/configuration/indexers")
def save_indexers(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    from .resource_search import Indexers
    local_only(request)
    same_origin(request)
    try:
        return Indexers(request.app.state.downloads.credentials).save(body)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
    except OSError:
        raise HTTPException(400, "索引器配置没有保存，请检查本机凭据目录权限") from None


@router.post("/api/configuration/downloads")
def save_downloads(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    """地址、目标目录、等待上限与 CloudDrive2 令牌。令牌只写本机凭据文件。

    有令牌时随响应回一份按已保存配置做的检查报告；115 目标目录留空时按推送发现填上。"""
    local_only(request)
    same_origin(request)
    service, roots = _downloads(request)
    try:
        return web_downloads.save_settings(service, body, roots)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/api/configuration/downloads/check")
def check_saved_downloads(request: Request, _args=Depends(require_auth)):
    """按已保存的地址、令牌与目录检查，页面打开时用。令牌只从本机凭据文件取，不经页面。"""
    local_only(request)
    service, _roots = _downloads(request)
    try:
        return web_downloads.check_clouddrive(service, {})
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/downloads/check")
def check_downloads(request: Request, body: dict = Body(default={}), _args=Depends(require_auth)):
    """调 CloudDrive2 的 `GetApiTokenInfo` 等只读接口：离线权限、目标目录、115 剩余配额，
    目标目录与 PikPak 根留空时按推送发现推建议值。"""
    local_only(request)
    same_origin(request)
    service, _roots = _downloads(request)
    try:
        return web_downloads.check_clouddrive(service, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/downloads/folder")
def create_download_folder(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    """调 CloudDrive2 的 `CreateFolder` 建 115 目标目录。只在用户点「新建这个目录」时发。"""
    local_only(request)
    same_origin(request)
    service, _roots = _downloads(request)
    try:
        return web_downloads.create_clouddrive_folder(service, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/downloads/pikpak/login")
def login_pikpak(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    service, roots = _downloads(request)
    try:
        return web_downloads.pikpak_login(service, body, roots)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/downloads/pikpak/browser-login")
def start_pikpak_browser_login(request: Request, _args=Depends(require_auth)):
    """拉起 PikPak 登录窗口（ADR-0093），立刻回设置块；登录在后台等，页面轮询下面那条读接口。"""
    local_only(request)
    same_origin(request)
    service, roots = _downloads(request)
    try:
        return web_downloads.pikpak_browser_start(service, roots)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/api/configuration/downloads/pikpak/browser-login")
def pikpak_browser_login_status(request: Request, _args=Depends(require_auth)):
    local_only(request)
    service, roots = _downloads(request)
    return web_downloads.settings_payload(service, roots)


@router.post("/api/configuration/downloads/pikpak/browser-login/cancel")
def cancel_pikpak_browser_login(request: Request, _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    service, roots = _downloads(request)
    return web_downloads.pikpak_browser_cancel(service, roots)


@router.post("/api/configuration/downloads/pikpak/logout")
def logout_pikpak(request: Request, _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    service, roots = _downloads(request)
    return web_downloads.pikpak_logout(service, roots)


@router.post("/api/configuration/startup")
def save_startup(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    try:
        return desktop_startup.save(settings_file.load_config(), enabled=body.get("enabled"), silent=body.get("silent"),
                                    desktop=body.get("desktop"))
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/configuration/uninstall")
def uninstall(request: Request, body: dict = Body(...), _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    if body.get("confirmation") != "卸载 Peach":
        raise HTTPException(400, "请确认卸载 Peach")
    from .jobs import BackgroundJob
    from .task_runs import task_label
    # 写出是哪几个：开机后自动跑的关注、订阅检查不在用户印象里，只说「后台任务」没处可找。
    running = dict.fromkeys(task_label(job.task_key) for job in vars(request.app.state.web_contract).values()
                            if isinstance(job, BackgroundJob) and (job.snapshot() or {}).get("status") == "running")
    if running:
        raise HTTPException(409, f"{'、'.join(running)}正在运行，请在任务中心等它完成或取消后再卸载")
    try:
        return desktop_uninstall.request(settings_file.load_config(), body.get("delete_data"))
    except (ValueError, Timeout) as exc:
        raise HTTPException(409, str(exc)) from exc


def _storage_config():
    config = settings_file.load_config()
    if not config.present:
        raise HTTPException(409, "请先完成首次设置")
    return config


@router.get("/api/configuration/storage")
def read_storage(request: Request, _args=Depends(require_auth)):
    """「存储空间」：数据目录位置、磁盘余量、上次统计的分类占用与迁移状态。"""
    local_only(request)
    return data_storage.snapshot(_storage_config())


@router.post("/api/configuration/storage/measure")
def measure_storage(request: Request, _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    config = _storage_config()
    try:
        data_storage.JOBS.start(config, "measure")
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    return data_storage.snapshot(config)


@router.post("/api/configuration/storage/clean")
def clean_storage(request: Request, body: dict[str, Any] = Body(default_factory=dict),
                  _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    config = _storage_config()
    # 勾选几类一起清理时传 `categories`；单清一类的旧写法 `category` 照收。
    raw = body.get("categories", [body.get("category")])
    categories = raw if isinstance(raw, list) else []
    if not categories or any(not isinstance(key, str) or key not in data_storage.CLEANABLE for key in categories):
        raise HTTPException(400, "这一类不能在这里清理")
    try:
        data_storage.JOBS.start(config, categories)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    return data_storage.snapshot(config)


@router.post("/api/configuration/storage/relocate")
def relocate_storage(request: Request, body: dict[str, Any] = Body(default_factory=dict),
                     _args=Depends(require_auth)):
    """校验新位置并写下迁移请求；托盘接手后停服务、退出，由迁移助手搬家并重新打开。"""
    local_only(request)
    same_origin(request)
    config = _storage_config()
    try:
        return data_storage.request(config, body.get("target"))
    except ValueError as exc:
        raise HTTPException(400, {"message": "无法迁移到这个位置", "errors": {"target": str(exc)}}) from exc
    except Timeout as exc:
        raise HTTPException(409, "迁移请求正在处理") from exc


@router.get("/api/configuration/updates")
def check_updates(request: Request, _args=Depends(require_auth)):
    local_only(request)
    result = release_updates.check()
    request.app.state.automatic_updates.remember(result)
    return result


@router.get('/api/client-updates')
def client_updates(request: Request, _args=Depends(require_auth)):
    from .client_updates import snapshot
    result = snapshot(request.app.state.automatic_updates)
    result['update_job'] = standalone_update.public()
    result['repairs'] = request.app.state.upgrade_repairs.snapshot()
    return result


@router.post('/api/configuration/upgrade-repairs/retry')
async def retry_upgrade_repairs(request: Request, _args=Depends(require_auth)):
    import asyncio
    from .api import _installation_in_progress
    local_only(request)
    same_origin(request)
    try:
        if await asyncio.to_thread(_installation_in_progress, request.app.state.settings.db_path):
            raise ValueError('正在安装更新，请稍后重试')
        service = request.app.state.upgrade_repairs
        activation = getattr(request.app.state, 'ledger_activation', None)
        if activation is not None and not request.app.state.ledger_background_ready:
            if not await activation.resume():
                return service.snapshot()
        await asyncio.to_thread(service.retry)
        return service.snapshot()
    except (ValueError, OSError, Timeout) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get('/api/configuration/upgrade-repairs/review')
def upgrade_repairs_review(request: Request, _args=Depends(require_auth)):
    local_only(request)
    service = request.app.state.upgrade_repairs
    path = service.root / 'catalog-review.json'
    if not path.is_file():
        raise HTTPException(404, '暂无升级复核记录')
    return Response(path.read_bytes(), media_type='application/json',
                    headers={'Content-Disposition': 'attachment; filename="upgrade-review.json"'})


@router.get("/api/configuration/update-status")
def update_status(request: Request, _args=Depends(require_auth)):
    local_only(request)
    return standalone_update.public()


@router.post("/api/configuration/update")
def download_update(request: Request, _args=Depends(require_auth)):
    local_only(request)
    try:
        return standalone_update.start()
    except (ValueError, Timeout) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/api/configuration/update-restart")
def restart_update(request: Request, _args=Depends(require_auth)):
    local_only(request)
    try:
        return standalone_update.request_restart()
    except (ValueError, Timeout) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post('/api/configuration/smb/test')
def test_smb_connection(request: Request, body: dict[str, Any] = Body(default_factory=dict),
                        _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    from .smb_media import address, canonical, credential_store
    from .smb_transport import SmbConnection, SmbTransport
    config = settings_file.load_config()
    try:
        host, share, tail, port = address(canonical(str(body.get('path', ''))))
        values = {}
        key = str(body.get('root_id', ''))
        known = config.storage_roots.get(key)
        if known and known.get('transport') == 'smb' and canonical(known['mount']) == canonical(body['path']):
            credential = credential_store(config).load('smb-' + key)
            values = credential.values if credential else {}
        username = body.get('smb_username', values.get('username', ''))
        password = body.get('smb_password') or (values.get('password', '') if username == values.get('username', '') else '')
        if not isinstance(username, str) or not isinstance(password, str):
            raise ValueError('SMB 账号和密码必须是文字')
        transport = SmbTransport(SmbConnection(host, share, username=username, password=password, port=port,
                                             encrypt=body.get('smb_encrypt') is True, timeout=8))
        try:
            entries = transport.scandir(tail)
        finally:
            transport.close()
        return {'readable': True, 'directories': [entry.name for entry in entries if entry.is_dir and not entry.is_symlink][:500]}
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
    except PermissionError:
        raise HTTPException(403, 'SMB 登录失败或没有读取权限，请检查账号、密码和共享权限') from None
    except OSError:
        raise HTTPException(502, 'SMB 共享无法读取，请检查地址、共享名和网络连接') from None


def _validate(body: dict[str, Any], config) -> tuple[dict[str, Any], dict[str, Any]]:
    """逐项校验，错误按字段归位：文件夹按行、端口一句。全对时第一个返回值为空。"""
    errors: dict[str, Any] = {}
    validated: dict[str, Any] = {}
    from . import media_identity
    raws = body.get("media_dirs")
    rows = [str(item) for item in raws] if isinstance(raws, list) else [str(raws or "")]
    if "media_sources" in body:
        sources = media_configuration.prepare_sources(body["media_sources"], windows=os.name == "nt", config=config)
        locations, mounts, problems = media_configuration.validate(sources, windows=os.name == "nt", config=config)
        paths = []
        validated.update(locations=locations, mounts=mounts)
        if not problems:
            validated["media_costs"] = media_configuration.costs(sources, config, windows=os.name == "nt")
            try:
                prepared = media_identity.configure_sources(config, sources, windows=os.name == "nt")
                validated.update(library_catalog=prepared.library_catalog, storage_roots=prepared.storage_roots,
                                 locations=prepared.locations, mounts=prepared.mounts,
                                 media_costs=prepared.media_costs)
            except ValueError as exc:
                problems = [str(exc)] * len(sources)
        names, icons = {}, {}
        if not problems:
            for index, row in enumerate(sources):
                name = str(row.get("library", "")).strip()
                if len(name) > 80 or any(ord(char) < 32 for char in name):
                    problems = [""] * len(body["media_sources"])
                    problems[index] = "媒体库名称请使用 1 到 80 个可见字符"
                    break
                root = str(media_configuration.PureWindowsPath(row.get('root') or row['path']))
                if name:
                    names[root] = name
                from .media_libraries import LIBRARY_ICONS
                glyph = str(row.get("library_icon", ""))
                if glyph and glyph not in LIBRARY_ICONS:
                    problems = [""] * len(body["media_sources"])
                    problems[index] = "请选择列表中的媒体库图标"
                    break
                if glyph:
                    icons[root] = glyph
            validated["library_names"] = names
            validated["library_icons"] = icons
    else:
        paths, problems = onboarding.read_media_dirs(
            rows, validate=onboarding.media_dir_validator(windows=os.name == "nt"))
        if not problems:
            sources = media_identity.sources_for_paths(config, paths, windows=os.name == "nt", keep_other_sources=True)
            try:
                prepared = media_identity.configure_sources(config, sources, windows=os.name == "nt")
                validated.update(locations=prepared.locations, mounts=prepared.mounts,
                                 library_catalog=prepared.library_catalog, storage_roots=prepared.storage_roots,
                                 library_names=prepared.library_names, library_icons=prepared.library_icons,
                                 media_costs=prepared.media_costs)
            except ValueError as exc:
                problems = [str(exc)] * max(1, len(rows))
    if problems:
        errors["media_dirs"] = problems
    else:
        validated["media_dirs"] = paths
    server_errors, server_values = _validate_server(body, config)
    errors.update(server_errors)
    validated.update(server_values)
    return errors, validated


def _validate_server(body, config):
    """端口、监听范围和局域网名称按运行方式校验。"""
    errors, validated = {}, {}
    try:
        port = onboarding.validate_port(str(body.get("port", config.server.port)))
        if distribution.standalone():
            onboarding.check_available_port(port, config.server.port)
        elif port != config.server.port:
            raise ValueError("访问端口由托盘管理")
        validated["port"] = port
    except ValueError as exc:
        errors["port"] = str(exc)
    for field, validator in (('host', onboarding.validate_host), ('mdns_name', onboarding.validate_mdns_name)):
        if field not in body:
            continue
        try:
            if not isinstance(body[field], str):
                raise ValueError('请选择访问范围' if field == 'host' else '请填写局域网名称')
            value = validator(body[field])
            if not distribution.standalone() and value != getattr(config.server, field):
                raise ValueError('访问范围与名称由服务启动配置管理')
            validated[field] = value
        except ValueError as exc:
            errors[field] = str(exc)
    return errors, validated


def _close_tunnel_without_password(request: Request) -> str:
    """没有访问密码就不能留着公网入口；这里当场停掉并把开关写回关闭。

    启动前的检查挡不住这条路径：隧道是在有密码时起来的，密码被关掉之后它还在转发。
    """
    manager = getattr(request.app.state, "tunnel", None)
    if manager is None:
        return ""
    try:
        state = manager.snapshot().state
    except (AttributeError, OSError, ValueError):
        return ""
    if state not in {"starting", "running"}:
        return ""
    manager.stop()
    try:
        config = settings_file.load_config()
        if config.present and config.tunnel.enabled:
            with FileLock(str(config.path.with_suffix(".lock")), timeout=0):
                settings_file.write(
                    replace(config, tunnel=replace(config.tunnel, enabled=False)),
                    force=True,
                )
    except (Timeout, OSError, ValueError):
        return "临时远程链接已停止；设置文件未能写入，请在本机检查设置文件。"
    return "已停止临时远程链接：没有访问密码时不保留公网入口。"


@router.post("/api/configuration/access")
def save_access(request: Request, body: dict[str, Any] = Body(default_factory=dict),
                _args=Depends(require_auth)):
    local_only(request)
    same_origin(request)
    path = request.app.state.settings.access_path
    if not request.app.state.settings.configured or path is None:
        raise HTTPException(409, "请先完成首次设置")
    if any(not isinstance(body.get(key, ""), str) for key in ("password", "confirmation", "current_password")):
        raise HTTPException(400, "密码需要是文字")
    password = body.get("password", "")
    if body.get("action") not in {"set", "disable"}:
        raise HTTPException(400, "请选择设置或关闭密码")
    if body["action"] == "set" and not password:
        raise HTTPException(400, {"message": "请输入访问密码", "errors": {"password": "请输入访问密码"}})
    if body["action"] == "disable" and body.get("confirm_disable") is not True:
        raise HTTPException(400, "关闭访问密码前先勾选确认")
    try:
        try:
            access.validate_password(password, body.get("confirmation", ""))
        except ValueError as exc:
            field = "confirmation" if password != body.get("confirmation", "") else "password"
            raise HTTPException(400, {"message": str(exc), "errors": {field: str(exc)}}) from exc
        path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(str(path.with_suffix(".lock")), timeout=0):
            policy = access.load(path)
            if body.get("revision") != policy["revision"]:
                raise HTTPException(409, "访问设置已变更，请刷新后再保存")
            if policy["mode"] == "locked":
                raise HTTPException(409, "访问设置无法读取，请在本机检查配置文件")
            if policy["mode"] == "password" and not access.verify(policy, body.get("current_password", "")):
                raise HTTPException(400, {"message": "当前访问密码不正确", "errors": {"current_password": "当前访问密码不正确"}})
            policy = access.save(path, password if body["action"] == "set" else "")
    except Timeout:
        raise HTTPException(409, "访问设置正在保存，请稍后重试") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    payload = access.public(policy)
    if policy["mode"] != "password":
        notice = _close_tunnel_without_password(request)
        if notice:
            payload["tunnel_notice"] = notice
    response = JSONResponse(payload, headers={"Cache-Control": "no-store"})
    response.delete_cookie("tok", path="/")
    response.delete_cookie(access.COOKIE, path="/")
    if policy["mode"] == "password":
        from .routes_auth import set_auth_cookie
        set_auth_cookie(response, request, login=True)
    return response


def tunnel_changes(config, body: dict[str, Any]) -> dict[str, Any]:
    """从写回请求里取出隧道形态，缺席的键保持设置文件里的现值。

    令牌不回显，页面也就交不回原值：空串一律当作「不改」，要换只能提交一个新的。
    命名隧道在独立包里没有着落点，这里当场拒绝，不让它先落盘再在启动时失败。
    """
    changes: dict[str, Any] = {}
    for key in ("mode", "hostname", "token"):
        if key in body and not isinstance(body[key], str):
            raise HTTPException(400, f"{key} 必须是文字")
    try:
        if "mode" in body:
            changes["mode"] = tunnel.normalize_mode(body["mode"])
        if body.get("hostname", "").strip():
            changes["hostname"] = tunnel.normalize_hostname(body["hostname"])
    except tunnel.TunnelError as exc:
        field = "mode" if "mode" in body and "mode" not in changes else "hostname"
        raise HTTPException(400, {"message": str(exc), "errors": {field: str(exc)}}) from exc
    if body.get("token", "").strip():
        changes["token"] = body["token"].strip()
    mode = changes.get("mode") or (getattr(config.tunnel, "mode", "") or tunnel.QUICK_MODE)
    if mode == tunnel.NAMED_MODE and distribution.standalone():
        raise HTTPException(400, tunnel.STANDALONE_NAMED_ERROR)
    return changes


@router.post("/api/configuration/tunnel")
def save_tunnel(request: Request, body: dict[str, Any] = Body(default_factory=dict),
                _args=Depends(require_auth)):
    """保存隧道形态并启动或停止它；入口只对本机配置页开放。"""
    local_only(request)
    same_origin(request)
    config = settings_file.load_config()
    if not config.present:
        raise HTTPException(409, "请先完成首次设置")
    if body.get("revision") != revision(config):
        raise HTTPException(409, "设置已变更，请刷新后再保存")
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        raise HTTPException(400, "enabled 必须是 true 或 false")
    updated = replace(
        config, tunnel=replace(config.tunnel, enabled=enabled, **tunnel_changes(config, body)),
    )
    manager = request.app.state.tunnel
    state = tunnel.TunnelSnapshot(state="stopped")
    started_here = False
    if enabled:
        settings = request.app.state.settings
        try:
            existing = manager.snapshot()
            started_here = existing.state not in {"starting", "running"}
            # 计划按这次提交的形态构造，不是磁盘上那一份：模式和主机名可能就是本次改的。
            plan = tunnel.plan_for_config(
                updated,
                access_path=settings.access_path,
                token=settings.token,
                standalone_mode=getattr(settings, "tunnel_standalone", distribution.standalone()),
                lan_address=getattr(settings, "tunnel_lan_address", None),
                https_port=getattr(settings, "tunnel_origin_port", None),
                tls_enabled=getattr(settings, "tls_enabled", True),
            )
            state = manager.start(plan)
        except tunnel.TunnelError as exc:
            raise HTTPException(409, str(exc)) from exc
    try:
        with FileLock(str(config.path.with_suffix(".lock")), timeout=0):
            current = settings_file.load_config()
            if revision(current) != revision(config):
                if started_here:
                    manager.stop()
                raise HTTPException(409, "设置已变更，请刷新后再保存")
            settings_file.write(updated, force=True)
    except Timeout:
        if started_here:
            manager.stop()
        raise HTTPException(409, "设置正在保存，请稍后重试") from None
    except OSError as exc:
        if started_here:
            manager.stop()
        raise HTTPException(500, f"设置写入失败：{exc}") from exc
    if not enabled:
        state = manager.stop()
    return {**tunnel_payload(updated, state, enabled), "revision": revision(updated)}


@router.post("/api/pick-folder")
def pick_folder(request: Request, body: dict[str, Any] = Body(default_factory=dict),
                _args=Depends(require_auth)):
    """让运行 Peach 的这台电脑弹系统文件夹对话框，选中的绝对路径交回页面。

    只对本机连接开放：系统对话框显示在运行 Peach 的电脑上。首启页和配置页共用这一条，
    所以不要求独立包。对话框是模态的，一次只开一个；用户取消时 `path` 为 None。
    """
    local_only(request)
    same_origin(request)
    initial = body.get("initial")
    try:
        path = folder_picker.pick_folder(initial if isinstance(initial, str) and initial else None)
    except folder_picker.PickerBusy as exc:
        raise HTTPException(409, str(exc)) from exc
    except folder_picker.PickerUnavailable as exc:
        raise HTTPException(501, str(exc)) from exc
    return {"path": path}


@router.post("/api/configuration")
def save_configuration(request: Request, body: dict[str, Any] = Body(default_factory=dict),
                       _args=Depends(require_auth)):
    local_only(request)
    if not managed_configuration():
        raise HTTPException(409, "此部署通过配置文件管理服务")
    same_origin(request)
    with _SAVE_LOCK:
        config = settings_file.load_config()
        if not config.present:
            raise HTTPException(409, "请先完成首次设置")
        if body.get("revision") != revision(config):
            raise HTTPException(409, "配置已变更，请刷新后再保存")
        errors, validated = _validate(body, config)
        if errors:
            # 400 的响应体带每个字段的原因：页面把它写回出错的那一行底下，不是弹一句总话。
            raise HTTPException(400, {"message": "有几项需要修改", "errors": errors})
        paths = validated["media_dirs"]
        locations, mounts = dict(config.locations), dict(config.mounts)
        if "locations" in validated:
            locations, mounts = validated["locations"], validated["mounts"]
            for key in set(config.locations) - dict(media_configuration.SOURCE_OPTIONS).keys():
                locations[key] = config.locations[key]
                if key in config.mounts:
                    mounts[key] = config.mounts[key]
        elif os.name == "nt":
            locations["local"] = tuple(str(path) for path in paths)
        else:
            sources = media_configuration.prepare_sources(
                [{"location": "local", "path": str(path)} for path in paths], windows=False, config=config)
            local_roots, local_mounts, problems = media_configuration.validate(sources, windows=False, config=config)
            if problems:
                raise HTTPException(400, {"message": "有几项需要修改", "errors": {"media_dirs": problems}})
            locations["local"], mounts["local"] = local_roots["local"], local_mounts["local"]
            validated["library_names"] = {**config.library_names, **{
                row["root"]: row["library"] for row in sources if row.get("library")}}
        prepared = replace(config, locations=locations, mounts=mounts,
                           library_catalog=validated.get("library_catalog", config.library_catalog),
                           storage_roots=validated.get("storage_roots", config.storage_roots),
                           library_names=validated.get("library_names", config.library_names),
                           library_icons=validated.get("library_icons", config.library_icons),
                           media_costs=validated.get("media_costs", config.media_costs),
                           server=replace(config.server, port=validated["port"],
                                          host=validated.get('host', config.server.host),
                                          mdns_name=validated.get('mdns_name', config.server.mdns_name)))
        if prepared.storage_roots:
            from . import media_identity
            prepared = media_identity.project(prepared)
        temporary = config.path.with_suffix(".pending.toml")
        try:
            shutil.copy2(config.path, config.path.with_suffix(".previous.toml"))
            settings_file.keep_pre_identity_backup(config.path)
            temporary.write_text(settings_file.render(prepared), encoding="utf-8")
            from .smb_media import credential_transaction
            with credential_transaction(prepared, body.get('media_sources', [])):
                os.replace(temporary, config.path)
            if body.get("scan_now"):
                onboarding.request_first_scan(prepared, "configured")
            config.directory("state").mkdir(parents=True, exist_ok=True)
            (config.directory("state") / RELOAD_NAME).write_text("reload", encoding="utf-8")
        except OSError as exc:
            raise HTTPException(500, f"配置保存失败：{exc}") from exc
    url = f"http://127.0.0.1:{prepared.server.port}/" if distribution.standalone() else str(request.base_url)
    return {"saved": True, "url": url,
            "revision": revision(prepared)}
