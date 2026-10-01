"""Minimal client for the GNS3 v3 controller REST API.

GNS3 3.x controllers expose a `/v3`-prefixed REST API secured with JWT
bearer tokens (`POST /v3/access/users/login`), which is a different scheme
from the GNS3 v2 API (HTTP Basic Auth, `/v2` prefix) that older clients such
as `gns3fy` target. This client talks to the v3 API directly, based on the
server's own OpenAPI spec (`/openapi.json`).
"""
from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Optional

import requests

from .console import Console, pull_file, push_file
from .exceptions import Gns3ApiError


class Gns3Client:
    def __init__(self, base_url: str, username: str, password: str, verify: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify = verify
        self.session = requests.Session()
        self.session.verify = verify
        self._token: Optional[str] = None

    @classmethod
    def from_creds_file(cls, path: str | Path, verify: bool = False) -> "Gns3Client":
        """Builds a client from a simple "Key: Value" creds file (e.g. a
        course project's gitignored creds.txt), reading whichever of
        "GNS3 IP"/"GNS 3 IP", "Username" and "Password" it finds (match is
        case-insensitive, other keys are ignored)."""
        fields: dict[str, str] = {}
        for line in Path(path).read_text().splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            fields[key.strip().lower()] = value.strip()

        host = fields.get("gns3 ip") or fields.get("gns 3 ip")
        username = fields.get("username")
        password = fields.get("password")
        missing = [k for k, v in (("GNS3 IP", host), ("Username", username), ("Password", password)) if not v]
        if missing:
            raise ValueError(f"{path}: missing {', '.join(missing)}")

        base_url = host if "://" in host else f"http://{host}"
        return cls(base_url, username, password, verify=verify)

    # -- auth -----------------------------------------------------------
    def authenticate(self) -> str:
        resp = self.session.post(
            f"{self.base_url}/v3/access/users/login",
            data={"username": self.username, "password": self.password},
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        self.session.headers["Authorization"] = f"Bearer {self._token}"
        return self._token

    def _ensure_auth(self) -> None:
        if self._token is None:
            self.authenticate()

    def _send_with_retry(self, method: str, url: str, retries: int, **kwargs):
        # Some GNS3 setups (e.g. behind a proxy) drop keep-alive connections
        # after just one or two requests. Recreate the session (fresh TCP
        # connection) and retry on transient connection errors instead of
        # failing the whole call.
        last_error: Exception = RuntimeError("no attempt made")
        for attempt in range(retries + 1):
            try:
                return self.session.request(method, url, **kwargs)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_error = exc
                self.session.close()
                self.session = requests.Session()
                self.session.verify = self.verify
                if self._token is not None:
                    self.session.headers["Authorization"] = f"Bearer {self._token}"
                time.sleep(0.5 * (attempt + 1))
        raise last_error

    # -- low level --------------------------------------------------------
    def _request(self, method: str, path: str, retries: int = 3, raw: bool = False, **kwargs) -> Any:
        self._ensure_auth()
        url = f"{self.base_url}{path}"
        resp = self._send_with_retry(method, url, retries, **kwargs)
        if resp.status_code == 401 and self._token is not None:
            # token may have expired; retry once after re-authenticating
            self.authenticate()
            resp = self._send_with_retry(method, url, retries, **kwargs)
        if not resp.ok:
            try:
                detail = resp.json().get("detail", resp.text)
            except ValueError:
                detail = resp.text
            raise Gns3ApiError(resp.status_code, detail, method, path)
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.text if raw else resp.json()

    def get(self, path: str, **kwargs) -> Any:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, json: Any = None, **kwargs) -> Any:
        # Action endpoints (start/stop/open/close/...) require an actual
        # empty JSON body -- sending none at all makes the server 422 with
        # "Field required" even though the schema has no required fields.
        return self._request("POST", path, json=json if json is not None else {}, **kwargs)

    def put(self, path: str, json: Any = None, **kwargs) -> Any:
        return self._request("PUT", path, json=json, **kwargs)

    def delete(self, path: str, **kwargs) -> Any:
        return self._request("DELETE", path, **kwargs)

    # -- server info ------------------------------------------------------
    def version(self) -> dict:
        return self.get("/v3/version")

    # -- projects -----------------------------------------------------------
    def list_projects(self) -> list[dict]:
        return self.get("/v3/projects")

    def get_project(self, project_id: str) -> dict:
        return self.get(f"/v3/projects/{project_id}")

    def find_project(self, name: str) -> Optional[dict]:
        for project in self.list_projects():
            if project["name"] == name:
                return project
        return None

    def create_project(self, name: str, **kwargs) -> dict:
        return self.post("/v3/projects", json={"name": name, **kwargs})

    def open_project(self, project_id: str) -> dict:
        return self.post(f"/v3/projects/{project_id}/open")

    def close_project(self, project_id: str) -> dict:
        return self.post(f"/v3/projects/{project_id}/close")

    def delete_project(self, project_id: str) -> None:
        self.delete(f"/v3/projects/{project_id}")

    # -- nodes ------------------------------------------------------------
    def list_nodes(self, project_id: str) -> list[dict]:
        return self.get(f"/v3/projects/{project_id}/nodes")

    def get_node(self, project_id: str, node_id: str) -> dict:
        return self.get(f"/v3/projects/{project_id}/nodes/{node_id}")

    def find_node(self, project_id: str, name: str) -> Optional[dict]:
        for node in self.list_nodes(project_id):
            if node["name"] == name:
                return node
        return None

    def create_node(self, project_id: str, **kwargs) -> dict:
        return self.post(f"/v3/projects/{project_id}/nodes", json=kwargs)

    def update_node(self, project_id: str, node_id: str, **kwargs) -> dict:
        return self.put(f"/v3/projects/{project_id}/nodes/{node_id}", json=kwargs)

    def delete_node(self, project_id: str, node_id: str) -> None:
        self.delete(f"/v3/projects/{project_id}/nodes/{node_id}")

    def start_node(self, project_id: str, node_id: str) -> dict:
        return self.post(f"/v3/projects/{project_id}/nodes/{node_id}/start")

    def stop_node(self, project_id: str, node_id: str) -> dict:
        return self.post(f"/v3/projects/{project_id}/nodes/{node_id}/stop")

    def suspend_node(self, project_id: str, node_id: str) -> dict:
        return self.post(f"/v3/projects/{project_id}/nodes/{node_id}/suspend")

    def reload_node(self, project_id: str, node_id: str) -> dict:
        return self.post(f"/v3/projects/{project_id}/nodes/{node_id}/reload")

    def start_all_nodes(self, project_id: str) -> None:
        self.post(f"/v3/projects/{project_id}/nodes/start")

    def stop_all_nodes(self, project_id: str) -> None:
        self.post(f"/v3/projects/{project_id}/nodes/stop")

    # -- links --------------------------------------------------------------
    def list_links(self, project_id: str) -> list[dict]:
        return self.get(f"/v3/projects/{project_id}/links")

    def create_link(
        self,
        project_id: str,
        node_a_id: str,
        port_a: int,
        node_b_id: str,
        port_b: int,
        adapter_a: int = 0,
        adapter_b: int = 0,
    ) -> dict:
        payload = {
            "nodes": [
                {"node_id": node_a_id, "adapter_number": adapter_a, "port_number": port_a},
                {"node_id": node_b_id, "adapter_number": adapter_b, "port_number": port_b},
            ]
        }
        return self.post(f"/v3/projects/{project_id}/links", json=payload)

    def delete_link(self, project_id: str, link_id: str) -> None:
        self.delete(f"/v3/projects/{project_id}/links/{link_id}")

    # -- templates ------------------------------------------------------------
    def list_templates(self) -> list[dict]:
        return self.get("/v3/templates")

    def find_template(self, name: str) -> Optional[dict]:
        for template in self.list_templates():
            if template["name"] == name:
                return template
        return None

    def create_node_from_template(
        self, project_id: str, template_id: str, x: int = 0, y: int = 0
    ) -> dict:
        return self.post(
            f"/v3/projects/{project_id}/templates/{template_id}", json={"x": x, "y": y}
        )

    # -- consoles -------------------------------------------------------------
    def console_endpoint(self, node: dict) -> tuple[str, int]:
        # The nodes API reports console_host as a bind-all placeholder
        # ("0.0.0.0", "::", "127.0.0.1"); connecting to it targets the local
        # machine instead of the controller and fails with ECONNREFUSED.
        host = node.get("console_host")
        if not host or host in ("0.0.0.0", "::", "127.0.0.1", "localhost"):
            parsed = urlparse(self.base_url)
            host = parsed.hostname
        port = node.get("console")
        if not port:
            raise Gns3ApiError(400, "node has no console port (is it started?)", "GET", "console")
        return host, port

    def get_console(self, project_id: str, node_id: str) -> tuple[str, int]:
        # A closed project blocks node reads outright (403 "not opened") or,
        # when half-open, returns stripped payloads without console fields;
        # both states are healed by opening the project first.
        try:
            node = self.get_node(project_id, node_id)
        except Gns3ApiError:
            self.open_project(project_id)
            node = self.get_node(project_id, node_id)
        if not node.get("console"):
            self.open_project(project_id)
            node = self.get_node(project_id, node_id)
        return self.console_endpoint(node)

    # -- node files -------------------------------------------------------------
    def read_node_file(self, project_id: str, node_id: str, path: str) -> str:
        # Works for controller-managed paths such as /etc/network/interfaces;
        # for /root the files API silently 404s on read - use the node console.
        resp = self._request(
            "GET",
            f"/v3/projects/{project_id}/nodes/{node_id}/files{path}",
            raw=True,
        )
        return resp if isinstance(resp, str) else (resp.get("content", "") if resp else "")

    def write_node_file(
        self, project_id: str, node_id: str, path: str, content: str
    ) -> None:
        # Content-Type must be application/octet-stream (raw body); a JSON
        # body corrupts the target file.
        self._request(
            "POST",
            f"/v3/projects/{project_id}/nodes/{node_id}/files{path}",
            data=content.encode(),
            headers={"Content-Type": "application/octet-stream"},
        )

    def _ensure_node_running(self, project_id: str, node_id: str, wait: int = 90) -> None:
        # A stopped node has no listening console; start and wait before
        # attempting any console session.
        node = self.get_node(project_id, node_id)
        if node.get("status") == "started":
            return
        self.start_node(project_id, node_id)
        deadline = time.time() + wait
        while time.time() < deadline:
            time.sleep(1)
            if self.get_node(project_id, node_id).get("status") == "started":
                # debinet's boot runs /root/init.sh synchronously; give
                # the resulting shell a settle window before console work
                time.sleep(5)
                return
        raise Gns3ApiError(500, "node did not reach started state", "POST", "start")

    def _console_retry(self, fn, *, retries: int = 2, delay: float = 1.5):
        # The console is a raw telnet socket proxied by the GNS3 compute --
        # unlike the REST layer (_send_with_retry), a mid-session reset here
        # previously had no recovery at all. Observed in practice (not
        # image-specific: reproduces on both alpinet and debinet consoles)
        # as a ConnectionResetError/BrokenPipeError on the *second* send on
        # an otherwise healthy connection. Retrying the whole operation on a
        # fresh connection clears it. push_file/pull_file raise RuntimeError
        # (not a connection-level exception) for a corrupted/incomplete
        # transfer, which the same underlying reset also causes -- those are
        # just as retriable.
        last_error: Exception = RuntimeError("no attempt made")
        for attempt in range(retries + 1):
            try:
                return fn()
            except (ConnectionError, OSError, RuntimeError) as exc:
                last_error = exc
                if attempt < retries:
                    time.sleep(delay)
        raise Gns3ApiError(500, f"console operation failed after retries: {last_error}", "CONSOLE", "")

    def console_exec(self, project_id: str, node_id: str, command: str, timeout: float = 30.0) -> str:
        self._ensure_node_running(project_id, node_id)

        def attempt():
            host, port = self.get_console(project_id, node_id)
            with Console(host, port) as con:
                return con.exec(command, timeout=timeout)

        return self._console_retry(attempt)

    def push_node_file(
        self, project_id: str, node_id: str, path: str, content: str,
        mode: int | None = None, timeout: float = 120.0,
    ) -> str:
        # Console-channel write: unlike write_node_file this reaches /root
        # and any other path, at the cost of the node being started and the
        # file arriving as base64 chunks through the PTY.
        self._ensure_node_running(project_id, node_id)

        def attempt():
            host, port = self.get_console(project_id, node_id)
            return push_file(host, port, path, content, mode=mode, timeout=timeout)

        return self._console_retry(attempt)

    def pull_node_file(self, project_id: str, node_id: str, path: str,
                       timeout: float = 60.0) -> str:
        # Console-channel read: the counterpart of push_node_file, working
        # for every path including /root (the files API 404s there). The
        # transfer is base64 so binary content stays intact.
        self._ensure_node_running(project_id, node_id)

        def attempt():
            host, port = self.get_console(project_id, node_id)
            return pull_file(host, port, path, timeout=timeout)

        return self._console_retry(attempt)

    # -- idempotent builders ----------------------------------------------------
    def ensure_node(
        self, project_id: str, name: str, template_id: str, **properties
    ) -> dict:
        # Creates the node if absent; on an existing node it only reconciles
        # the adapter count upwards (GNS3 refuses to shrink while links exist)
        # and never invents a fresh position.
        node = self.find_node(project_id, name)
        if node is None:
            body = {"template_id": template_id, "name": name}
            body.update(properties)
            return self.create_node(project_id, **body)
        adapters = properties.get("properties", {}).get("adapters")
        current = node.get("properties", {}).get("adapters")
        if adapters and isinstance(current, int) and not isinstance(current, bool):
            if current != adapters:
                if current > adapters:
                    raise Gns3ApiError(
                        500, f"node '{name}' has {current} adapters (> {adapters}) "
                             "and cannot be shrunk while links exist",
                        "PUT", "adapters",
                    )
                self.update_node(project_id, node["node_id"], adapters=adapters)
        return self.get_node(project_id, node["node_id"])

    def ensure_link(
        self,
        project_id: str,
        node_a_id: str,
        adapter_a: int,
        port_a: int,
        node_b_id: str,
        adapter_b: int,
        port_b: int,
    ) -> dict:
        # Skips creation when the same endpoint pair is already wired;
        # endpoint order is irrelevant for the comparison.
        want = frozenset({
            (node_a_id, adapter_a, port_a),
            (node_b_id, adapter_b, port_b),
        })
        have = self.list_links(project_id)
        for link in have:
            endpoints = frozenset({
                (e["node_id"], e["adapter_number"], e["port_number"])
                for e in link.get("nodes", [])
            })
            if endpoints == want:
                return link
        return self.create_link(
            project_id,
            node_a_id=node_a_id, adapter_a=adapter_a, port_a=port_a,
            node_b_id=node_b_id, adapter_b=adapter_b, port_b=port_b,
        )
