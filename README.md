# gns3api-py

Python wrapper to interact with the GNS3 REST API. Tested on GNS3 3.0.6.

GNS3 3.x controllers expose a `/v3`-prefixed REST API secured with JWT
bearer tokens (`POST /v3/access/users/login`) - a different scheme from the
GNS3 v2 API (HTTP Basic Auth, `/v2` prefix) that older clients such as
[`gns3fy`](https://github.com/davidban77/gns3fy) target and are incompatible
with a v3 controller. This library talks to the v3 API directly, based on
the server's own OpenAPI spec (`/openapi.json`).

## Install

```bash
pip install git+https://github.com/manoedinata/gns3api-py.git
```

## Usage

```python
from gns3api import Gns3Client

client = Gns3Client(base_url="http://<gns3-host>:80", username="...", password="...")

client.version()
projects = client.list_projects()
project = client.find_project("my-project")

client.open_project(project["project_id"])
nodes = client.list_nodes(project["project_id"])
client.start_all_nodes(project["project_id"])
```

Authentication is lazy: the first API call triggers a login and caches the
bearer token, and a `401` response transparently re-authenticates and
retries once.

## File injection into nodes

The files API is the mechanism to place configuration into a node's
filesystem. `/etc/network/interfaces` on every docker image and any path
outside `/root` persist at write time; `/root` itself can only be reached
through the node console (telnet), not through this API.

```python
iface = client.read_node_file(project_id, node_id, "/etc/network/interfaces")
client.write_node_file(project_id, node_id, "/etc/network/interfaces", iface)
```

For reading back, `pull_node_file()` is the console-channel counterpart of
`push_node_file()`: it works on every path (/root included) and transfers
base64 so binary content survives.

```python
text = client.pull_node_file(project_id, node_id, "/root/init.sh")
```

### Large files

A one-shot pull streams the whole base64 payload as a single console line;
once the echoed output wraps past the PTY's line limit, bracketed-paste
toggles and wrap artifacts start landing inside the payload and the decode
misaligns. `pull_file_chunked()` avoids that class of corruption entirely:

```python
from gns3api.console import pull_file_chunked

host, port = client.get_console(project_id, node_id)
text = pull_file_chunked(host, port, "/root/init.sh")
```

It stages the base64 node-side (`base64 -w`), fetches it in fixed-size page
windows, and verifies the reassembled content against a node-side md5 before
returning - a mismatch raises instead of returning silently corrupted data.
All transport markers embed `#` (outside the base64 alphabet) so payload
text can never fabricate or truncate a marker match, and each page opens
with a `#START#` window so the echoed command line - which wraps
arbitrarily - can never leak into the payload.

## Console endpoints

The `console_host` field of every node is a bind-all placeholder
(`0.0.0.0`, `::`, or `127.0.0.1`); one must connect to the controller host
instead. `get_console()` resolves that mapping, ensuring the project is
open (a closed project returns node payloads without console fields) and
returning a live `(host, port)` pair. By default, the socket requires an
open project with the node running.

```python
host, port = client.get_console(project_id, node_id)
sock = socket.create_connection((host, port), timeout=10)   # telnet-flow automation
```

## Console automation

`console_exec()` runs a shell command on a node through its telnet console
and returns the cleaned output. The transport handles the telnet IAC
negotiation sequences that GNS3 consoles emit and drains a fresh session's
boot banner passively on connect. Each command runs on its own connection
(the console server tolerates exactly one outbound line per connection),
verified with a unique completion marker, and `Gns3Client` transparently
retries on a reset. Both
`console_exec()` and `push_node_file()` resolve the endpoint through
`get_console()` internals, so the project is opened and the node state is
checked for you.

```python
out = client.console_exec(project_id, node_id, "hostname; uptime")
```

## Pushing arbitrary files over the console

`push_node_file()` writes any file to any path, /root included - the files
API cannot reach that path. This is what makes pattern like the debinet
image's `/root/init.sh` (run automatically at boot) scriptable. The payload
travels base64-chunked (keeps each console line under the PTY's ~255 byte
canonical limit), the upload is size-checked, and the result is verified
with an after-write size check. `mode` (octal) adds a chmod step.

```python
client.push_node_file(project_id, node_id, "/root/init.sh", script_text, mode=0o755)
```

## Idempotent builders

`ensure_node()` creates by template but reconciles existing nodes instead
of failing; `ensure_link()` skips when the same wiring already exists.

```python
node = client.ensure_node(project_id, "rootkit", template_id, script="...", x=0, y=0)
client.ensure_link(project_id, node_a["node_id"], 1, 0, node_b["node_id"], 0, 0)
```

## Coverage

`Gns3Client` covers projects, nodes, links and templates (list/get/create/
update/delete, start/stop/suspend/reload, plus project open/close), node
file injection (`read/write_node_file`), console endpoint resolution
(`get_console`, `console_endpoint`), console shell execution
(`console_exec`), console-channel file transfer (`push_node_file`,
`pull_node_file`, chunked variant `pull_file_chunked` in
[`gns3api/console.py`](gns3api/console.py)), and the
idempotent builders (`ensure_node`, `ensure_link`). See
[`gns3api/client.py`](gns3api/client.py) for the full method list, or the
server's `/docs` and `/openapi.json` for the complete API surface.
