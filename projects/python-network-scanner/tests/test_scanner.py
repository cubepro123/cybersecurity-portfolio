from __future__ import annotations

import json
import socket
import threading
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from scanner import main, parse_ports


def start_local_server() -> tuple[socket.socket, int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def _accept_once() -> None:
        conn, _ = server.accept()
        conn.close()

    thread = threading.Thread(target=_accept_once, daemon=True)
    thread.start()
    return server, server.getsockname()[1]


def test_parse_ports_handles_ranges() -> None:
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_public_targets_blocked_by_default(capsys) -> None:
    rc = main(["--target", "8.8.8.8", "--ports", "53"])
    assert rc == 1
    assert "Public targets are blocked" in capsys.readouterr().err


def test_localhost_scan_json_output(tmp_path) -> None:
    server, port = start_local_server()
    output_path = tmp_path / "scan.json"

    rc = main(["--target", "127.0.0.1", "--ports", str(port), "--json-output", str(output_path)])

    server.close()
    assert rc == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["target"] == "127.0.0.1"
    assert payload["results"][0]["port"] == port
