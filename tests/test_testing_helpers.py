# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import json
import os
import time
from base64 import b64decode
from email.utils import formatdate
from pathlib import Path
from random import randbytes

import requests
import websocket  # type: ignore[import]

from opsicommon.testing.helpers import (  # type: ignore[import]
	environment,
	http_test_server,
)


def test_environment() -> None:
	assert "TEST_VAR1" not in os.environ
	with environment({"TEST_VAR1": "VAL1"}):
		assert os.environ.get("TEST_VAR1") == "VAL1"
		with environment({"TEST_VAR1": "VAL2"}):
			assert os.environ.get("TEST_VAR1") == "VAL2"
		assert os.environ.get("TEST_VAR1") == "VAL1"
	assert "TEST_VAR1" not in os.environ


def test_test_http_server_log_file(tmp_path: Path) -> None:
	log_file = tmp_path / "server.log"
	with http_test_server(log_file=log_file) as server:
		res = requests.get(f"http://localhost:{server.port}/dir/file", timeout=10)
		assert res.status_code == 200
	request = json.loads(log_file.read_text(encoding="utf-8").strip())
	assert request["method"] == "GET"
	assert request["client_address"][0] == "127.0.0.1"
	assert request["path"] == "/dir/file"
	assert request["headers"]["Host"].startswith("localhost:")
	log_file.unlink()

	with http_test_server(log_file=None) as server:
		res = requests.get(f"http://localhost:{server.port}/dir/file", timeout=10)
		assert res.status_code == 200

	assert not log_file.exists()


def test_test_http_server_headers() -> None:
	with http_test_server(response_headers={"Server": "test/123", "X-Server-Adress": "{server_address}", "X-Host": "{host}"}) as server:
		res = requests.get(f"http://localhost:{server.port}", timeout=10)
		assert res.status_code == 200
		assert res.headers["Server"] == "test/123"
		assert res.headers["X-Server-Adress"].endswith(f":{server.port}")
		assert res.headers["X-Host"].endswith(f":{server.port}")


def test_test_http_server_response_delay() -> None:
	with http_test_server(response_delay=2) as server:
		start = time.time()
		res = requests.get(f"http://localhost:{server.port}", timeout=10)
		assert res.status_code == 200
		delay = round(time.time() - start)
		assert 6 >= delay >= 2


def test_test_http_server_post() -> None:
	with http_test_server() as server:
		rpc = {"id": 1, "method": "test", "parms": [1, 2]}
		res = requests.post(f"http://localhost:{server.port}", json=rpc, timeout=10)
		assert res.status_code == 200


def test_test_http_server_serve_files(tmp_path: Path) -> None:
	test_dir = tmp_path / "dir1"
	test_dir.mkdir()
	test_file1 = test_dir / "file1"
	test_file1.touch()
	test_file2 = test_dir / "file2"
	test_file2.write_text("test2", encoding="utf-8")
	with http_test_server(serve_directory=tmp_path) as server:
		res = requests.get(f"http://127.0.0.1:{server.port}/dir1", timeout=10)
		assert res.status_code == 200
		assert "Directory listing for /dir1" in res.text

		res = requests.get(f"http://127.0.0.1:{server.port}/dir1/file2", timeout=10)
		assert res.status_code == 200
		assert res.text == "test2"

		res = requests.get(f"http://127.0.0.1:{server.port}/dir1/file2", headers={"Range": "bytes=3-4"}, timeout=10)
		assert res.status_code == 206
		assert res.text == "t2"

		res = requests.get(f"http://127.0.0.1:{server.port}/dir1/file2", headers={"Range": "bytes=3-1024"}, timeout=10)
		assert res.status_code == 206
		assert res.text == "t2"

		(test_dir / "index.html").write_text("index", encoding="utf-8")

		res = requests.get(f"http://127.0.0.1:{server.port}/dir1", timeout=10)
		assert res.status_code == 200
		assert res.text == "index"

		res = requests.get(f"http://127.0.0.1:{server.port}/dir2/", timeout=10)
		assert res.status_code == 404

		res = requests.get(f"http://127.0.0.1:{server.port}/404", timeout=10)
		assert res.status_code == 404

		date = formatdate(timeval=time.time())
		res = requests.get(f"http://127.0.0.1:{server.port}/dir1/file2", headers={"If-Modified-Since": date}, timeout=10)
		assert res.status_code == 304

		res = requests.get(f"http://127.0.0.1:{server.port}/dir1/file2", headers={"If-Modified-Since": "INVALID"}, timeout=10)
		assert res.status_code == 200

		res = requests.put(f"http://127.0.0.1:{server.port}/dir1/put", data="test", timeout=10)
		assert res.status_code == 201

		res = requests.head(f"http://127.0.0.1:{server.port}/dir1/file1", timeout=10)
		assert res.status_code == 200

		res = requests.delete(f"http://127.0.0.1:{server.port}/dir1/file1", timeout=10)
		assert res.status_code == 204

		res = requests.head(f"http://127.0.0.1:{server.port}/dir1/file1", timeout=10)
		assert res.status_code == 404

		res = requests.request("MKCOL", f"http://127.0.0.1:{server.port}/newdir", timeout=10)
		assert res.status_code == 201


def test_test_http_server_ranges(tmp_path: Path) -> None:
	test_file = tmp_path / "file1"
	data = randbytes(1_000)
	test_file.write_bytes(data)
	with http_test_server(serve_directory=tmp_path) as server:
		res = requests.get(f"http://127.0.0.1:{server.port}/file1", timeout=10, headers={"Range": "bytes=0-99"})
		assert res.status_code == 206
		dat = res.content
		assert len(dat) == 100
		assert dat == data[:100]

		res = requests.get(f"http://127.0.0.1:{server.port}/file1", timeout=10, headers={"Range": "bytes=-99"})
		assert res.status_code == 206
		dat = res.content
		assert len(dat) == 100
		assert dat == data[:100]

		res = requests.get(f"http://127.0.0.1:{server.port}/file1", timeout=10, headers={"Range": "bytes=100-"})
		assert res.status_code == 206
		dat = res.content
		assert len(dat) == 900
		assert dat == data[100:]

		res = requests.get(f"http://127.0.0.1:{server.port}/file1", timeout=10, headers={"Range": "bytes=0-99,200-299"})
		assert res.status_code == 206
		dat = res.content
		boundary = b"\n--" + res.headers["Content-Type"].split("boundary=")[1].encode("ascii")
		parts = [p.split(b"\n\n", 1)[1] for p in dat.split(boundary)[1:-1]]
		assert len(parts) == 2
		assert len(parts[0]) == 100
		assert parts[0] == data[:100]
		assert len(parts[1]) == 100
		assert parts[1] == data[200:300]

		res = requests.get(f"http://127.0.0.1:{server.port}/file1", timeout=10, headers={"Range": "bytes=-399,400-499,500-"})
		assert res.status_code == 206
		dat = res.content
		boundary = b"\n--" + res.headers["Content-Type"].split("boundary=")[1].encode("ascii")
		parts = [p.split(b"\n\n", 1)[1] for p in dat.split(boundary)[1:-1]]
		assert len(parts) == 3
		assert b"".join(parts) == data


def test_http_server_websocket(tmp_path: Path) -> None:
	log_file = tmp_path / "server.log"
	with http_test_server(log_file=log_file, ws_message_callback=lambda handler, message: handler.ws_send_message(b"response")) as server:
		wsock = websocket.create_connection(f"ws://127.0.0.1:{server.port}/websocket/test")
		wsock.send(b"test")
		assert wsock.recv() == b"response"
		wsock.close()
	time.sleep(1)
	reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]

	assert reqs[0]["method"] == "GET"
	assert reqs[0]["client_address"][0] == "127.0.0.1"
	assert reqs[0]["path"] == "/websocket/test"
	assert reqs[0]["headers"]["Host"].startswith("127.0.0.1:")
	assert reqs[0]["headers"]["Connection"] == "Upgrade"
	assert reqs[0]["headers"]["Sec-WebSocket-Key"]
	assert reqs[0]["headers"]["Sec-WebSocket-Version"]

	assert reqs[1]["method"] == "websocket"
	assert reqs[1]["client_address"][0] == "127.0.0.1"
	assert reqs[1]["path"] == "/websocket/test"
	assert reqs[1]["headers"]["Host"].startswith("127.0.0.1:")
	assert b64decode(reqs[1]["request"]) == b"test"
