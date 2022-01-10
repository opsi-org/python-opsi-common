# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import time
import json
from urllib.parse import unquote
from requests.exceptions import ConnectionError as RConnectionError, ReadTimeout, HTTPError
import pytest

from opsicommon.client.jsonrpc import JSONRPCClient, BackendAuthenticationError, BackendPermissionDeniedError, OpsiRpcError
from opsicommon.ssl import create_ca, create_server_cert, as_pem
from opsicommon.logging import LOG_WARNING

from .helpers import http_jsonrpc_server, environment, log_stream



def test_arguments():
	kwargs = {
		"application": "application test",
		"compression": True,
		"connect_on_init": False,
		"create_methods": False,
		"ca_cert_file": "/tmp/cacert",
		"verify_server_cert": True,
		"proxy_url": "http://localhost:8080",
		"username": "user",
		"password": "pass",
		"serialization": "auto",
		"ip_version": "auto",
		"connect_timeout": 11,
		"read_timeout": 12,
		"http_pool_maxsize": 13,
		"http_max_retries": 14,
		"session_lifetime": 15,
	}
	client = JSONRPCClient("http://localhost", **kwargs)
	for attr, val in kwargs.items():
		assert getattr(client, f"_{attr}") == val

	_kwargs = kwargs.copy()
	del _kwargs["http_max_retries"]
	_kwargs["retry"] = False
	_kwargs["invalid"] = True
	client = JSONRPCClient("http://localhost", **_kwargs)
	assert getattr(client, "_http_max_retries") == 0

	for serialization in ("invalid", "json", "msgpack", "auto"):
		kwargs["serialization"] = serialization
		client = JSONRPCClient("localhost", **kwargs)
		if serialization == "invalid":
			serialization = "auto"
		assert getattr(client, "_serialization") == serialization
		assert client.base_url == "https://localhost:4447/rpc"

	for ip_version in ("8", "4", "6", "auto"):
		kwargs["ip_version"] = ip_version
		client = JSONRPCClient("https://localhost/base/path", **kwargs)
		if ip_version == "8":
			ip_version = "auto"
		assert getattr(client, "_ip_version") == ip_version
		assert client.base_url == "https://localhost:4447/base/path"

	for compression in ("gzip", "lz4", "true", True, "false", False):
		kwargs["compression"] = compression
		client = JSONRPCClient("http://localhost:123/base/path", **kwargs)
		if compression == "true":
			compression = True
		elif compression == "false":
			compression = False
		assert getattr(client, "_compression") == compression
		assert client.base_url == "http://localhost:123/base/path"

	client = JSONRPCClient("http://127.0.0.1", **kwargs)
	assert getattr(client, "_ip_version") == 4

	client = JSONRPCClient("http://[::1]", **kwargs)
	assert getattr(client, "_ip_version") == 6


def test_timeouts():
	with http_jsonrpc_server(response_delay=3) as server:
		start = time.time()
		with pytest.raises(RConnectionError):
			JSONRPCClient(f"http://localhost:{server.port+1}", connect_timeout=2)
			assert round(time.time() - start) == 2

		with pytest.raises(ReadTimeout):
			JSONRPCClient(f"http://localhost:{server.port}", read_timeout=2)
			assert round(time.time() - start) == 2

		JSONRPCClient(f"http://localhost:{server.port}", read_timeout=6)


def test_proxy(tmp_path):
	log_file = tmp_path / "request.log"
	with http_jsonrpc_server(log_file=log_file) as server:
		# Proxy will not be used for localhost (JSONRPCClient.no_proxy_addresses)
		with pytest.raises(RConnectionError):
			JSONRPCClient(f"http://localhost:{server.port+1}", proxy_url=f"http://localhost:{server.port}", connect_timeout=2)

		proxy_env = {
			"http_proxy": f"http://localhost:{server.port}",
			"https_proxy": f"http://localhost:{server.port}"
		}
		with environment(proxy_env), pytest.raises(RConnectionError):
			JSONRPCClient(f"http://localhost:{server.port+1}", proxy_url="system", connect_timeout=2)


		JSONRPCClient.no_proxy_addresses = []
		# Now proxy will be used for localhost

		proxy_env = {
			"http_proxy": "http://should-not-be-used",
			"https_proxy": "http://should-not-be-used"
		}
		with environment(proxy_env):
			for host, proxy_host in (
				("localhost", "localhost"),
				("localhost", "127.0.0.1"),
				("127.0.0.1", "localhost"),
				("127.0.0.1", "127.0.0.1")
			):
				JSONRPCClient(f"http://{host}:{server.port+1}", proxy_url=f"http://{proxy_host}:{server.port}", connect_timeout=2)

				request = json.loads(log_file.read_text(encoding="utf-8"))
				#print(request)
				assert request.get("path") == f"http://{host}:{server.port+1}/rpc"
				os.remove(log_file)

		proxy_env = {
			"http_proxy": f"http://localhost:{server.port}",
			"https_proxy": f"http://localhost:{server.port+2}",
			"no_proxy": ""
		}
		with environment(proxy_env):
			JSONRPCClient(f"http://localhost:{server.port+1}", proxy_url="system", connect_timeout=2)
			request = json.loads(log_file.read_text(encoding="utf-8"))
			#print(request)
			assert request.get("path") == f"http://localhost:{server.port+1}/rpc"
			os.remove(log_file)


		proxy_env = {
			"http_proxy": "http://should-not-be-used",
			"https_proxy": "http://should-not-be-used"
		}
		with environment(proxy_env):
			# Do not use any proxy
			JSONRPCClient(f"http://{host}:{server.port}", proxy_url=None, connect_timeout=2)
			request = json.loads(log_file.read_text(encoding="utf-8"))
			#print(request)
			assert request.get("path") == "/rpc"
			os.remove(log_file)


def test_proxy_legacy(tmp_path):
	log_file = tmp_path / "request.log"
	with http_jsonrpc_server(log_file=log_file) as server:
		JSONRPCClient.no_proxy_addresses = []
		proxy_env = {
			"http_proxy": "should-not-be-used",
			"https_proxy": "should-not-be-used"
		}

		JSONRPCClient(f"http://localhost:{server.port+1}", proxy_url=f"localhost:{server.port}", connect_timeout=2)
		request = json.loads(log_file.read_text(encoding="utf-8"))
		assert request.get("path") == f"http://localhost:{server.port+1}/rpc"
		os.remove(log_file)

		proxy_env = {
			"http_proxy": f"localhost:{server.port}",
			"https_proxy": f"localhost:{server.port+2}",
			"no_proxy": ""
		}
		with environment(proxy_env):
			JSONRPCClient(f"http://localhost:{server.port+1}", proxy_url="system", connect_timeout=2)
			request = json.loads(log_file.read_text(encoding="utf-8"))
			assert request.get("path") == f"http://localhost:{server.port+1}/rpc"
			os.remove(log_file)


def test_cookie_handling(tmp_path):
	log_file = tmp_path / "request.log"
	cookie = "COOKIE-NAME=abc"
	with http_jsonrpc_server(
		log_file=log_file,
		response_headers={"Set-Cookie": cookie}
	) as server:
		client = JSONRPCClient(f"http://localhost:{server.port}")
		client.get("/")
		assert client.session_id == cookie

	request = json.loads(log_file.read_text(encoding="utf-8").strip().split("\n")[1])
	#print(request)
	assert request["headers"].get("Cookie") == cookie


def test_force_ip_version_4(tmp_path):
	log_file = tmp_path / "request.log"
	with http_jsonrpc_server(ip_version=4, log_file=log_file) as server:
		client = JSONRPCClient(f"http://localhost:{server.port}", ip_version=4)
		client.get("/")
		request = json.loads(log_file.read_text(encoding="utf-8").strip().split("\n")[1])
		#print(request)
		assert "127.0.0.1" in request["client_address"][0]


@pytest.mark.not_in_docker
def test_force_ip_version_6(tmp_path):
	log_file = tmp_path / "request.log"
	with http_jsonrpc_server(ip_version=6, log_file=log_file) as server:
		client = JSONRPCClient(f"http://localhost:{server.port}", ip_version=6)
		client.get("/")
		request = json.loads(log_file.read_text(encoding="utf-8").strip().split("\n")[1])
		#print(request)
		assert "::1" in request["client_address"][0]


@pytest.mark.parametrize("server_name, expected_version", (
	("opsiconfd 4.1.0.1", [4, 1, 0, 1]),
	("opsiconfd service 4.2.00.99", [4, 2, 0, 99]),
	("opsiconfd service 4.2.0.x", None),
	("apache 2.0.1", None),
))
def test_server_name_handling(tmp_path, server_name, expected_version):
	log_file = tmp_path / f"{server_name}.log"
	with http_jsonrpc_server(
		log_file=log_file,
		response_headers={"Server": server_name}
	) as server:
		client = JSONRPCClient(f"http://localhost:{server.port}", compression=True)
		assert client.server_name == server_name
		assert client.server_name == client.serverName
		assert client.server_version == expected_version
		client.execute_rpc("method", ["param"*100])

	if expected_version:
		request = json.loads(log_file.read_text(encoding="utf-8").strip().split("\n")[1])
		#print(request)
		if expected_version[0] > 4 or (expected_version[0] == 4 and expected_version[1] >= 2):
			assert request["headers"].get('Content-Type') == 'application/msgpack'
			assert request["headers"].get('Content-Encoding') == 'lz4'
		else:
			assert request["headers"].get('Content-Type') == 'application/json'
			assert request["headers"].get('Content-Encoding') is None


def test_compression_and_serialization(tmp_path):
	for compression, serialization in (
		(True, "json"),
		("lz4", "json"),
		("gzip", "json"),
		("lz4", "msgpack"),
		("gzip", "msgpack"),
		("none", "msgpack")
	):
		server_name = "opsiconfd 4.2.0.0"
		log_file = tmp_path / f"{compression}_{serialization}.log"
		with http_jsonrpc_server(
			log_file=log_file,
			response_headers={"Server": server_name}
		) as server:
			client = JSONRPCClient(
				f"http://localhost:{server.port}", compression=compression, serialization=serialization
			)
			assert client.server_name == server_name
			client.execute_rpc("method", ["param"*100])

		request = json.loads(log_file.read_text(encoding="utf-8").strip().split("\n")[1])
		#print(request)
		if compression is True:
			compression = "lz4"
		elif compression == "none":
			compression = None
		assert request["headers"].get('Content-Type') == f'application/{serialization}'
		assert request["headers"].get('Content-Encoding') == compression


def test_pass_session_id(tmp_path):
	log_file = tmp_path / "request.log"
	session_id = "opsi-session-id=_ABüßö&$§"
	with http_jsonrpc_server(
		log_file=log_file,
		#response_headers={"Set-Cookie": "COOKIE-NAME=abc; SameSite=Lax"}
	) as server:
		client = JSONRPCClient(
			f"http://localhost:{server.port}",
			session_id=session_id
		)
		client.get("/")
		assert client.session_id == session_id

	for line in log_file.read_text(encoding="utf-8").strip().split("\n"):
		request = json.loads(line)
		#print(request)
		assert unquote(request["headers"].get("Cookie")) == session_id


def test_pass_invalid_session_id():
	session_id = "1234556789"
	client = JSONRPCClient(
		"http://localhost",
		session_id=session_id,
		connect_on_init=False
	)
	assert not client._session.cookies  # pylint: disable=protected-access
	assert not client.session_id


def test_get_path(tmp_path):
	log_file = tmp_path / "request.log"
	user_agent = "opsi 4.2"
	session_lifetime = 10
	username = "abcüöäa"
	password = "123&:%$§"

	with http_jsonrpc_server(log_file=log_file) as server:
		client = JSONRPCClient(
			f"http://localhost:{server.port}",
			connect_on_init=False,
			create_methods=False,
			application=user_agent,
			session_lifetime=session_lifetime,
			username=username,
			password=password,
		)
		response = client.get("/path")
		assert response.content.decode("utf-8") == "OK"

	log = log_file.read_text(encoding="utf-8")
	request = json.loads(log)
	#print(request)
	assert request["method"] == "GET"
	assert request["path"] == "/path"
	assert request["headers"]["User-Agent"] == user_agent
	assert request["headers"]["X-opsi-session-lifetime"] == str(session_lifetime)
	assert request["headers"]["Authorization"] == "Basic YWJj/PbkYToxMjMmOiUkpw=="


def test_error_handling():
	with http_jsonrpc_server(response_status=[500, "internal server error"]) as server:
		with pytest.raises(OpsiRpcError):
			JSONRPCClient(f"http://localhost:{server.port}")

	with http_jsonrpc_server(response_status=[401, "auth error"]) as server:
		with pytest.raises(BackendAuthenticationError):
			JSONRPCClient(f"http://localhost:{server.port}")

	with http_jsonrpc_server(response_status=[403, "permission denied"]) as server:
		with pytest.raises(BackendPermissionDeniedError):
			JSONRPCClient(f"http://localhost:{server.port}")

	response_body = json.dumps({"error": {"message": "err_msg"}}).encode("utf-8")
	with http_jsonrpc_server(response_body=response_body) as server:
		with pytest.raises(OpsiRpcError) as err:
			JSONRPCClient(f"http://localhost:{server.port}")
		assert err.message == "err_msg"

	response_body = json.dumps({"error": "err_msg2"}).encode("utf-8")
	with http_jsonrpc_server(response_body=response_body) as server:
		with pytest.raises(OpsiRpcError) as err:
			JSONRPCClient(f"http://localhost:{server.port}")
		assert err.message == "err_msg2"

	with http_jsonrpc_server() as server:
		client = JSONRPCClient(f"http://localhost:{server.port}")
		with pytest.raises(HTTPError):
			client.get("/", {"X-Response-Status": "500 Internal Server Error"})


def test_interface_and_exit(tmp_path):
	log_file = tmp_path / "request.log"
	with open("tests/data/client/jsonrpc/interface.json", "rb") as file:
		interface = file.read()

	with http_jsonrpc_server(log_file=log_file, response_body=interface) as server:
		client = JSONRPCClient(f"http://localhost:{server.port}", connect_on_init=False)
		assert not hasattr(client, "host_getObjects")
		assert client.interface
		assert hasattr(client, "host_getObjects")
		assert client.backend_getInterface()
		assert client.getInterface()
		client.disconnect()

		client._connected = True  # pylint: disable=protected-access
		client.execute_rpc = lambda method, params: exec('raise Exception("fail")')  # pylint: disable=exec-used
		client.disconnect()
	request = json.loads(log_file.read_text(encoding="utf-8").strip().split("\n")[1])
	assert request["request"]["method"] == "backend_exit"


def test_wget(tmpdir):  # pylint: disable=redefined-outer-name, unused-argument
	ca_cert, ca_key = create_ca({"CN": "python-opsi-common test ca"}, 3)
	kwargs = {
		"subject": {"CN": "python-opsi-common test server cert"},
		"valid_days": 3,
		"ip_addresses": {"172.0.0.1", "::1"},
		"hostnames": {"localhost", "ip6-localhost"},
		"ca_key": ca_key,
		"ca_cert": ca_cert
	}
	cert, key = create_server_cert(**kwargs)

	server_cert = tmpdir / "server_cert.pem"
	server_key = tmpdir / "server_key.pem"
	server_cert.write_text(as_pem(cert), encoding="utf-8")
	server_key.write_text(as_pem(key), encoding="utf-8")


def test_env_requests_ca_bundle(tmpdir):
	ca_cert, ca_key = create_ca({"CN": "python-opsi-common test ca"}, 3)
	kwargs = {
		"subject": {"CN": "python-opsi-common test server cert"},
		"valid_days": 3,
		"ip_addresses": {"172.0.0.1", "::1"},
		"hostnames": {"localhost", "ip6-localhost"},
		"ca_key": ca_key,
		"ca_cert": ca_cert
	}
	cert, key = create_server_cert(**kwargs)
	server_cert = tmpdir / "server_cert.pem"
	server_key = tmpdir / "server_key.pem"
	server_cert.write_text(as_pem(cert), encoding="utf-8")
	server_key.write_text(as_pem(key), encoding="utf-8")

	ca_bundle = "/error.crt"
	with log_stream(LOG_WARNING, format="%(levelname)s %(message)s") as stream:
		with environment({"REQUESTS_CA_BUNDLE": ca_bundle}):
			with http_jsonrpc_server(server_key=server_key, server_cert=server_cert) as server:
				with pytest.raises(OSError) as err:
					JSONRPCClient(f"https://localhost:{server.port}")

				assert ca_bundle in str(err)
				stream.seek(0)
				log = stream.read()
				print(log)
				assert f"WARNING Environment variable REQUESTS_CA_BUNDLE is set to '{ca_bundle}'" in log
