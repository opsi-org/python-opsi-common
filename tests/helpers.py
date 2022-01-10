# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing opsi.
"""

import os
import ssl
import gzip
import json
import time
import threading
import socket
from contextlib import closing, contextmanager
from http.server import HTTPServer, SimpleHTTPRequestHandler
import lz4
import msgpack


class HTTPJSONRPCServerRequestHandler(SimpleHTTPRequestHandler):
	def _log(self, data):  # pylint: disable=invalid-name
		if not self.server.log_file:
			return
		with open(self.server.log_file, "a", encoding="utf-8") as file:
			file.write(json.dumps(data))
			file.write("\n")
			file.flush()

	def version_string(self):
		for name, value in self.server.response_headers.items():
			if name.lower() == "server":
				return value
		return super().version_string()

	def _send_headers(self, headers=None):
		if self.server.response_delay:
			time.sleep(self.server.response_delay)
		headers = headers or {}
		headers.update(self.server.response_headers)
		for name, value in headers.items():
			if name.lower() == "server":
				continue
			value = value.replace("{server_address}", f"{self.server.server_address[0]}:{self.server.server_address[1]}")
			value = value.replace("{host}", self.headers["Host"])
			self.send_header(name, value)
		self.end_headers()

	def do_POST(self):  # pylint: disable=invalid-name
		length = int(self.headers['Content-Length'])
		request = self.rfile.read(length)
		#print(self.headers)

		if self.headers['Content-Encoding'] == "lz4":
			request = lz4.frame.decompress(request)
		elif self.headers['Content-Encoding'] == "gzip":
			request = gzip.decompress(request)

		if "json" in self.headers['Content-Type']:
			request = json.loads(request)
		elif "msgpack" in self.headers['Content-Type']:
			request = msgpack.loads(request)

		self._log({
			"method": "POST", "client_address": self.client_address,
			"path": self.path, "headers": dict(self.headers), "request": request
		})
		response = None
		if self.server.response_body:
			response = self.server.response_body
		else:
			response = {"id": request["id"], "result": []}
			response = json.dumps(response).encode("utf-8")
		if self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
		else:
			self.send_response(200, "OK")
		headers = {
			"Content-Length": str(len(response)),
			"Content-Type": "application/json"
		}
		self._send_headers(headers)
		self.wfile.write(response)

	def do_GET(self):
		if self.headers['X-Response-Status']:
			val = self.headers['X-Response-Status'].split(" ", 1)
			self.send_response(int(val[0]), val[1])
		elif self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
		else:
			self.send_response(200, "OK")
		self._log({
			"method": "GET", "client_address": self.client_address,
			"path": self.path, "headers": dict(self.headers)
		})
		response = None
		if self.server.response_body:
			response = self.server.response_body
		else:
			response = "OK".encode("utf-8")
		headers = {
			"Content-Length": str(len(response))
		}
		self._send_headers(headers)
		self.wfile.write(response)

class HTTPJSONRPCServer(threading.Thread):  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments
		self,
		log_file=None,
		ip_version=None,
		server_key=None,
		server_cert=None,
		response_headers=None,
		response_status=None,
		response_body=None,
		response_delay=None
	):
		super().__init__()
		self.log_file = str(log_file) if log_file else None
		self.ip_version = 6 if ip_version == 6 else 4
		self.server_key = server_key if server_key else None
		self.server_cert = server_cert if server_cert else None
		self.response_headers = response_headers if response_headers else {}
		self.response_status = response_status if response_status else None
		self.response_body = response_body if response_body else None
		self.response_delay = response_delay if response_delay else None
		# Auto select free port
		with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
			sock.bind(('', 0))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.port = sock.getsockname()[1]
		self.server = None

	def run(self):
		class HTTPServer6(HTTPServer):
			address_family = socket.AF_INET6

		if self.ip_version == 6:
			self.server = HTTPServer6(("::", self.port), HTTPJSONRPCServerRequestHandler)
		else:
			self.server = HTTPServer(("", self.port), HTTPJSONRPCServerRequestHandler)

		if self.server_key and self.server_cert:
			context = ssl.SSLContext()
			context.load_cert_chain(keyfile=self.server_key, certfile=self.server_cert)
			self.server.socket = context.wrap_socket(sock=self.server.socket, server_side=True)
		self.server.log_file = self.log_file  # pylint: disable=attribute-defined-outside-init
		self.server.response_headers = self.response_headers  # pylint: disable=attribute-defined-outside-init
		self.server.response_status = self.response_status  # pylint: disable=attribute-defined-outside-init
		self.server.response_body = self.response_body  # pylint: disable=attribute-defined-outside-init
		self.server.response_delay = self.response_delay  # pylint: disable=attribute-defined-outside-init
		#print("Server listening on port:" + str(self.port))
		self.server.serve_forever()

	def stop(self):
		if self.server:
			self.server.shutdown()


@contextmanager
def http_jsonrpc_server(  # pylint: disable=too-many-arguments
	log_file=None,
	ip_version=None,
	server_key=None,
	server_cert=None,
	response_headers=None,
	response_status=None,
	response_body=None,
	response_delay=None
):
	timeout = 5
	server = HTTPJSONRPCServer(
		log_file, ip_version, server_key, server_cert, response_headers, response_status, response_body, response_delay
	)
	server.daemon = True
	server.start()

	running = False
	start = time.time()
	while time.time() - start < timeout:
		with closing(socket.socket(socket.AF_INET6 if ip_version == 6 else socket.AF_INET, socket.SOCK_STREAM)) as sock:
			sock.settimeout(1)
			res = sock.connect_ex(("::1" if ip_version == 6 else "127.0.0.1", server.port))
			if res == 0:
				running = True
				break

	if not running:
		raise RuntimeError("Failed to start HTTPJSONRPCServer")
	try:
		yield server
	finally:
		server.stop()


@contextmanager
def environment(env_vars: dict):
	old_environ = os.environ.copy()
	os.environ.update(env_vars)
	#print(os.environ)
	try:
		yield
	finally:
		os.environ.clear()
		os.environ.update(old_environ)
