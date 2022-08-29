# -*- coding: utf-8 -*-

# Copyright (C) 2014, 2015 Seven Watt <info@sevenwatt.com>
# https://gist.github.com/SevenW/47be2f9ab74cac26bf21#file-httpwebsocketshandler-py
# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing.
"""

import datetime
import gzip
import json
import os
import shutil
import socket
import ssl
import struct
import threading
import time
from base64 import b64encode
from contextlib import closing, contextmanager
from email.utils import parsedate_to_datetime
from hashlib import sha1
from http import HTTPStatus
from http.server import HTTPServer, SimpleHTTPRequestHandler
from io import BufferedReader, BytesIO
from pathlib import Path
from socketserver import BaseServer
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Generator, Optional, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

import lz4  # type: ignore[import]
import msgpack  # type: ignore[import]

from opsicommon.ssl import as_pem, create_ca, create_server_cert  # type: ignore[import]


class WebSocketError(Exception):
	pass


class HTTPTestServerRequestHandler(SimpleHTTPRequestHandler):
	_ws_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
	_opcode_continuation = 0x0
	_opcode_text = 0x1
	_opcode_binary = 0x2
	_opcode_close = 0x8
	_opcode_ping = 0x9
	_opcode_pong = 0xa

	mutex = threading.Lock()
	server: "HTTPTestServer"

	def __init__(self, *args: Any, **kwargs: Any) -> None:
		if args[2].serve_directory:
			kwargs["directory"] = args[2].serve_directory
		super().__init__(*args, **kwargs)
		self._headers_send = False
		self._ws_connected = False
		self._ws_opcode = 0x0
		self.close_connection = False

	def _log(self, data: Any) -> None:  # pylint: disable=invalid-name
		if not self.server.log_file:
			return

		with open(self.server.log_file, "a", encoding="utf-8") as file:
			file.write(json.dumps(data))
			file.write("\n")
			file.flush()

	def version_string(self) -> str:
		for name, value in self.server.response_headers.items():
			if name.lower() == "server":
				return value
		return super().version_string()

	def end_headers(self) -> None:
		if self.server.response_delay:
			time.sleep(self.server.response_delay)
		for name, value in self.server.response_headers.items():
			if name.lower() == "server":
				continue
			value = value.replace("{server_address}", f"{self.server.server_address[0]}:{self.server.server_address[1]}")
			value = value.replace("{host}", self.headers["Host"])
			self.send_header(name, value)
		super().end_headers()

	def send_head(self) -> Union[None, BufferedReader, BytesIO]:  # pylint: disable=too-many-branches,too-many-statements
		"""Common code for GET and HEAD commands.

		This sends the response code and MIME headers.

		Return value is either a file object (which has to be copied
		to the outputfile by the caller unless the command was HEAD,
		and must be closed by the caller under all circumstances), or
		None, in which case the caller has nothing further to do.

		"""
		path = self.translate_path(self.path)
		file = None
		if os.path.isdir(path):
			parts = urlsplit(self.path)
			if not parts.path.endswith("/"):
				# redirect browser - doing basically what apache does
				self.send_response(HTTPStatus.MOVED_PERMANENTLY)
				new_parts = (parts[0], parts[1], parts[2] + "/", parts[3], parts[4])
				new_url = urlunsplit(new_parts)
				self.send_header("Location", new_url)
				self.end_headers()
				return None
			for index in "index.html", "index.htm":
				index = os.path.join(path, index)  # pylint: disable=dotted-import-in-loop
				if os.path.exists(index):  # pylint: disable=dotted-import-in-loop
					path = index
					break
			else:
				return self.list_directory(path)

		ctype = self.guess_type(path)
		# check for trailing "/" which should return 404. See Issue17324
		# The test for this was added in test_httpserver.py
		# However, some OS platforms accept a trailingSlash as a filename
		# See discussion on python-dev and Issue34711 regarding
		# parseing and rejection of filenames with a trailing slash
		if path.endswith("/"):
			self.send_error(HTTPStatus.NOT_FOUND, "File not found")
			return None
		try:
			file = open(path, "rb")  # pylint: disable=consider-using-with
		except OSError:
			self.send_error(HTTPStatus.NOT_FOUND, "File not found")
			return None

		try:
			fst = os.fstat(file.fileno())
			# Use browser cache if possible
			if "If-Modified-Since" in self.headers and "If-None-Match" not in self.headers:
				# compare If-Modified-Since and time of last file modification
				try:
					ims = parsedate_to_datetime(self.headers["If-Modified-Since"])
				except (TypeError, IndexError, OverflowError, ValueError):
					# ignore ill-formed values
					ims = None
				if ims:
					if ims.tzinfo is None:
						# obsolete format with no timezone, cf.
						# https://tools.ietf.org/html/rfc7231#section-7.1.1.1
						ims = ims.replace(tzinfo=datetime.timezone.utc)
					if ims.tzinfo is datetime.timezone.utc:
						# compare to UTC datetime of last modification
						last_modif = datetime.datetime.fromtimestamp(fst.st_mtime, datetime.timezone.utc)
						# remove microseconds, like in If-Modified-Since
						last_modif = last_modif.replace(microsecond=0)

						if last_modif <= ims:
							self.send_response(HTTPStatus.NOT_MODIFIED)
							self.end_headers()
							file.close()
							return None

			range_ = self.headers.get("Range")
			if range_:
				self.send_response(HTTPStatus.PARTIAL_CONTENT)
			else:
				self.send_response(HTTPStatus.OK)
			self.send_header("Content-type", ctype)
			if range_:
				start_byte, end_byte = range_.split("=")[1].split("-")
				start_byte = int(start_byte or 0)
				end_byte = int(end_byte or fst[6])
				if end_byte >= fst[6]:
					end_byte = fst[6] - 1
				self.send_header("Content-Length", str(end_byte - start_byte + 1))
				self.send_header("Content-Range", f"bytes {start_byte}-{end_byte}/{fst[6]}")
			else:
				self.send_header("Content-Length", str(fst[6]))
			self.send_header("Last-Modified", self.date_time_string(round(fst.st_mtime)))
			self.end_headers()
			return file
		except Exception:  # pylint: disable=broad-except
			file.close()
			raise

	def do_POST(self) -> None:  # pylint: disable=invalid-name
		length = int(self.headers["Content-Length"])
		request: Any = self.rfile.read(length)

		if self.headers["Content-Encoding"] == "lz4":
			request = lz4.frame.decompress(request)
		elif self.headers["Content-Encoding"] == "gzip":
			request = gzip.decompress(request)

		if "json" in self.headers.get("Content-Type", ""):
			request = json.loads(request)
		elif "msgpack" in self.headers.get("Content-Type", ""):
			request = msgpack.loads(request)

		log_request = b64encode(request).decode("ascii") if isinstance(request, bytes) else request
		self._log(
			{"method": "POST", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers), "request": log_request}
		)
		response = None
		if self.server.response_body:
			response = self.server.response_body
		else:
			response = json.dumps({"id": request["id"], "result": []}).encode("utf-8")
		if self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
		else:
			self.send_response(200, "OK")
		self.send_header("Content-Length", str(len(response)))
		self.send_header("Content-Type", "application/json")
		self.end_headers()
		if self.server.send_max_bytes:
			response = response[:self.server.send_max_bytes]
		self.wfile.write(response)

	def do_GET(self) -> None:  # pylint: disable=invalid-name,too-many-branches
		self._log({"method": "GET", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)})
		if self.headers.get("Upgrade") == "websocket":
			self._ws_handshake()
			# This handler is in websocket mode now.
			# do_GET only returns after client close or socket error.
			self._ws_read_messages()
			return None

		if self.server.serve_directory:
			file = self.send_head()
			if file:
				try:
					range_ = self.headers.get("Range")
					response = b""
					if range_:
						#  Range: bytes=0-2047
						fst = os.fstat(file.fileno())
						start_byte, end_byte = range_.split("=")[1].split("-")
						start_byte = int(start_byte or 0)
						end_byte = int(end_byte or fst[6])
						file.seek(start_byte)
						response = file.read(end_byte - start_byte + 1)
					else:
						response = file.read()

					if self.server.send_max_bytes:
						response = response[:self.server.send_max_bytes]
					self.wfile.write(response)
				finally:
					file.close()
			return None

		if self.headers["X-Response-Status"]:
			val = self.headers["X-Response-Status"].split(" ", 1)
			self.send_response(int(val[0]), val[1])
		elif self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
		else:
			self.send_response(200, "OK")

		response = b""
		if self.server.response_body:
			response = self.server.response_body
		else:
			response = "OK".encode("utf-8")
		self.send_header("Content-Length", str(len(response)))
		self.end_headers()
		if self.server.send_max_bytes:
			response = response[:self.server.send_max_bytes]
		self.wfile.write(response)
		return None

	def do_PUT(self) -> None:  # pylint: disable=invalid-name
		"""Serve a PUT request."""
		self._log({"method": "PUT", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)})
		if self.server.serve_directory:
			path = self.translate_path(self.path)
			length = int(self.headers["Content-Length"])
			with open(path, "wb") as file:
				file.write(self.rfile.read(length))
			self.send_response(201, "Created")
			self.end_headers()
		else:
			self.send_response(500, "Not implemented")
			self.end_headers()

	def do_MKCOL(self) -> None:  # pylint: disable=invalid-name
		"""Serve a MKCOL request."""
		self._log({"method": "MKCOL", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)})
		if self.server.serve_directory:
			path = self.translate_path(self.path)
			os.makedirs(path)
			self.send_response(201, "Created")
			self.end_headers()
		else:
			self.send_response(500, "Not implemented")
			self.end_headers()

	def do_DELETE(self) -> None:  # pylint: disable=invalid-name
		"""Serve a DELETE request."""
		self._log({"method": "DELETE", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)})
		if self.server.serve_directory:
			path = self.translate_path(self.path)
			if os.path.exists(path):
				if os.path.isdir(path):
					shutil.rmtree(path)
				else:
					os.remove(path)
				self.send_response(204, "Deleted")
			else:
				self.send_response(404, "Not found")
			self.end_headers()
		else:
			self.send_response(500, "Not implemented")
			self.end_headers()

	def do_HEAD(self) -> None:  # pylint: disable=invalid-name
		"""Serve a HEAD request."""
		self._log({"method": "HEAD", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)})
		if self.server.serve_directory:
			super().do_HEAD()
		else:
			self.send_response(200, "OK")
			self.end_headers()

	def on_ws_message(self, message: bytes) -> None:
		# print("Websocket message", message)
		log_message = b64encode(message).decode("ascii") if isinstance(message, bytes) else message
		self._log(
			{"method": "websocket", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers), "request": log_message}
		)

	def on_ws_connected(self) -> None:
		# print("Websocket connected")
		self.ws_send_message(self._opcode_binary, self.server.response_body or b"")

	def on_ws_closed(self) -> None:
		# print("Websocket closed")
		pass

	def _ws_read_messages(self) -> None:
		try:
			while self._ws_connected:
				self._ws_read_next_message()
		except (socket.error, WebSocketError):
			self._ws_close()
		except Exception:  # pylint: disable=broad-except
			self._ws_close()

	def _ws_read_next_message(self) -> None:
		# self.rfile.read(n) is blocking.
		# It returns however immediately when the socket is closed.
		try:
			self._ws_opcode = ord(self.rfile.read(1)) & 0x0F
			length = ord(self.rfile.read(1)) & 0x7F
			if length == 126:
				length = struct.unpack(">H", self.rfile.read(2))[0]
			elif length == 127:
				length = struct.unpack(">Q", self.rfile.read(8))[0]
			masks = list(self.rfile.read(4))
			decoded = b""
			for char in self.rfile.read(length):
				decoded += bytes([char ^ masks[len(decoded) % 4]])
			self._ws_process_message(decoded)
		except (struct.error, TypeError) as err:
			# Catch exceptions from ord() and struct.unpack()
			if self._ws_connected:
				raise WebSocketError("Websocket read aborted while listening") from err
			# The socket was closed while waiting for input

	def ws_send_message(self, opcode: int, message: bytes) -> None:
		try:
			# Use of self.wfile.write gives socket exception after socket is closed. Avoid.
			self.wfile.write(bytes([0x80 + opcode]))
			length = len(message)
			if length <= 125:
				self.wfile.write(bytes([length]))
			elif 126 <= length <= 65535:
				self.wfile.write(bytes([126]))
				self.wfile.write(struct.pack(">H", length))
			else:
				self.wfile.write(bytes([127]))
				self.wfile.write(struct.pack(">Q", length))
			if length > 0:
				self.wfile.write(message)
		except socket.error:
			# Websocket content error, time-out or disconnect.
			self._ws_close()
		except Exception as err:  # pylint: disable=broad-except
			# Unexpected error in websocket connection.
			print(err)
			self._ws_close()

	def _ws_handshake(self) -> None:
		headers = self.headers
		if headers.get("Upgrade", None) != "websocket":
			return
		key = headers['Sec-WebSocket-Key']
		digest = b64encode(sha1((key + self._ws_GUID).encode("ascii")).digest()).decode("ascii")
		self.send_response(101, 'Switching Protocols')
		self.send_header('Upgrade', 'websocket')
		self.send_header('Connection', 'Upgrade')
		self.send_header('Sec-WebSocket-Accept', digest)
		self.end_headers()
		self._ws_connected = True
		self.on_ws_connected()

	def _ws_close(self) -> None:
		# Avoid closing a single socket two time for send and receive.
		with self.mutex:
			if self._ws_connected:
				self._ws_connected = False
				# Terminate BaseHTTPRequestHandler.handle() loop:
				self.close_connection = True
				# Send close and ignore exceptions. An error may already have occurred.
				try:
					self._ws_send_close()
				except Exception:  # pylint: disable=broad-except
					pass
				self.on_ws_closed()
			else:
				# _ws_close websocket in closed state. Ignore."
				pass

	def _ws_process_message(self, message: bytes) -> None:
		# close
		if self._ws_opcode == self._opcode_close:
			self._ws_close()
		# ping
		elif self._ws_opcode == self._opcode_ping:
			self.ws_send_message(self._opcode_pong, message)
		# pong
		elif self._ws_opcode == self._opcode_pong:
			pass
		# data
		elif self._ws_opcode in (self._opcode_continuation, self._opcode_text, self._opcode_binary):
			self.on_ws_message(message)

	def _ws_send_close(self) -> None:
		# Dedicated _send_close allows for catch all exception handling
		msg = bytearray()
		msg.append(0x80 + self._opcode_close)
		msg.append(0x00)
		self.wfile.write(msg)


class HTTPTestServer(threading.Thread, BaseServer):  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments
		self,
		*,
		log_file: str = None,
		ip_version: str = None,
		server_key: str = None,
		server_cert: str = None,
		response_headers: Dict[str, str] = None,
		response_status: Tuple[int, str] = None,
		response_body: bytes = None,
		response_delay: float = None,
		serve_directory: Union[str, Path] = None,
		send_max_bytes: int = None
	) -> None:
		super().__init__()
		self.log_file = str(log_file) if log_file else None
		self.ip_version = 6 if ip_version == 6 else 4
		self.server_key = server_key if server_key else None
		self.server_cert = server_cert if server_cert else None
		self.response_headers = response_headers if response_headers else {}
		self.response_status = response_status if response_status else None
		self.response_body = response_body if response_body else None
		self.response_delay = response_delay if response_delay else None
		self.serve_directory = str(serve_directory) if serve_directory else None
		self.send_max_bytes = int(send_max_bytes) if send_max_bytes else None
		# Auto select free port
		with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
			sock.bind(("", 0))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.port = sock.getsockname()[1]
		self.server: Optional[HTTPServer] = None

	def run(self) -> None:
		class HTTPServer6(HTTPServer):  # pylint: disable=too-many-instance-attributes
			address_family = socket.AF_INET6

		if self.ip_version == 6:
			self.server = HTTPServer6(("::", self.port), HTTPTestServerRequestHandler)
		else:
			self.server = HTTPServer(("", self.port), HTTPTestServerRequestHandler)

		if self.server_key and self.server_cert:
			context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			context.load_cert_chain(keyfile=self.server_key, certfile=self.server_cert)
			self.server.socket = context.wrap_socket(sock=self.server.socket, server_side=True)
		self.server.log_file = self.log_file  # type: ignore[attr-defined]  # pylint: disable=attribute-defined-outside-init
		self.server.response_headers = self.response_headers  # type: ignore[attr-defined]  # pylint: disable=attribute-defined-outside-init
		self.server.response_status = self.response_status  # type: ignore[attr-defined]  # pylint: disable=attribute-defined-outside-init
		self.server.response_body = self.response_body  # type: ignore[attr-defined]  # pylint: disable=attribute-defined-outside-init
		self.server.response_delay = self.response_delay  # type: ignore[attr-defined]  # pylint: disable=attribute-defined-outside-init
		self.server.serve_directory = self.serve_directory  # type: ignore[attr-defined]  # pylint: disable=attribute-defined-outside-init
		self.server.send_max_bytes = self.send_max_bytes  # type: ignore[attr-defined]  # pylint: disable=attribute-defined-outside-init
		# print("Server listening on port:" + str(self.port))
		self.server.serve_forever()

	def set_option(self, name: str, value: Any) -> None:
		setattr(self.server, name, value)

	def stop(self) -> None:
		if self.server:
			self.server.shutdown()


@contextmanager
def http_test_server(  # pylint: disable=too-many-arguments,too-many-locals
	*,
	log_file: str = None,
	ip_version: str = None,
	server_key: str = None,
	server_cert: str = None,
	generate_cert: bool = False,
	response_headers: Dict[str, str] = None,
	response_status: Tuple[int, str] = None,
	response_body: bytes = None,
	response_delay: float = None,
	serve_directory: Union[str, Path] = None,
	send_max_bytes: int = None
) -> Generator[HTTPTestServer, None, None]:
	if generate_cert:
		ca_cert, ca_key = create_ca({"CN": "http_test_server ca"}, 3)
		kwargs = {
			"subject": {"CN": "http_test_server server cert"},
			"valid_days": 3,
			"ip_addresses": {"172.0.0.1", "::1"},
			"hostnames": {"localhost", "ip6-localhost"},
			"ca_key": ca_key,
			"ca_cert": ca_cert
		}
		cert, key = create_server_cert(**kwargs)

		tmp = NamedTemporaryFile(delete=False)
		tmp.write(as_pem(key).encode("utf-8"))
		tmp.close()
		server_key = tmp.name

		tmp = NamedTemporaryFile(delete=False)
		tmp.write(as_pem(cert).encode("utf-8"))
		tmp.close()
		server_cert = tmp.name

	try:
		timeout = 5
		server = HTTPTestServer(
			log_file=log_file,
			ip_version=ip_version,
			server_key=server_key,
			server_cert=server_cert,
			response_headers=response_headers,
			response_status=response_status,
			response_body=response_body,
			response_delay=response_delay,
			serve_directory=serve_directory,
			send_max_bytes=send_max_bytes
		)
		server.daemon = True
		server.start()

		running = False
		start = time.time()
		sock_type = socket.AF_INET6 if ip_version == 6 else socket.AF_INET
		while time.time() - start < timeout:  # pylint: disable=dotted-import-in-loop
			with closing(socket.socket(sock_type, socket.SOCK_STREAM)) as sock:  # pylint: disable=dotted-import-in-loop
				sock.settimeout(1)
				res = sock.connect_ex(("::1" if ip_version == 6 else "127.0.0.1", server.port))  # pylint: disable=loop-invariant-statement
				if res == 0:
					running = True
					break

		if not running:
			raise RuntimeError("Failed to start HTTPTestServer")
		try:
			yield server
		finally:
			server.stop()
	finally:
		if generate_cert:
			if server_key:
				os.unlink(server_key)
			if server_cert:
				os.unlink(server_cert)


@contextmanager
def environment(env_vars: Dict[str, str]) -> Generator[Dict[str, str], None, None]:
	old_environ = os.environ.copy()
	os.environ.update(env_vars)
	try:
		yield dict(os.environ.items())
	finally:
		os.environ.clear()
		os.environ.update(old_environ)


if __name__ == "__main__":
	with http_test_server(generate_cert=True) as server:
		print(server.port)
		while True:
			time.sleep(1)
