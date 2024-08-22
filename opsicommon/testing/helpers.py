# -*- coding: utf-8 -*-

# Copyright (C) 2014, 2015 Seven Watt <info@sevenwatt.com>
# https://gist.github.com/SevenW/47be2f9ab74cac26bf21#file-httpwebsocketshandler-py
# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing.
"""

import ctypes
import datetime
import gc
import gzip
import os
import platform
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
from io import BufferedReader, BytesIO, UnsupportedOperation
from pathlib import Path
from socketserver import BaseServer, ThreadingMixIn
from tempfile import NamedTemporaryFile
from typing import Any, Callable, Generator
from urllib.parse import urlsplit, urlunsplit

import lz4  # type: ignore[import]
from psutil import Process

from opsicommon.config.opsi import OpsiConfig
from opsicommon.ssl import as_pem, create_ca, create_server_cert
from opsicommon.utils import json_decode, json_encode, msgpack_decode


class WebSocketError(Exception):
	pass


class HTTPTestServerRequestHandler(SimpleHTTPRequestHandler):
	_ws_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	_opcode_continuation = 0x0
	_opcode_text = 0x1
	_opcode_binary = 0x2
	_opcode_close = 0x8
	_opcode_ping = 0x9
	_opcode_pong = 0xA

	mutex = threading.Lock()
	server: "ThreadingHTTPServer"

	def __init__(self, *args: Any, **kwargs: Any) -> None:
		if args[2].serve_directory:
			kwargs["directory"] = args[2].serve_directory
		super().__init__(*args, **kwargs)
		self._headers_send = False
		self._ws_connected = False
		self._ws_opcode = 0x0
		self.close_connection = False

	def _log(self, data: Any) -> None:
		if not self.server.log_file:
			return

		with open(self.server.log_file, "ab") as file:
			file.write(json_encode(data) + b"\n")

	def version_string(self) -> str:
		if self.server.response_headers:
			for name, value in self.server.response_headers.items():
				if name.lower() == "server":
					return value
		return super().version_string()

	def end_headers(self) -> None:
		if self.server.response_delay:
			time.sleep(self.server.response_delay)
		if self.server.response_headers:
			for name, value in self.server.response_headers.items():
				if name.lower() == "server":
					continue
				value = value.replace("{server_address}", f"{self.server.server_address[0]!r}:{self.server.server_address[1]!r}")
				value = value.replace("{host}", self.headers["Host"])
				self.send_header(name, value)
		super().end_headers()

	def _get_ranges(self, file_size: int) -> list[tuple[int, int]]:
		ranges: list[tuple[int, int]] = []
		range_head = self.headers.get("Range")
		if not range_head:
			return ranges

		for rah in [r.strip() for r in range_head.split("=")[1].split(",")]:
			str_start_byte, str_end_byte = rah.split("-")
			start_byte = int(str_start_byte or 0)
			end_byte = int(str_end_byte or file_size)
			if end_byte >= file_size:
				end_byte = file_size - 1
			ranges.append((start_byte, end_byte))
		return ranges

	def send_head(self) -> BufferedReader | BytesIO | None:
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
				index = os.path.join(path, index)
				if os.path.exists(index):
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
			file = open(path, "rb")
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

			ranges = self._get_ranges(fst.st_size)
			if ranges:
				self.send_response(HTTPStatus.PARTIAL_CONTENT)
			else:
				self.send_response(HTTPStatus.OK)
			if ranges:
				if len(ranges) == 1:
					self.send_header("Content-Type", ctype)
					length = ranges[0][1] - ranges[0][0] + 1
					self.send_header("Content-Length", str(length))
					self.send_header("Content-Range", f"bytes {ranges[0][0]}-{ranges[0][1]}/{fst.st_size}")
				else:
					boundary = "c293f38bd87c48919123cae944ab3486"
					self.send_header("Content-Type", f"multipart/byteranges; boundary={boundary}")
					length = 0
					for range_ in ranges:
						length += len(
							(
								f"\r\n--{boundary}\r\nContent-Type: {ctype}\r\n"
								f"Content-Range: bytes {range_[0]}-{range_[1]}/{fst.st_size}\r\n\r\n"
							).encode("ascii")
						)
						length += range_[1] - range_[0] + 1
					length += len(f"\r\n--{boundary}--".encode("ascii"))
					self.send_header("Content-Length", str(length))
			else:
				self.send_header("Content-Type", ctype)
				self.send_header("Content-Length", str(fst.st_size))
			self.send_header("Last-Modified", self.date_time_string(round(fst.st_mtime)))
			self.end_headers()
			return file
		except Exception:
			file.close()
			raise

	def send_response(self, code: int, message: str | None = None) -> None:
		self.log_request(code)
		self.send_response_only(code, message)
		self.send_header("Server", self.version_string())
		if "date" not in [hdr.lower() for hdr in self.server.response_headers or {}]:
			self.send_header("Date", self.date_time_string())

	def do_POST(self) -> None:
		length = int(self.headers["Content-Length"])
		request: Any = self.rfile.read(length)

		if self.headers["Content-Encoding"] == "lz4":
			request = lz4.frame.decompress(request)
		elif self.headers["Content-Encoding"] == "gzip":
			request = gzip.decompress(request)

		if "json" in self.headers.get("Content-Type", ""):
			request = json_decode(request)
		elif "msgpack" in self.headers.get("Content-Type", ""):
			request = msgpack_decode(request)

		log_request = b64encode(request).decode("ascii") if isinstance(request, bytes) else request
		request_info = {
			"method": "POST",
			"client_address": self.client_address,
			"path": self.path,
			"headers": dict(self.headers),
			"request": log_request,
		}

		self._log(request_info)
		response = None
		if self.server.response_body:
			response = self.server.response_body
		elif "json" in self.headers.get("Content-Type", "") or "msgpack" in self.headers.get("Content-Type", ""):
			response = json_encode({"id": request["id"], "result": []})
		else:
			response = b""

		if self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
		else:
			self.send_response(200, "OK")
		self.send_header("Content-Length", str(len(response)))
		self.send_header("Content-Type", "application/json")
		self.end_headers()
		if self.server.send_max_bytes:
			response = response[: self.server.send_max_bytes]
		self.wfile.write(response)
		if self.server.request_callback:
			self.server.request_callback(self.server.test_server, request_info)

	def do_GET(self) -> None:
		request_info = {"method": "GET", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)}
		self._log(request_info)
		if self.headers.get("Upgrade") == "websocket":
			if self.server.response_status:
				self.send_response(self.server.response_status[0], self.server.response_status[1])
				self.end_headers()
				if self.server.request_callback:
					self.server.request_callback(self.server.test_server, request_info)
				return None

			self._ws_handshake()
			# This handler is in websocket mode now.
			# do_GET only returns after client close or socket error.
			self._ws_read_messages()
			return None

		if self.server.serve_directory:
			file = self.send_head()
			if file:
				try:
					response = b""
					try:
						file_size = os.fstat(file.fileno()).st_size
					except UnsupportedOperation:
						file_size = 0
					ranges = self._get_ranges(file_size)
					if ranges:
						if len(ranges) == 1:
							file.seek(ranges[0][0])
							response = file.read(ranges[0][1] - ranges[0][0] + 1)
						else:
							path = self.translate_path(self.path)
							ctype = self.guess_type(path)
							boundary = "c293f38bd87c48919123cae944ab3486"
							for range_ in ranges:
								response += (
									f"\r\n--{boundary}\r\nContent-Type: {ctype}\r\n"
									f"Content-Range: bytes {range_[0]}-{range_[1]}/{file_size}\r\n\r\n"
								).encode("ascii")
								file.seek(range_[0])
								response += file.read(range_[1] - range_[0] + 1)
							response += f"\r\n--{boundary}--".encode("ascii")
					else:
						response = file.read()
					if self.server.send_max_bytes:
						response = response[: self.server.send_max_bytes]
					self.wfile.write(response)
				finally:
					file.close()
			if self.server.request_callback:
				self.server.request_callback(self.server.test_server, request_info)
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
			response = response[: self.server.send_max_bytes]
		self.wfile.write(response)
		if self.server.request_callback:
			self.server.request_callback(self.server.test_server, request_info)
		return None

	def do_PUT(self) -> None:
		"""Serve a PUT request."""
		request_info = {"method": "PUT", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)}
		self._log(request_info)
		if self.server.serve_directory:
			path = self.translate_path(self.path)
			length = int(self.headers["Content-Length"])
			with open(path, "wb") as file:
				file.write(self.rfile.read(length))
			self.send_response(201, "Created")
			self.end_headers()
		elif self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
			self.end_headers()
		else:
			self.send_response(500, "Not implemented")
			self.end_headers()
		if self.server.request_callback:
			self.server.request_callback(self.server.test_server, request_info)

	def do_MKCOL(self) -> None:
		"""Serve a MKCOL request."""
		request_info = {"method": "MKCOL", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)}
		self._log(request_info)
		if self.server.serve_directory:
			path = self.translate_path(self.path)
			os.makedirs(path)
			self.send_response(201, "Created")
			self.end_headers()
		else:
			self.send_response(500, "Not implemented")
			self.end_headers()
		if self.server.request_callback:
			self.server.request_callback(self.server.test_server, request_info)

	def do_DELETE(self) -> None:
		"""Serve a DELETE request."""
		request_info = {"method": "DELETE", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)}
		self._log(request_info)
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
		if self.server.request_callback:
			self.server.request_callback(self.server.test_server, request_info)

	def do_HEAD(self) -> None:
		"""Serve a HEAD request."""
		request_info = {"method": "HEAD", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)}
		self._log(request_info)
		if self.server.serve_directory:
			super().do_HEAD()
		else:
			self.send_response(200, "OK")
			self.end_headers()
		if self.server.request_callback:
			self.server.request_callback(self.server.test_server, request_info)

	def do_CONNECT(self) -> None:
		"""
		Serve a CONNECT request.
		For example, the CONNECT method can be used to access websites that use SSL (HTTPS).
		The client asks an HTTP Proxy server to tunnel the TCP connection to the desired destination.
		The server then proceeds to make the connection on behalf of the client.
		Once the connection has been established by the server, the Proxy server continues to proxy the TCP stream to and from the client.
		"""
		request_info = {"method": "CONNECT", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)}
		self._log(request_info)
		self.send_response(501, "I am not a proxy")
		self.end_headers()
		if self.server.request_callback:
			self.server.request_callback(self.server.test_server, request_info)

	def on_ws_message(self, message: bytes) -> None:
		# print("Websocket message", message)
		log_message = b64encode(message).decode("ascii") if isinstance(message, bytes) else message
		self._log(
			{
				"method": "websocket",
				"client_address": self.client_address,
				"path": self.path,
				"headers": dict(self.headers),
				"request": log_message,
			}
		)
		if self.server.ws_message_callback:
			self.server.ws_message_callback(self, message)

	def on_ws_connected(self) -> None:
		# print("Websocket connected")
		if self.server.ws_connect_callback:
			self.server.ws_connect_callback(self)

	def on_ws_closed(self) -> None:
		# print("Websocket closed")
		pass

	def _ws_read_messages(self) -> None:
		try:
			self.connection.setblocking(False)
			while self._ws_connected:
				try:
					if self.server.stopping:
						return
					self._ws_read_next_message()
				except ssl.SSLWantReadError:
					# Timeout on non blocking read
					time.sleep(0.1)
				except WebSocketError as err:
					if "read aborted while listening" in str(err):
						time.sleep(0.1)
					else:
						raise
		except (socket.error, WebSocketError):
			self._ws_close()
		except Exception:
			self._ws_close()

	def _ws_read_next_message(self) -> None:
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

	def ws_send_message(self, message: bytes) -> None:
		self._ws_send_message(self._opcode_binary, message)

	def _ws_send_message(self, opcode: int, message: bytes) -> None:
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
		except Exception as err:
			# Unexpected error in websocket connection.
			print(err)
			self._ws_close()

	def _ws_handshake(self) -> None:
		headers = self.headers
		if headers.get("Upgrade", None) != "websocket":
			return
		key = headers["Sec-WebSocket-Key"]
		digest = b64encode(sha1((key + self._ws_GUID).encode("ascii")).digest()).decode("ascii")
		self.send_response(101, "Switching Protocols")
		self.send_header("Upgrade", "websocket")
		self.send_header("Connection", "Upgrade")
		self.send_header("Sec-WebSocket-Accept", digest)
		self.end_headers()
		self._ws_connected = True
		self.on_ws_connected()

	def _ws_close(self, code: int = 1005, reason: str = "") -> None:
		# Avoid closing a single socket two time for send and receive.
		with self.mutex:
			if self._ws_connected:
				self._ws_connected = False
				# Terminate BaseHTTPRequestHandler.handle() loop:
				self.close_connection = True
				# Send close and ignore exceptions. An error may already have occurred.
				try:
					self._ws_send_close(code, reason)
					time.sleep(1)
				except Exception:
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
			self._ws_send_message(self._opcode_pong, message)
		# pong
		elif self._ws_opcode == self._opcode_pong:
			pass
		# data
		elif self._ws_opcode in (self._opcode_continuation, self._opcode_text, self._opcode_binary):
			self.on_ws_message(message)

	def _ws_send_close(self, code: int, reason: str = "") -> None:
		# Dedicated _send_close allows for catch all exception handling
		breason = reason.encode("utf-8")
		if reason and not code:
			code = 1000
		length = (2 if code else 0) + len(breason)
		self.wfile.write(bytes([0x80 + self._opcode_close]) + bytes([length]))
		if reason:
			self.wfile.write(struct.pack("!H", code) + breason)


# Use ThreadingMixIn to handle requests in a separate thread
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
	block_on_close = True
	daemon_threads = False
	allow_reuse_address = True

	def __init__(self, test_server: "HTTPTestServer", server_address: tuple[str, int], address_family: int = socket.AF_INET) -> None:
		self.address_family = address_family
		super().__init__(server_address, HTTPTestServerRequestHandler)
		self.test_server = test_server
		self.stopping = False

	@property
	def log_file(self) -> str | None:
		return self.test_server.log_file

	@property
	def response_headers(self) -> dict[str, str] | None:
		return self.test_server.response_headers

	@property
	def response_status(self) -> tuple[int, str] | None:
		return self.test_server.response_status

	@property
	def response_body(self) -> bytes | None:
		return self.test_server.response_body

	@property
	def response_delay(self) -> float | None:
		return self.test_server.response_delay

	@property
	def request_callback(self) -> Callable | None:
		return self.test_server.request_callback

	@property
	def ws_connect_callback(self) -> Callable | None:
		return self.test_server.ws_connect_callback

	@property
	def ws_message_callback(self) -> Callable | None:
		return self.test_server.ws_message_callback

	@property
	def serve_directory(self) -> str | Path | None:
		return self.test_server.serve_directory

	@property
	def send_max_bytes(self) -> int | None:
		return self.test_server.send_max_bytes


class HTTPTestServer(threading.Thread, BaseServer):
	def __init__(
		self,
		*,
		log_file: Path | str | None = None,
		ip_version: str | int | None = None,
		server_key: Path | str | None = None,
		server_cert: Path | str | None = None,
		ca_cert: Path | str | None = None,
		generate_cert: bool = False,
		client_verify_mode: ssl.VerifyMode = ssl.CERT_NONE,
		response_headers: dict[str, str] | None = None,
		response_status: tuple[int, str] | None = None,
		response_body: bytes | None = None,
		response_delay: float | None = None,
		request_callback: Callable | None = None,
		ws_connect_callback: Callable | None = None,
		ws_message_callback: Callable | None = None,
		serve_directory: str | Path | None = None,
		send_max_bytes: int | None = None,
	) -> None:
		super().__init__()
		self.log_file = str(log_file) if log_file else None
		self.ip_version = 6 if int(ip_version or 4) == 6 else 4
		self.ca_key: Path | None = None
		self.ca_cert: Path | None = Path(ca_cert) if ca_cert else None
		self.server_key: Path | None = Path(server_key) if server_key else None
		self.server_cert: Path | None = Path(server_cert) if server_cert else None
		self.generate_cert = generate_cert
		self.client_verify_mode = client_verify_mode
		self.response_headers = response_headers if response_headers else {}
		self.response_status = response_status if response_status else None
		self.response_body = response_body if response_body else None
		self.response_delay = response_delay if response_delay else None
		self.request_callback = request_callback if request_callback else None
		self.ws_connect_callback = ws_connect_callback if ws_connect_callback else None
		self.ws_message_callback = ws_message_callback if ws_message_callback else None
		self.serve_directory = str(serve_directory) if serve_directory else None
		self.send_max_bytes = int(send_max_bytes) if send_max_bytes else None
		self._restart_server = False
		self._cleanup_done = threading.Event()
		# Auto select free port
		with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
			sock.bind(("", 0))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.port = sock.getsockname()[1]
		self.server: ThreadingHTTPServer | None = None

	def run(self) -> None:
		while True:
			self._restart_server = False
			self._cleanup_done.clear()
			if self.generate_cert:
				self._generate_cert()
			self.server = ThreadingHTTPServer(
				self,
				("::" if self.ip_version == 6 else "", self.port),
				socket.AF_INET6 if self.ip_version == 6 else socket.AF_INET,
			)
			self._init_ssl_socket()
			# print("Server listening on port:" + str(self.port))
			self.server.serve_forever()
			if not self._restart_server:
				break
			time.sleep(3)
			# print("Server restarting")

	def set_option(self, name: str, value: Any) -> None:
		setattr(self, name, value)

	def _generate_cert(self) -> None:
		if self.server_key and self.server_key.exists() and self.server_cert and self.server_cert.exists():
			return

		# Use 2048 bits for speedup
		ca_cert, ca_key = create_ca(subject={"CN": "http_test_server ca"}, valid_days=3, bits=2048)

		tmp = NamedTemporaryFile(delete=False)
		tmp.write(as_pem(ca_key).encode("utf-8"))
		tmp.close()
		self.ca_key = Path(tmp.name)

		tmp = NamedTemporaryFile(delete=False)
		tmp.write(as_pem(ca_cert).encode("utf-8"))
		tmp.close()
		self.ca_cert = Path(tmp.name)

		kwargs: dict[str, Any] = {
			"subject": {"CN": "http_test_server server cert"},
			"valid_days": 3,
			"ip_addresses": {"172.0.0.1", "::1"},
			"hostnames": {"localhost", "ip6-localhost"},
			"ca_key": ca_key,
			"ca_cert": ca_cert,
			"bits": 2048,
		}
		cert, key = create_server_cert(**kwargs)

		tmp = NamedTemporaryFile(delete=False)
		tmp.write(as_pem(key).encode("utf-8"))
		tmp.close()
		self.server_key = Path(tmp.name)

		tmp = NamedTemporaryFile(delete=False)
		tmp.write(as_pem(cert).encode("utf-8"))
		tmp.close()
		self.server_cert = Path(tmp.name)

	def _cleanup_cert(self) -> None:
		if self.generate_cert:
			if self.ca_key and self.ca_key.exists():
				self.ca_key.unlink()
			if self.ca_cert and self.ca_cert.exists():
				self.ca_cert.unlink()
			if self.server_key and self.server_key.exists():
				self.server_key.unlink()
			if self.server_cert and self.server_cert.exists():
				self.server_cert.unlink()

	def _init_ssl_socket(self) -> None:
		if self.server and self.server_key and self.server_cert:
			context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			context.verify_mode = self.client_verify_mode
			context.load_cert_chain(keyfile=str(self.server_key), certfile=str(self.server_cert))
			if self.ca_cert:
				context.load_verify_locations(cafile=str(self.ca_cert))
			self.server.socket = context.wrap_socket(sock=self.server.socket, server_side=True)

	def stop(self, cleanup_cert: bool = True) -> None:
		try:
			if self.server:
				self.server.stopping = True
				if self._restart_server and platform.system().lower() != "windows":
					self.server.socket.close()
				self.server.shutdown()
				if self._restart_server and platform.system().lower() == "windows":
					self.server.socket.close()
		finally:
			if cleanup_cert:
				self._cleanup_cert()
			self._cleanup_done.set()

	def restart(self, new_cert: bool = False) -> None:
		if not self.server:
			return
		self._restart_server = True
		self.stop(not new_cert)
		self.wait_for_server_socket()

	def wait_for_server_socket(self, timeout: int = 15) -> bool:
		start = time.time()
		sock_type = socket.AF_INET6 if self.ip_version == 6 else socket.AF_INET
		while time.time() - start < timeout:
			with closing(socket.socket(sock_type, socket.SOCK_STREAM)) as sock:
				sock.settimeout(1)
				res = sock.connect_ex(("::1" if self.ip_version == 6 else "127.0.0.1", self.port))
				if res == 0:
					return True
		return False


@contextmanager
def http_test_server(
	*,
	log_file: Path | str | None = None,
	ip_version: str | int | None = None,
	ca_cert: Path | str | None = None,
	server_key: Path | str | None = None,
	server_cert: Path | str | None = None,
	generate_cert: bool = False,
	client_verify_mode: ssl.VerifyMode = ssl.CERT_NONE,
	response_headers: dict[str, str] | None = None,
	response_status: tuple[int, str] | None = None,
	response_body: bytes | None = None,
	response_delay: float | None = None,
	request_callback: Callable | None = None,
	ws_connect_callback: Callable | None = None,
	ws_message_callback: Callable | None = None,
	serve_directory: str | Path | None = None,
	send_max_bytes: int | None = None,
) -> Generator[HTTPTestServer, None, None]:
	server = HTTPTestServer(
		log_file=log_file,
		ip_version=ip_version,
		ca_cert=ca_cert,
		server_key=server_key,
		server_cert=server_cert,
		generate_cert=generate_cert,
		client_verify_mode=client_verify_mode,
		response_headers=response_headers,
		response_status=response_status,
		response_body=response_body,
		response_delay=response_delay,
		request_callback=request_callback,
		ws_connect_callback=ws_connect_callback,
		ws_message_callback=ws_message_callback,
		serve_directory=serve_directory,
		send_max_bytes=send_max_bytes,
	)
	server.daemon = True
	server.start()
	if not server.wait_for_server_socket():
		raise RuntimeError("Failed to start HTTPTestServer")
	try:
		yield server
	finally:
		server.stop()


@contextmanager
def environment(env_vars: dict[str, str]) -> Generator[dict[str, str], None, None]:
	old_environ = os.environ.copy()
	os.environ.update(env_vars)
	try:
		yield dict(os.environ.items())
	finally:
		os.environ.clear()
		os.environ.update(old_environ)


@contextmanager
def opsi_config(conf_vars: dict[str, Any]) -> Generator[OpsiConfig, None, None]:
	orig_config_file = OpsiConfig.config_file
	config_file = NamedTemporaryFile(delete=False)
	opsi_conf = OpsiConfig(upgrade_config=False)
	try:
		opsi_conf.config_file = config_file.name
		for key, value in conf_vars.items():
			category, config = key.split(".", 1)
			opsi_conf.set(category, config, value, persistent=False)
		yield opsi_conf
	finally:
		opsi_conf.config_file = orig_config_file
		try:
			if os.path.exists(config_file.name):
				os.unlink(config_file.name)
		except Exception:
			pass


class MemoryUsageMonitor(threading.Thread):
	def __init__(self, interval: float = 1.0) -> None:
		super().__init__(daemon=True)
		self._interval = max(interval, 0.01)
		self._process = Process(os.getpid())
		self._should_stop = threading.Event()
		self._system = platform.system()
		self.started = threading.Event()
		self.stopped = threading.Event()
		self.rss_values: list[float] = []

	def _memory_cleanup(self) -> None:
		gc.collect()
		if self._system == "Linux":
			ctypes.CDLL("libc.so.6").malloc_trim(0)

	def run(self) -> None:
		self._memory_cleanup()
		self.rss_values.append(self._process.memory_info().rss)
		self.started.set()
		while not self._should_stop.wait(self._interval):
			self.rss_values.append(self._process.memory_info().rss)
		self._memory_cleanup()
		self.rss_values.append(self._process.memory_info().rss)
		self.stopped.set()

	def stop(self) -> None:
		self._should_stop.set()
		self.stopped.wait(self._interval + 1.0)

	def print_stats(self) -> None:
		print("Memory usage statistics:")
		print(f"  Start RSS: {self.start_rss / 1_000_000:.2f} MB")
		print(f"  End RSS: {self.end_rss / 1_000_000:.2f} MB")
		print(f"  Min RSS: {self.min_rss / 1_000_000:.2f} MB")
		print(f"  Max RSS: {self.max_rss / 1_000_000:.2f} MB")
		print(f"  Avg RSS: {self.avg_rss / 1_000_000:.2f} MB")
		print(f"  Max increase RSS: {self.max_increase_rss / 1024 / 1024:.2f} MB")

	@property
	def max_increase_rss(self) -> float:
		return (max(self.rss_values) - self.start_rss) if self.rss_values else 0.0

	@property
	def max_rss(self) -> float:
		return max(self.rss_values) if self.rss_values else 0.0

	@property
	def min_rss(self) -> float:
		return min(self.rss_values) if self.rss_values else 0.0

	@property
	def avg_rss(self) -> float:
		return (sum(self.rss_values) / len(self.rss_values)) if self.rss_values else 0.0

	@property
	def start_rss(self) -> float:
		return self.rss_values[0] if self.rss_values else 0.0

	@property
	def end_rss(self) -> float:
		return self.rss_values[-1] if self.rss_values else 0.0


@contextmanager
def memory_usage_monitor(interval: float = 1.0) -> Generator[MemoryUsageMonitor, None, None]:
	monitor = MemoryUsageMonitor(interval)
	monitor.start()
	monitor.started.wait(5.0)
	try:
		yield monitor
	finally:
		if monitor.is_alive():
			monitor.stop()
