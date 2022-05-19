# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing.
"""

import datetime
import email
import gzip
import json
import os
import shutil
import socket
import ssl
import threading
import time
import urllib
from contextlib import closing, contextmanager
from http import HTTPStatus
from http.server import HTTPServer, SimpleHTTPRequestHandler

import lz4  # type: ignore[import]
import msgpack  # type: ignore[import]


class HTTPTestServerRequestHandler(SimpleHTTPRequestHandler):
	def __init__(self, *args, **kwargs):
		if args[2].serve_directory:
			kwargs["directory"] = args[2].serve_directory
		super().__init__(*args, **kwargs)
		self._headers_send = False

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

	def end_headers(self):
		if self.server.response_delay:
			time.sleep(self.server.response_delay)
		for name, value in self.server.response_headers.items():
			if name.lower() == "server":
				continue
			value = value.replace("{server_address}", f"{self.server.server_address[0]}:{self.server.server_address[1]}")
			value = value.replace("{host}", self.headers["Host"])
			self.send_header(name, value)
		super().end_headers()

	def send_head(self):  # pylint: disable=too-many-branches,too-many-statements
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
			parts = urllib.parse.urlsplit(self.path)
			if not parts.path.endswith("/"):
				# redirect browser - doing basically what apache does
				self.send_response(HTTPStatus.MOVED_PERMANENTLY)
				new_parts = (parts[0], parts[1], parts[2] + "/", parts[3], parts[4])
				new_url = urllib.parse.urlunsplit(new_parts)
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
					ims = email.utils.parsedate_to_datetime(self.headers["If-Modified-Since"])
				except (TypeError, IndexError, OverflowError, ValueError):
					# ignore ill-formed values
					pass
				else:
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
			self.send_header("Last-Modified", self.date_time_string(fst.st_mtime))
			self.end_headers()
			return file
		except Exception:  # pylint: disable=broad-except
			file.close()
			raise

	def do_POST(self):  # pylint: disable=invalid-name
		length = int(self.headers["Content-Length"])
		request = self.rfile.read(length)

		if self.headers["Content-Encoding"] == "lz4":
			request = lz4.frame.decompress(request)
		elif self.headers["Content-Encoding"] == "gzip":
			request = gzip.decompress(request)

		if "json" in self.headers.get("Content-Type", ""):
			request = json.loads(request)
		elif "msgpack" in self.headers.get("Content-Type", ""):
			request = msgpack.loads(request)

		self._log(
			{"method": "POST", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers), "request": request}
		)
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
		self.send_header("Content-Length", str(len(response)))
		self.send_header("Content-Type", "application/json")
		self.end_headers()
		if self.server.send_max_bytes:
			response = response[:self.server.send_max_bytes]
		self.wfile.write(response)

	def do_GET(self):  # pylint: disable=invalid-name
		self._log({"method": "GET", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)})
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

		response = None
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

	def do_PUT(self):  # pylint: disable=invalid-name
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

	def do_MKCOL(self):  # pylint: disable=invalid-name
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

	def do_DELETE(self):  # pylint: disable=invalid-name
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

	def do_HEAD(self):  # pylint: disable=invalid-name
		"""Serve a HEAD request."""
		self._log({"method": "HEAD", "client_address": self.client_address, "path": self.path, "headers": dict(self.headers)})
		if self.server.serve_directory:
			super().do_HEAD()
		else:
			self.send_response(200, "OK")
			self.end_headers()


class HTTPTestServer(threading.Thread):  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments
		self,
		log_file=None,
		ip_version=None,
		server_key=None,
		server_cert=None,
		response_headers=None,
		response_status=None,
		response_body=None,
		response_delay=None,
		serve_directory=None,
		send_max_bytes=None
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
		self.serve_directory = str(serve_directory) if serve_directory else None
		self.send_max_bytes = int(send_max_bytes) if send_max_bytes else None
		# Auto select free port
		with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
			sock.bind(("", 0))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.port = sock.getsockname()[1]
		self.server = None

	def run(self):
		class HTTPServer6(HTTPServer):
			address_family = socket.AF_INET6

		if self.ip_version == 6:
			self.server = HTTPServer6(("::", self.port), HTTPTestServerRequestHandler)
		else:
			self.server = HTTPServer(("", self.port), HTTPTestServerRequestHandler)

		if self.server_key and self.server_cert:
			context = ssl.SSLContext()
			context.load_cert_chain(keyfile=self.server_key, certfile=self.server_cert)
			self.server.socket = context.wrap_socket(sock=self.server.socket, server_side=True)
		self.server.log_file = self.log_file  # pylint: disable=attribute-defined-outside-init
		self.server.response_headers = self.response_headers  # pylint: disable=attribute-defined-outside-init
		self.server.response_status = self.response_status  # pylint: disable=attribute-defined-outside-init
		self.server.response_body = self.response_body  # pylint: disable=attribute-defined-outside-init
		self.server.response_delay = self.response_delay  # pylint: disable=attribute-defined-outside-init
		self.server.serve_directory = self.serve_directory  # pylint: disable=attribute-defined-outside-init
		self.server.send_max_bytes = self.send_max_bytes  # pylint: disable=attribute-defined-outside-init
		# print("Server listening on port:" + str(self.port))
		self.server.serve_forever()

	def set_option(self, name, value):
		setattr(self.server, name, value)

	def stop(self):
		if self.server:
			self.server.shutdown()


@contextmanager
def http_test_server(  # pylint: disable=too-many-arguments
	log_file=None,
	ip_version=None,
	server_key=None,
	server_cert=None,
	response_headers=None,
	response_status=None,
	response_body=None,
	response_delay=None,
	serve_directory=None,
	send_max_bytes=None
):
	timeout = 5
	server = HTTPTestServer(
		log_file, ip_version, server_key, server_cert, response_headers, response_status, response_body, response_delay, serve_directory, send_max_bytes
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
		raise RuntimeError("Failed to start HTTPTestServer")
	try:
		yield server
	finally:
		server.stop()


@contextmanager
def environment(env_vars: dict):
	old_environ = os.environ.copy()
	os.environ.update(env_vars)
	try:
		yield
	finally:
		os.environ.clear()
		os.environ.update(old_environ)
