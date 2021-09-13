# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""
import pytest
import os

import time
import subprocess
import http.server
import socketserver
import ssl
import threading
from OpenSSL.crypto import (
	FILETYPE_PEM, load_certificate
)

from opsicommon.ssl import install_ca, remove_ca
from OPSI.System import execute, isCentOS, isDebian, isOpenSUSE, isRHEL, isSLES, isUbuntu




def create_certification():
	print("create_certification")
	openssl = "openssl req -nodes -x509 -newkey rsa:2048 -days 730 -keyout tests/testopsicommon/data/ssl/ca.key -out tests/testopsicommon/data/ssl/ca.crt -new -sha512 -subj /C=DE/ST=RP/L=Mainz/O=uib/OU=root/CN=uib-Signing-Authority"
	print(openssl.split(" "))
	r = subprocess.call(openssl.split(" "), encoding="utf-8")
	print("?", r)
	openssl = "openssl req -nodes -newkey rsa:2048 -keyout tests/testopsicommon/data/ssl/test-server.key -out tests/testopsicommon/data/ssl/test-server.csr -subj /C=DE/ST=RP/L=Mainz/O=uib/OU=root/CN=test-server"
	r = subprocess.call(openssl.split(" "), encoding="utf-8")
	print(r)
	openssl = "openssl ca -batch -config tests/testopsicommon/data/ssl/ca.conf -notext -in tests/testopsicommon/data/ssl/test-server.csr -out tests/testopsicommon/data/ssl/test-server.crt"
	r = subprocess.call(openssl.split(" "), encoding="utf-8")
	print(r)
	openssl = "openssl ca -config ca.conf -gencrl -keyfile tests/testopsicommon/data/ssl/ca.key -cert ca.crt -out tests/testopsicommon/data/ssl/root.crl.pem"
	r = subprocess.call(openssl.split(" "), encoding="utf-8")
	print(r)
	openssl = "openssl crl -inform PEM -in tests/testopsicommon/data/ssl/root.crl.pem -outform DER -out tests/testopsicommon/data/ssl/root.crl"
	r = subprocess.call(openssl.split(" "), encoding="utf-8")
	print(r)
	print("create_certification done...")

@pytest.fixture(scope="function")
def start_httpserver():
	create_certification()
	print("start server")
	PORT = 8080
	Handler = http.server.SimpleHTTPRequestHandler

	httpd = socketserver.TCPServer(("", PORT), Handler)
	httpd.socket = ssl.wrap_socket(
		httpd.socket,
		keyfile="tests/testopsicommon/data/ssl/test-server.key",
		certfile="tests/testopsicommon/data/ssl/test-server.crt",
		server_side=True
	)
	thread = threading.Thread(target = httpd.serve_forever)
	thread.daemon = True
	thread.start()
	yield None
	print("shutdown server")
	httpd.shutdown()


def test_curl(start_httpserver):
	time.sleep(5)

	with open("tests/testopsicommon/data/ssl/ca.crt", "rb") as file:
		ca = load_certificate(FILETYPE_PEM, file.read())
		install_ca(ca)

	r = subprocess.call(["curl", "https://localhost:8080"], encoding="utf-8")
	print(r)
	assert r == 0

	remove_ca(ca.get_subject().CN)

	r = subprocess.call(["curl", "https://localhost:8080"], encoding="utf-8")
	print(r)
	assert r == 60
