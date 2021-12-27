# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import time
import subprocess
import http.server
import socketserver
import ssl
import threading

import pytest
from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from opsicommon.ssl import install_ca, remove_ca


def create_certification():
	openssl = (
		"openssl req -nodes -x509 -newkey rsa:2048 -days 730 -keyout tests/data/ssl/ca.key "
		"-out tests/data/ssl/ca.crt -new -sha512 -subj /C=DE/ST=RP/L=Mainz/O=uib/OU=root/CN=uib-Signing-Authority"
	)
	subprocess.check_call(openssl.split(" "), encoding="utf-8")
	openssl = (
		"openssl req -nodes -newkey rsa:2048 -keyout tests/data/ssl/test-server.key "
		"-out tests/data/ssl/test-server.csr -subj /C=DE/ST=RP/L=Mainz/O=uib/OU=root/CN=test-server"
	)
	subprocess.check_call(openssl.split(" "), encoding="utf-8")
	openssl = "openssl ca -batch -config tests/data/ssl/ca.conf -notext -in tests/data/ssl/test-server.csr -out tests/data/ssl/test-server.crt"
	subprocess.check_call(openssl.split(" "), encoding="utf-8")
	openssl = "openssl ca -config ca.conf -gencrl -keyfile tests/data/ssl/ca.key -cert ca.crt -out tests/data/ssl/root.crl.pem"
	subprocess.check_call(openssl.split(" "), encoding="utf-8")
	openssl = "openssl crl -inform PEM -in tests/data/ssl/root.crl.pem -outform DER -out tests/data/ssl/root.crl"
	subprocess.check_call(openssl.split(" "), encoding="utf-8")


@pytest.fixture(scope="function")
def start_httpserver():
	create_certification()
	Handler = http.server.SimpleHTTPRequestHandler

	httpd = socketserver.TCPServer(("", 8080), Handler)
	context = ssl.SSLContext()
	context.load_cert_chain(
		keyfile="tests/data/ssl/test-server.key",
		certfile="tests/data/ssl/test-server.crt"
	)
	httpd.socket = context.wrap_socket(sock=httpd.socket, server_side=True)
	thread = threading.Thread(target = httpd.serve_forever)
	thread.daemon = True
	thread.start()
	yield None
	httpd.shutdown()

@pytest.mark.skipif(os.geteuid() != 0, reason="no root permissons")
def test_curl(start_httpserver):  # pylint: disable=redefined-outer-name, unused-argument
	time.sleep(5)

	with open("tests/data/ssl/ca.crt", "rb", encoding="utf8") as file:
		ca_cert = load_certificate(FILETYPE_PEM, file.read())
		install_ca(ca_cert)

	return_code = subprocess.call(["curl", "https://localhost:8080"], encoding="utf-8")
	assert return_code == 0

	remove_ca(ca_cert.get_subject().CN)

	return_code = subprocess.call(["curl", "https://localhost:8080"], encoding="utf-8")
	assert return_code == 60
