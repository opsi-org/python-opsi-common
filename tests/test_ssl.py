# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import time
import subprocess
import http.server
import socketserver
import ssl
import threading
import ipaddress

import pytest

from OpenSSL.crypto import load_certificate, FILETYPE_PEM, X509, PKey

from opsicommon.ssl import (
	create_x590_name, as_pem, create_ca, create_server_cert,
	install_ca, remove_ca
)

def test_create_x590_name():
	subject = {"emailAddress": "test@test.de"}
	x590_name = create_x590_name(subject)
	assert x590_name.emailAddress == subject["emailAddress"]
	assert x590_name.CN == "opsi"


def test_create_ca():
	subject = {
		"CN": "opsi CA",
		"OU": "opsi",
		"emailAddress": "opsi@opsi.org"
	}
	cert, key = create_ca(subject, 100)
	assert isinstance(cert, X509)
	assert isinstance(key, PKey)
	assert cert.get_subject().CN == subject["CN"]
	assert cert.get_subject().OU == subject["OU"]
	assert cert.get_subject().emailAddress == subject["emailAddress"]

	del subject["CN"]
	with pytest.raises(ValueError):
		create_ca(subject, 100)


def test_create_server_cert():
	subject = {
		"CN": "opsi CA",
		"OU": "opsi",
		"emailAddress": "opsi@opsi.org"
	}
	ca_cert, ca_key = create_ca(subject, 1000)
	kwargs = {
		"subject": {"CN": "server.dom.tld"},
		"valid_days": 100,
		"ip_addresses": {"172.0.0.1", "::1", "192.168.1.1"},
		"hostnames": {"localhost", "opsi", "opsi.dom.tld"},
		"ca_key": ca_key,
		"ca_cert": ca_cert
	}
	cert, key = create_server_cert(**kwargs)
	assert isinstance(cert, X509)
	assert isinstance(key, PKey)
	assert cert.get_subject().CN == kwargs["subject"]["CN"]

	cert_hns = set()
	cert_ips = set()
	for idx in range(cert.get_extension_count()):
		ext = cert.get_extension(idx)
		if ext.get_short_name() == b"subjectAltName":
			for alt_name in str(ext).split(","):
				alt_name = alt_name.strip()
				if alt_name.startswith("DNS:"):
					cert_hns.add(alt_name.split(":", 1)[-1].strip())
				elif alt_name.startswith(("IP:", "IP Address:")):
					addr = alt_name.split(":", 1)[-1].strip()
					addr = ipaddress.ip_address(addr)
					cert_ips.add(addr.compressed)
			break

	assert cert_hns == kwargs["hostnames"]
	assert cert_ips == kwargs["ip_addresses"]


def test_as_pem():
	subject = {
		"CN": "opsi CA",
		"OU": "opsi",
		"emailAddress": "opsi@opsi.org"
	}
	cert, key = create_ca(subject, 100)
	pem = as_pem(cert, "")
	assert pem.startswith("-----BEGIN CERTIFICATE-----")
	pem = as_pem(key, None)
	assert pem.startswith("-----BEGIN PRIVATE KEY-----")
	pem = as_pem(key, "password")
	assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
	with pytest.raises(TypeError):
		as_pem(create_x590_name({}))


def create_certification():
	subprocess.check_call([
		"openssl", "req", "-nodes", "-x509", "-newkey", "rsa:2048", "-days", "730", "-keyout", "tests/data/ssl/ca.key",
		"-out", "tests/data/ssl/ca.crt", "-new", "-sha512", "-subj", "/C=DE/ST=RP/L=Mainz/O=uib/OU=root/CN=uib-Signing-Authority"
	])
	subprocess.check_call([
		"openssl", "req", "-nodes", "-newkey", "rsa:2048", "-keyout", "tests/data/ssl/test-server.key",
		"-out", "tests/data/ssl/test-server.csr", "-subj", "/C=DE/ST=RP/L=Mainz/O=uib/OU=root/CN=test-server"
	])
	subprocess.check_call([
		"openssl", "ca", "-batch", "-config", "tests/data/ssl/ca.conf", "-notext",
		"-in", "tests/data/ssl/test-server.csr", "-out", "tests/data/ssl/test-server.crt"
	])
	subprocess.check_call([
		"openssl", "ca", "-config", "tests/data/ssl/ca.conf", "-gencrl",
		"-keyfile", "tests/data/ssl/ca.key", "-cert", "tests/data/ssl/ca.crt", "-out", "tests/data/ssl/root.crl.pem"
	])
	subprocess.check_call([
		"openssl", "crl", "-inform", "PEM", "-in", "tests/data/ssl/root.crl.pem", "-outform", "DER", "-out", "tests/data/ssl/root.crl"
	])


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


@pytest.mark.root_permissions
def test_curl(start_httpserver):  # pylint: disable=redefined-outer-name, unused-argument
	time.sleep(5)

	with open("tests/data/ssl/ca.crt", "rb") as file:
		ca_cert = load_certificate(FILETYPE_PEM, file.read())
		install_ca(ca_cert)

	return_code = subprocess.call(["curl", "https://localhost:8080"], encoding="utf-8")
	assert return_code == 0

	remove_ca(ca_cert.get_subject().CN)

	return_code = subprocess.call(["curl", "https://localhost:8080"], encoding="utf-8")
	assert return_code == 60
