# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.terminal tests
"""

import asyncio
import os
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from opsicommon.messagebus.message import (
	Error,
	TerminalCloseEventMessage,
	TerminalCloseRequestMessage,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalErrorMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
)
from opsicommon.messagebus.terminal import Terminal, process_messagebus_message, start_pty, stop_running_terminals, terminals
from opsicommon.system.info import is_macos, is_posix, is_windows

from .helpers import MessageSender


def test_start_pty_params(tmp_path: Path) -> None:
	str_path = str(tmp_path)
	cols = 150
	rows = 20

	env = {"PATH": os.environ["PATH"], "OPSI_TEST": "foo"}
	(
		pty_pid,
		pty_read,
		pty_write,
		pty_set_size,
		pty_stop,
	) = start_pty(shell="cmd.exe" if is_windows() else "bash", rows=rows, cols=cols, cwd=str_path, env=env)
	assert pty_pid > 0

	time.sleep(2)
	data = pty_read(4096)
	print("read:", data)
	lines = [line.strip() for line in data.decode("utf-8").split("\n")]

	command = "cd" if is_windows() else "pwd"
	pty_write(f"{command}\r\n".encode("utf-8"))
	time.sleep(2)
	data = pty_read(4096)
	print("read:", data)
	lines = [line.strip() for line in data.decode("utf-8").split("\n")]
	assert lines[0] == command
	assert lines[1].strip().endswith(str_path)

	command = "set" if is_windows() else "env"
	pty_write(f"{command}\r\n".encode("utf-8"))
	data = b""
	for _ in range(30):
		time.sleep(1)
		dat = pty_read(8192)
		print("read:", dat)
		data += dat
		if b"OPSI_TEST=foo" in data:
			if not is_posix():
				break
			if b"TERM=" in data:
				break

	lines = [line.strip() for line in data.decode("utf-8").split("\n")]
	assert lines[0] == command
	assert "OPSI_TEST=foo" in lines

	if is_posix():
		assert any(line.startswith("TERM=") for line in lines)

		pty_write("stty size\r\n".encode("utf-8"))
		data = b""
		for _ in range(30):
			time.sleep(1)
			dat = pty_read(8192)
			print("read:", dat)
			data += dat
			if b"stty size" in data:
				break
		lines = [line.strip() for line in data.decode("utf-8").split("\n")]
		print("lines:", lines)
		assert any(line.endswith("stty size") for line in lines)
		if not is_macos():
			assert f"{rows} {cols}" in lines

	pty_set_size(20, 100)
	pty_stop()


def test_start_pty_fail() -> None:
	with pytest.raises(RuntimeError, match="Failed to start pty with shell"):
		start_pty(shell="/will/fail")


async def test_terminal_params() -> None:
	if is_macos():
		pytest.skip("Test currently not implemented on MacOS")

	cols = 150
	rows = 25
	terminal_id = str(uuid.uuid4())
	sender = "service_worker:pytest:1"
	shell = "/bin/bash" if not is_windows() else "cmd.exe"
	env = {"LANG": "de", "OPSI_TEST": "foo"}

	assert not terminals

	message_sender = MessageSender()

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell=shell, rows=rows, cols=cols, env=env
	)
	await process_messagebus_message(message=terminal_open_request, send_message=message_sender.send_message, sender=sender)

	messages = await message_sender.wait_for_messages(count=2)

	assert len(terminals) == 1
	assert isinstance(terminals[terminal_id], Terminal)

	assert isinstance(messages[0], TerminalOpenEventMessage)
	assert messages[0].type == "terminal_open_event"
	assert messages[0].sender == sender
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id
	assert messages[0].cols == cols
	assert messages[0].rows == rows

	assert isinstance(messages[1], TerminalDataReadMessage)
	assert messages[1].type == "terminal_data_read"
	assert messages[1].sender == sender
	assert messages[1].channel == "back_channel"
	assert messages[1].terminal_id == terminal_id
	assert messages[1].data

	command = "set" if is_windows() else "env"
	terminal_data_write_message = TerminalDataWriteMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, data=f"{command}\r\n".encode("utf-8")
	)
	await process_messagebus_message(message=terminal_data_write_message, send_message=message_sender.send_message, sender=sender)

	messages = await message_sender.wait_for_messages(count=10, timeout=5, error_on_timeout=False)
	data = b""
	for message in messages:
		assert isinstance(message, TerminalDataReadMessage)
		data += message.data
	lines = data.decode("utf-8").split("\r\n")
	assert "OPSI_TEST=foo" in lines
	assert "LANG=de" in lines
	assert f"OPSI_TERMINAL_ID={terminal_id}" in lines

	if is_posix():
		terminal_data_write_message = TerminalDataWriteMessage(
			sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, data="stty size\r\n".encode("utf-8")
		)
		await process_messagebus_message(message=terminal_data_write_message, send_message=message_sender.send_message, sender=sender)

		messages = await message_sender.wait_for_messages(count=2)

		assert isinstance(messages[0], TerminalDataReadMessage)
		assert messages[0].type == "terminal_data_read"
		assert messages[0].sender == sender
		assert messages[0].channel == "back_channel"
		assert messages[0].terminal_id == terminal_id
		lines = messages[0].data.decode("utf-8").split("\r\n")
		assert lines[0] == "stty size"

		assert isinstance(messages[1], TerminalDataReadMessage)
		assert f"{rows} {cols}" in messages[1].data.decode("utf-8")

	# Reopen terminal
	cols = 160
	rows = 30
	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell=shell, rows=rows, cols=cols
	)
	await process_messagebus_message(message=terminal_open_request, send_message=message_sender.send_message, sender=sender)

	messages = await message_sender.wait_for_messages(count=1)

	assert len(terminals) == 1
	assert isinstance(terminals[terminal_id], Terminal)

	assert isinstance(messages[0], TerminalOpenEventMessage)
	assert messages[0].type == "terminal_open_event"
	assert messages[0].sender == sender
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id
	assert messages[0].cols == cols
	assert messages[0].rows == rows

	for message in await message_sender.wait_for_messages(count=10, timeout=3, error_on_timeout=False):
		assert isinstance(message, TerminalDataReadMessage)

	terminal_close_request = TerminalCloseRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id
	)
	await process_messagebus_message(message=terminal_close_request, send_message=message_sender.send_message, sender=sender)
	messages = await message_sender.wait_for_messages(count=1)

	assert isinstance(messages[0], TerminalCloseEventMessage)
	assert messages[0].type == "terminal_close_event"
	assert messages[0].sender == sender
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id

	if is_windows():
		await asyncio.sleep(3)


async def test_terminal_timeout() -> None:
	terminal_id = str(uuid.uuid4())
	sender = "service_worker:pytest:1"

	assert not terminals

	message_sender = MessageSender()

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id
	)
	with patch("opsicommon.messagebus.terminal.Terminal.idle_timeout", 3):
		await process_messagebus_message(message=terminal_open_request, send_message=message_sender.send_message, sender=sender)
		await message_sender.wait_for_messages(count=2)
		await asyncio.sleep(4)
		messages = await message_sender.wait_for_messages(count=1)
		assert isinstance(messages[0], TerminalCloseEventMessage)


async def test_terminal_fail() -> None:
	terminal_id = str(uuid.uuid4())

	message_sender = MessageSender(print_messages=True)

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell="/fail/shell"
	)
	await process_messagebus_message(message=terminal_open_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=2)

	assert len(messages) == 2
	assert isinstance(messages[0], TerminalErrorMessage)
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id
	assert messages[0].error == Error(
		message=(
			"Failed to create new terminal: Failed to start pty with shell '/fail/shell': "
			"The command was not found or was not executable: /fail/shell."
		)
	)

	assert isinstance(messages[1], TerminalCloseEventMessage)
	assert messages[1].channel == "back_channel"
	assert messages[1].terminal_id == terminal_id

	await asyncio.sleep(1)
	terminal_id = str(uuid.uuid4())

	shell = 'cmd.exe /c "echo exit_1 && exit 1"' if is_windows() else 'bash -c "echo exit_1 && exit 1"'
	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell=shell
	)
	await process_messagebus_message(message=terminal_open_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=3)

	assert len(messages) >= 3
	assert isinstance(messages[0], TerminalOpenEventMessage)
	data = b""
	for idx in range(1, len(messages) - 1):
		msg = messages[idx]
		assert isinstance(msg, TerminalDataReadMessage)
		data += msg.data

	if is_windows():
		assert b"exit_1\r\n" in data
	else:
		assert data == b"exit_1\r\n"
	assert isinstance(messages[-1], TerminalCloseEventMessage)


async def test_multiple_terminals() -> None:
	terminal1_id = str(uuid.uuid4())
	terminal2_id = str(uuid.uuid4())
	terminal3_id = str(uuid.uuid4())
	sender = "service_worker:pytest:1"

	assert not terminals

	message_sender = MessageSender()

	for terminal_id in (terminal1_id, terminal2_id, terminal3_id):
		terminal_open_request = TerminalOpenRequestMessage(sender="client", channel="channel", terminal_id=terminal_id)
		await process_messagebus_message(message=terminal_open_request, send_message=message_sender.send_message, sender=sender)

	await asyncio.sleep(1)

	for terminal_id in (terminal1_id, terminal2_id, terminal3_id):
		terminal_data_write_message = TerminalDataWriteMessage(
			sender="client", channel="channel", terminal_id=terminal_id, data="echo test\r\n".encode("utf-8")
		)
		await process_messagebus_message(message=terminal_data_write_message, send_message=message_sender.send_message, sender=sender)

	await asyncio.sleep(1)

	for terminal_id in (terminal1_id, terminal2_id, terminal3_id):
		terminal_close_request = TerminalCloseRequestMessage(sender="client", channel="channel", terminal_id=terminal_id)
		await process_messagebus_message(message=terminal_close_request, send_message=message_sender.send_message, sender=sender)

	messages = await message_sender.wait_for_messages(count=100, timeout=5, error_on_timeout=False)
	for terminal_id in (terminal1_id, terminal2_id, terminal3_id):
		assert any(isinstance(m, TerminalOpenEventMessage) and m.terminal_id == terminal_id for m in messages)
		assert any(isinstance(m, TerminalDataReadMessage) and m.terminal_id == terminal_id for m in messages)
		assert any(isinstance(m, TerminalCloseEventMessage) and m.terminal_id == terminal_id for m in messages)


async def test_stop_running_terminals() -> None:
	message_sender = MessageSender()

	terminal_id = str(uuid.uuid4())
	shell = "timeout /t 10" if is_windows() else "sleep 10"

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell=shell
	)
	await process_messagebus_message(terminal_open_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1
	assert isinstance(messages[0], TerminalOpenEventMessage)

	assert len(terminals) == 1
	assert terminals[terminal_open_request.terminal_id]

	await stop_running_terminals()

	messages = await message_sender.wait_for_messages(count=1)
	assert isinstance(messages[-1], TerminalCloseEventMessage)
	assert messages[-1].terminal_id == terminal_id
