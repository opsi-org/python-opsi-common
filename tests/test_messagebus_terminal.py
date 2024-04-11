# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.terminal tests
"""


import asyncio
import time
import uuid
from pathlib import Path
from unittest.mock import patch
import os
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
from opsicommon.system.info import is_windows, is_posix

from .helpers import MessageSender


def test_start_pty_params(tmp_path: Path) -> None:
	str_path = str(tmp_path)
	cols = 150
	rows = 20

	env = dict(os.environ)
	env["TEST"] = "test"
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
	lines = data.decode("utf-8").split("\r\n")

	command = "cd" if is_windows() else "pwd"
	pty_write(f"{command}\r\n".encode("utf-8"))
	time.sleep(2)
	data = pty_read(4096)
	print("read:", data)
	lines = data.decode("utf-8").split("\r\n")
	assert lines[0] == command
	assert lines[1].strip() == str_path

	command = "set" if is_windows() else "env"
	pty_write(f"{command}\r\n".encode("utf-8"))
	time.sleep(2)
	data = pty_read(4096)
	print("read:", data)
	lines = data.decode("utf-8").split("\r\n")
	assert lines[0] == command
	assert "TEST=test" in lines
	if is_posix():
		assert "TERM=xterm-256color" in lines

	if is_posix():
		pty_write("stty size\r\n".encode("utf-8"))
		time.sleep(2)
		data = pty_read(4096)
		print("read:", data)
		lines = data.decode("utf-8").split("\r\n")
		assert lines[0] == "stty size"
		assert lines[1] == f"{rows} {cols}"

	pty_set_size(20, 100)
	pty_stop()


def test_start_pty_fail() -> None:
	with pytest.raises(RuntimeError, match="Failed to start pty with shell"):
		start_pty(shell="/will/fail")


async def test_terminal_params() -> None:
	cols = 150
	rows = 25
	terminal_id = str(uuid.uuid4())
	sender = "service_worker:pytest:1"
	shell = "/bin/bash" if not is_windows() else "cmd.exe"

	assert not terminals

	message_sender = MessageSender()

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell=shell, rows=rows, cols=cols
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
	lines = messages[1].data.decode("utf-8").split("\r\n")
	assert lines[0] == f"{rows} {cols}"

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


async def test_terminal_timeout() -> None:
	terminal_id = str(uuid.uuid4())
	sender = "service_worker:pytest:1"

	assert not terminals

	message_sender = MessageSender()

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id
	)
	with patch("opsicommon.messagebus.terminal.Terminal.read_timeout", 1), patch("opsicommon.messagebus.terminal.Terminal.idle_timeout", 3):
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

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell='bash -c "echo exit_1 && exit 1"'
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
	assert data == b"exit_1\r\n"
	assert isinstance(messages[-1], TerminalCloseEventMessage)


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