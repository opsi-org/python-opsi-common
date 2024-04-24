# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.process tests
"""


import pytest

from opsicommon.messagebus import CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	ProcessDataReadMessage,
	ProcessDataWriteMessage,
	ProcessErrorMessage,
	ProcessStartEventMessage,
	ProcessStartRequestMessage,
	ProcessStopEventMessage,
	ProcessStopRequestMessage,
)
from opsicommon.messagebus.process import process_messagebus_message, processes, stop_running_processes
from opsicommon.system.info import is_windows

from .helpers import MessageSender


@pytest.mark.parametrize("close_stdin", [True, False])
async def test_execute_command(close_stdin: bool) -> None:
	sender = "test_sender"
	channel = "test_channel"
	message_sender = MessageSender()

	env = {"LANG": "de_DE.UTF-8", "TEST": "test"}
	command = ("echo hello",) if is_windows() else ("cat",)
	process_start_request = ProcessStartRequestMessage(sender=sender, channel=channel, command=command, shell=True, env=env)
	await process_messagebus_message(process_start_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1

	assert isinstance(messages[0], ProcessStartEventMessage)
	assert messages[0].process_id == process_start_request.process_id
	assert messages[0].os_process_id > 0

	if not is_windows():
		process_data_write_message = ProcessDataWriteMessage(
			sender=sender, channel=channel, process_id=process_start_request.process_id, stdin=b"hello\n"
		)
		await process_messagebus_message(process_data_write_message, send_message=message_sender.send_message)

		messages = await message_sender.wait_for_messages(count=1, clear_messages=False)

		if close_stdin:
			# Write empty data to signal EOF and to close stdin
			# cat process should exit
			process_data_write_message = ProcessDataWriteMessage(
				sender=sender, channel=channel, process_id=process_start_request.process_id, stdin=b""
			)
			await process_messagebus_message(process_data_write_message, send_message=message_sender.send_message)
		else:
			process_stop_request_message = ProcessStopRequestMessage(
				sender=sender, channel=channel, process_id=process_start_request.process_id
			)
			await process_messagebus_message(process_stop_request_message, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=2)

	assert isinstance(messages[0], ProcessDataReadMessage)
	assert messages[0].process_id == process_start_request.process_id
	assert messages[0].stdout == b"hello\r\n" if is_windows() else b"hello\n"

	assert isinstance(messages[1], ProcessStopEventMessage)
	assert messages[1].process_id == process_start_request.process_id
	assert messages[1].exit_code == 0


async def test_message_order() -> None:
	sender = "test_sender"
	channel = "test_channel"
	message_sender = MessageSender()

	command = ("echo", "test")
	process_start_request = ProcessStartRequestMessage(sender=sender, channel=channel, command=command, shell=True)
	await process_messagebus_message(process_start_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=3, timeout=5)
	assert len(messages) == 3

	assert isinstance(messages[0], ProcessStartEventMessage)
	assert isinstance(messages[1], ProcessDataReadMessage)
	assert isinstance(messages[2], ProcessStopEventMessage)
	assert messages[0].created < messages[1].created < messages[2].created


async def test_execute_error() -> None:
	sender = "test_sender"
	channel = "test_channel"
	message_sender = MessageSender()

	command = ("command_not_found", "--help")
	process_start_request = ProcessStartRequestMessage(sender=sender, channel=channel, command=command, shell=False)
	await process_messagebus_message(process_start_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1

	assert isinstance(messages[0], ProcessErrorMessage)
	assert messages[0].process_id == process_start_request.process_id
	assert messages[0].ref_id == process_start_request.id
	assert messages[0].sender == CONNECTION_USER_CHANNEL
	assert not messages[0].back_channel
	assert messages[0].channel == "test_sender"
	if is_windows():
		assert "[WinError 2]" in messages[0].error.message
	else:
		assert "No such file or directory: 'command_not_found'" in messages[0].error.message

	process_stop_request_message = ProcessStopRequestMessage(sender=sender, channel=channel, process_id=process_start_request.process_id)
	await process_messagebus_message(process_stop_request_message, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1

	assert isinstance(messages[0], ProcessErrorMessage)
	assert messages[0].process_id == process_start_request.process_id
	assert messages[0].ref_id == process_stop_request_message.id
	assert "not found" in messages[0].error.message


async def test_stop_running_processes() -> None:
	message_sender = MessageSender()

	command = ("timeout", "/t", "10") if is_windows() else ("sleep", "10")
	process_start_request = ProcessStartRequestMessage(sender="test_sender", channel="test_channel", command=command, shell=False)
	await process_messagebus_message(process_start_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1
	assert isinstance(messages[0], ProcessStartEventMessage)

	assert len(processes) == 1
	assert processes[process_start_request.process_id]

	messages = []
	await stop_running_processes()

	messages = await message_sender.wait_for_messages(count=1)
	assert isinstance(messages[-1], ProcessStopEventMessage)
	assert messages[-1].exit_code != 0
