# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.process tests
"""

import asyncio
import time

from opsicommon.messagebus.message import (
	Message,
	ProcessDataReadMessage,
	ProcessDataWriteMessage,
	ProcessStartEventMessage,
	ProcessStartRequestMessage,
	ProcessStopEventMessage,
	ProcessStopRequestMessage,
)
from opsicommon.messagebus.process import process_messagebus_message, processes, stop_running_processes
from opsicommon.system.info import is_windows


async def test_process_messagebus_message() -> None:
	sender = "test_sender"
	channel = "test_channel"
	messages_sent: list[Message] = []

	async def send_message(message: Message) -> None:
		nonlocal messages_sent
		messages_sent.append(message)

	async def wait_for_messages(count: int, timeout: float = 10.0) -> None:
		nonlocal messages_sent
		start = time.time()
		while len(messages_sent) < count:
			if time.time() - start > timeout:
				raise TimeoutError(f"Timeout waiting for {count} messages")
			await asyncio.sleep(0.1)

	command = ("echo hello",) if is_windows() else ("cat",)
	process_start_request = ProcessStartRequestMessage(sender=sender, channel=channel, command=command, shell=True)
	await process_messagebus_message(process_start_request, send_message=send_message)

	await wait_for_messages(1)
	assert len(messages_sent) == 1

	assert isinstance(messages_sent[0], ProcessStartEventMessage)
	assert messages_sent[0].process_id == process_start_request.process_id
	assert messages_sent[0].os_process_id > 0

	messages_sent = []
	if not is_windows():
		process_data_write_message = ProcessDataWriteMessage(
			sender=sender, channel=channel, process_id=process_start_request.process_id, stdin=b"hello\n"
		)
		await process_messagebus_message(process_data_write_message, send_message=send_message)

		await wait_for_messages(1)

		process_stop_request_message = ProcessStopRequestMessage(
			sender=sender, channel=channel, process_id=process_start_request.process_id
		)
		await process_messagebus_message(process_stop_request_message, send_message=send_message)

	await wait_for_messages(1)

	assert isinstance(messages_sent[0], ProcessDataReadMessage)
	assert messages_sent[0].process_id == process_start_request.process_id
	assert messages_sent[0].stdout == b"hello\r\n" if is_windows() else b"hello\n"

	assert isinstance(messages_sent[1], ProcessStopEventMessage)
	assert messages_sent[1].process_id == process_start_request.process_id
	assert messages_sent[1].exit_code == 0


async def test_stop_running_processes() -> None:
	messages_sent: list[Message] = []

	async def send_message(message: Message) -> None:
		nonlocal messages_sent
		messages_sent.append(message)

	async def wait_for_messages(count: int, timeout: float = 10.0) -> None:
		nonlocal messages_sent
		start = time.time()
		while len(messages_sent) < count:
			if time.time() - start > timeout:
				raise TimeoutError(f"Timeout waiting for {count} messages")
			await asyncio.sleep(0.1)

	command = ("timeout", "/t", "10") if is_windows() else ("sleep", "10")
	process_start_request = ProcessStartRequestMessage(sender="test_sender", channel="test_channel", command=command, shell=False)
	await process_messagebus_message(process_start_request, send_message=send_message)

	await wait_for_messages(1)
	assert len(messages_sent) == 1
	assert isinstance(messages_sent[0], ProcessStartEventMessage)

	assert len(processes) == 1
	assert processes[process_start_request.process_id]

	messages_sent = []
	await stop_running_processes()

	await wait_for_messages(1)
	assert isinstance(messages_sent[-1], ProcessStopEventMessage)
	assert messages_sent[-1].exit_code != 0
