# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.file_transfer tests
"""

import asyncio
from pathlib import Path
from unittest.mock import patch

from opsicommon.logging import LOG_TRACE, use_logging_config
from opsicommon.messagebus import CONNECTION_USER_CHANNEL
from opsicommon.messagebus.file_transfer import process_messagebus_message, stop_running_file_transfers
from opsicommon.messagebus.message import (
	FileChunkMessage,
	FileDownloadRequestMessage,
	FileTransferErrorMessage,
	FileUploadRequestMessage,
	FileUploadResponseMessage,
	FileUploadResultMessage,
)

from .helpers import MessageSender, MessageServer


async def test_file_upload(tmp_path: Path) -> None:
	sender = "test_sender"
	channel = "test_channel"
	chunk_size = 1000
	upload_path = tmp_path / "upload"
	test_file = Path(tmp_path) / "file.txt"
	test_file.write_text("opsi" * chunk_size, encoding="ascii")
	file_size = test_file.stat().st_size
	assert file_size == chunk_size * 4
	message_sender = MessageSender()

	file_upload_request = FileUploadRequestMessage(
		sender=sender,
		channel=channel,
		content_type="text/plain",
		name=test_file.name,
		size=file_size,
		destination_dir=str(upload_path),
	)
	await process_messagebus_message(file_upload_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1
	assert isinstance(messages[0], FileTransferErrorMessage)
	assert messages[0].sender == CONNECTION_USER_CHANNEL
	assert not messages[0].back_channel
	assert messages[0].channel == "test_sender"
	assert messages[0].file_id == file_upload_request.file_id
	assert "No such file or directory" in messages[0].error.message

	# Create the upload directory and try again
	upload_path.mkdir()
	file_upload_request = FileUploadRequestMessage(
		sender=sender,
		channel=channel,
		content_type="text/plain",
		name=test_file.name,
		size=file_size,
		destination_dir=str(upload_path),
	)
	await process_messagebus_message(
		file_upload_request, send_message=message_sender.send_message, sender="test_res_sender", back_channel="test_res_channel"
	)

	messages = await message_sender.wait_for_messages(count=1)
	assert isinstance(messages[0], FileUploadResponseMessage)
	assert messages[0].sender == "test_res_sender"
	assert messages[0].back_channel == "test_res_channel"
	assert messages[0].file_id == file_upload_request.file_id
	print(messages[0].path)
	assert messages[0].path == str(upload_path / test_file.name)

	with test_file.open("rb") as file:
		chunk_number = 0
		data_pos = 0
		while data := file.read(chunk_size):
			data_pos += len(data)
			chunk_number += 1
			file_chunk_message = FileChunkMessage(
				sender=sender,
				channel=channel,
				file_id=file_upload_request.file_id,
				number=chunk_number,
				data=data,
				last=data_pos == file_size,
			)
			await process_messagebus_message(file_chunk_message, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1
	assert isinstance(messages[0], FileUploadResultMessage)


async def test_file_download(tmp_path: Path) -> None:
	sender = "test_sender"
	channel = "test_channel"
	message_server = MessageServer()

	file_download_request = FileDownloadRequestMessage(
		sender=sender,
		channel=channel,
		path=message_server.path,
	)
	# TODO


async def test_upload_chunk_timeout(tmp_path: Path) -> None:
	sender = "test_sender"
	channel = "test_channel"
	chunk_size = 1000
	file_size = 100_000
	chunk_timeout = 3
	message_sender = MessageSender()

	with use_logging_config(stderr_level=LOG_TRACE), patch("opsicommon.messagebus.file_transfer.FileUpload.chunk_timeout", chunk_timeout):
		file_upload_request = FileUploadRequestMessage(
			sender=sender,
			channel=channel,
			content_type="application/octet-stream",
			name="file.bin",
			size=file_size,
			destination_dir=str(tmp_path),
		)
		await process_messagebus_message(file_upload_request, send_message=message_sender.send_message)

		messages = await message_sender.wait_for_messages(count=1)
		assert isinstance(messages[0], FileUploadResponseMessage)

		file_chunk_message = FileChunkMessage(
			sender=sender, channel=channel, file_id=file_upload_request.file_id, number=1, data=b"x" * chunk_size
		)
		await process_messagebus_message(file_chunk_message, send_message=message_sender.send_message)

		messages = await message_sender.wait_for_messages(count=1, timeout=chunk_timeout + 1)
		assert len(messages) == 1
		assert isinstance(messages[0], FileTransferErrorMessage)
		assert "File transfer timed out while waiting for next chunk" in messages[0].error.message

		file_chunk_message = FileChunkMessage(
			sender=sender, channel=channel, file_id=file_upload_request.file_id, number=2, data=b"x" * chunk_size
		)
		await process_messagebus_message(file_chunk_message, send_message=message_sender.send_message)

		messages = await message_sender.wait_for_messages(count=1)
		assert len(messages) == 1
		assert isinstance(messages[0], FileTransferErrorMessage)
		assert "not found" in messages[0].error.message
		assert messages[0].ref_id == file_chunk_message.id
		assert messages[0].file_id == file_chunk_message.file_id


async def test_stop_running_transfers(tmp_path: Path) -> None:
	sender = "test_sender"
	channel = "test_channel"
	chunk_size = 1000
	file_size = 100_000
	message_sender = MessageSender()

	with patch("opsicommon.messagebus.file_transfer.FileUpload.default_destination", tmp_path):
		file_upload_request = FileUploadRequestMessage(
			sender=sender,
			channel=channel,
			content_type="application/octet-stream",
			name="file.bin",
			size=file_size,
		)
		await process_messagebus_message(file_upload_request, send_message=message_sender.send_message)

		messages = await message_sender.wait_for_messages(count=1)
		assert isinstance(messages[0], FileUploadResponseMessage)

		file_chunk_message = FileChunkMessage(
			sender=sender, channel=channel, file_id=file_upload_request.file_id, number=1, data=b"x" * chunk_size
		)
		await process_messagebus_message(file_chunk_message, send_message=message_sender.send_message)
		await asyncio.sleep(1)
		await stop_running_file_transfers()

		messages = await message_sender.wait_for_messages(count=1)
		assert len(messages) == 1
		assert isinstance(messages[0], FileTransferErrorMessage)
		assert messages[0].file_id == file_upload_request.file_id
		assert "File transfer stopped before completion" in messages[0].error.message
