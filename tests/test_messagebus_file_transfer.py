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
from opsicommon.messagebus.file_transfer import (
	DEFAULT_CHUNK_SIZE,
	FileDownload,
	get_file_transfers,
	process_messagebus_message,
	stop_running_file_transfers,
)
from opsicommon.messagebus.message import (
	FileChunkMessage,
	FileDownloadAbortRequestMessage,
	FileDownloadRequestMessage,
	FileDownloadResponseMessage,
	FileTransferErrorMessage,
	FileUploadRequestMessage,
	FileUploadResponseMessage,
	FileUploadResultMessage,
)

from .helpers import MessageSender, gen_test_file


async def wait_for_get_file_transfers_empty() -> None:
	for _ in range(5):
		await asyncio.sleep(1)
		if not get_file_transfers():
			break
	assert len(get_file_transfers()) == 0

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

	await wait_for_get_file_transfers_empty()

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

	await wait_for_get_file_transfers_empty()

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

	await wait_for_get_file_transfers_empty()

async def test_file_download_chunk_size() -> None:
	for chunk_size in [None, -1, 0, 1000]:
		file_download_request = FileDownloadRequestMessage(
			sender="test_sender",
			channel="test_channel",
			chunk_size=chunk_size,
			path="/some/path",
		)
		file_download = FileDownload(send_message=lambda x: None, file_download_request=file_download_request)
		assert file_download._chunk_size == chunk_size if chunk_size and chunk_size > 0 else DEFAULT_CHUNK_SIZE


async def test_file_download(tmp_path: Path) -> None:
	sender = "test_sender"
	channel = "test_channel"
	chunk_size = 1000
	message_sender = MessageSender()
	test_file = str(tmp_path / "test_file_download.txt")

	file_download_request = FileDownloadRequestMessage(
		sender=sender,
		channel=channel,
		chunk_size=chunk_size,
		path=test_file,
	)
	await process_messagebus_message(file_download_request, send_message=message_sender.send_message)

	messages = await message_sender.wait_for_messages(count=1)
	assert len(messages) == 1
	assert isinstance(messages[0], FileTransferErrorMessage)
	assert messages[0].sender == CONNECTION_USER_CHANNEL
	assert not messages[0].back_channel
	assert messages[0].channel == sender
	assert messages[0].file_id == file_download_request.file_id

	# Create file and repeat

	res_sender = "test_res_sender"
	res_channel = "test_res_channel"
	res_back_channel = "test_res_back_channel"

	test_file_size = gen_test_file(file=test_file, chunk_size=chunk_size)
	file_download_request = FileDownloadRequestMessage(
		sender=res_sender,
		channel=res_channel,
		back_channel=res_back_channel,
		chunk_size=chunk_size,
		path=test_file,
	)
	await process_messagebus_message(
		file_download_request, send_message=message_sender.send_message, sender=res_sender, back_channel=res_channel
	)

	messages = await message_sender.wait_for_messages(count=1, true_count=True)
	assert isinstance(messages[0], FileDownloadResponseMessage)
	assert messages[0].sender == res_sender
	assert messages[0].back_channel == res_channel
	assert messages[0].size == test_file_size

	no_of_chunks = -(-test_file_size // chunk_size)
	data_messages = await message_sender.wait_for_messages(count=no_of_chunks, true_count=True)

	with Path(test_file).open("rb") as file:
		num = 0
		for data_message in data_messages:
			assert isinstance(data_message, FileChunkMessage)
			assert data_message.channel == res_back_channel
			assert data_message.number == num
			assert data_message.last is False
			assert data_message.data == file.read(chunk_size)
			num += 1

	last_message = await message_sender.wait_for_messages(count=1)
	assert isinstance(last_message[0], FileChunkMessage)
	assert last_message[0].channel == res_back_channel
	assert last_message[0].number == num
	assert last_message[0].last is True
	assert last_message[0].data == b""

	await wait_for_get_file_transfers_empty()

async def test_file_download_follow(tmp_path: Path) -> None:
	sender = "test_sender"
	channel = "test_channel"
	back_channel = "test_back_channel"
	chunk_size = 1000
	message_sender = MessageSender()
	test_file = str(tmp_path / "test_file_follow.txt")

	test_file_size = gen_test_file(file=test_file, chunk_size=chunk_size)
	no_of_chunks = -(-test_file_size // chunk_size)

	file_follow_request = FileDownloadRequestMessage(
		sender=sender,
		channel=channel,
		back_channel=back_channel,
		chunk_size=chunk_size,
		path=test_file,
		follow=True,
	)
	await process_messagebus_message(file_follow_request, send_message=message_sender.send_message, sender=sender, back_channel=channel)

	messages = await message_sender.wait_for_messages(count=1, true_count=True)
	assert isinstance(messages[0], FileDownloadResponseMessage)
	assert messages[0].sender == sender
	assert messages[0].back_channel == channel
	assert messages[0].size is None

	data_messages = await message_sender.wait_for_messages(count=no_of_chunks)

	num = 0
	with Path(test_file).open("rb") as file:
		for data_message in data_messages:
			assert isinstance(data_message, FileChunkMessage)
			assert data_message.channel == back_channel
			assert data_message.number == num
			assert data_message.last is False
			assert data_message.data == file.read(chunk_size)
			num += 1

	await asyncio.sleep(1)
	assert len(get_file_transfers()) == 1
	assert get_file_transfers()[0]._file_id == file_follow_request.file_id

	test_text = "moin moin"

	with Path(test_file).open("a+") as file:
		file.write(test_text)

	new_data_message = await message_sender.wait_for_messages(count=1)
	assert isinstance(new_data_message[0], FileChunkMessage)
	assert new_data_message[0].channel == back_channel
	assert new_data_message[0].number == num
	assert new_data_message[0].last is False
	assert new_data_message[0].data == bytes(test_text, encoding="UTF-8")

	assert await message_sender.no_messages()

	assert len(get_file_transfers()) == 1
	assert get_file_transfers()[0]._file_id == file_follow_request.file_id

	# Abort running file transfer
	file_download_abort_message = FileDownloadAbortRequestMessage(
		sender=sender,
		channel=channel,
		back_channel=back_channel,
		file_id=file_follow_request.file_id,
	)
	await process_messagebus_message(
		file_download_abort_message, send_message=message_sender.send_message, sender=sender, back_channel=channel
	)

	await wait_for_get_file_transfers_empty()

	await process_messagebus_message(
		file_download_abort_message, send_message=message_sender.send_message, sender=sender, back_channel=channel
	)
	new_data_message = await message_sender.wait_for_messages(count=1)
	assert isinstance(new_data_message[0], FileTransferErrorMessage)
	assert "not found" in new_data_message[0].error.message