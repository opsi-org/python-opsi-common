# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from threading import Lock
from time import time
from typing import AsyncGenerator, Callable

import aiofiles

from opsicommon.logging import get_logger
from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	Error,
	FileChunkMessage,
	FileDownloadAbortRequestMessage,
	FileDownloadRequestMessage,
	FileDownloadResponseMessage,
	FileTransferErrorMessage,
	FileTransferMessage,
	FileUploadRequestMessage,
	FileUploadResponseMessage,
	FileUploadResultMessage,
	Message,
)

DEFAULT_CHUNK_SIZE = 262144  # 256 KiB

file_transfers: dict[str, FileTransfer] = {}
file_transfers_lock = Lock()

logger = get_logger()


class FileTransfer:
	def __init__(
		self,
		send_message: Callable,
		file_request: FileDownloadRequestMessage | FileUploadRequestMessage,
		sender: str = CONNECTION_USER_CHANNEL,
		back_channel: str | None = None,
	) -> None:
		self._send_message: Callable = send_message
		self._sender = sender
		self._file_request = file_request
		self._back_channel = back_channel or CONNECTION_SESSION_CHANNEL
		self._loop = asyncio.get_running_loop()
		self._chunk_number = 0
		self._file_path: Path | None = None
		self._should_stop = False
		self._error: str | None = None
		self._completed = False

	def __str__(self) -> str:
		return f"{self.__class__.__name__}({self._file_request})"

	__repr__ = __str__

	@property
	def _file_id(self) -> str:
		return self._file_request.file_id

	@property
	def _response_channel(self) -> str:
		return self._file_request.response_channel

	async def stop(self) -> None:
		logger.info("Stopping %r (%r)", self)
		self._should_stop = True

	def _append_to_file(self, data: bytes) -> None:
		if not self._file_path:
			raise RuntimeError("File path not set")
		with open(self._file_path, mode="ab") as file:
			file.write(data)

	async def process_file_chunk(self, message: FileChunkMessage) -> None:
		if not isinstance(message, FileChunkMessage):
			raise ValueError(f"Received invalid message type {message.type}")

		if self._error:
			return

		self._last_chunk_time = time()
		if message.number != self._chunk_number + 1:
			await self._process_error(f"Expected chunk number {self._chunk_number + 1}", message)
			return

		self._chunk_number = message.number

		await self._loop.run_in_executor(None, self._append_to_file, message.data)

		if message.last:
			logger.debug("Last chunk received")
			self._completed = True
			upload_result = FileUploadResultMessage(
				sender=self._sender,
				channel=self._response_channel,
				file_id=self._file_id,
				back_channel=self._back_channel,
				path=str(self._file_path),
			)
			await self._send_message(upload_result)
			self._should_stop = True

	async def _process_error(self, error: str, message: Message | None = None) -> None:
		self._error = error
		logger.error(error)
		self._should_stop = True
		await self._loop.run_in_executor(None, remove_file_transfer, self._file_id)
		error_message = FileTransferErrorMessage(
			sender=self._sender,
			channel=self._response_channel,
			ref_id=message.id if message else None,
			file_id=self._file_id,
			error=Error(
				code=None,
				message=error,
				details=None,
			),
		)
		await self._send_message(error_message)
		self._should_stop = True


class FileUpload(FileTransfer):
	chunk_timeout = 300
	default_destination: Path | None = None

	def __init__(
		self,
		send_message: Callable,
		file_upload_request: FileUploadRequestMessage,
		sender: str = CONNECTION_USER_CHANNEL,
		back_channel: str | None = None,
	) -> None:
		super().__init__(
			send_message=send_message,
			file_request=file_upload_request,
			sender=sender,
			back_channel=back_channel,
		)
		self._last_chunk_time = time()

	async def start(self) -> None:
		assert isinstance(self._file_request, FileUploadRequestMessage)
		logger.notice("Received FileUploadRequestMessage %r", self)

		try:
			if not self._file_request.name:
				raise ValueError("Invalid name")
			if not self._file_request.content_type:
				raise ValueError("Invalid content_type")

			destination_path: Path | None = None
			if self._file_request.destination_dir:
				destination_path = Path(self._file_request.destination_dir)
			elif self.default_destination:
				destination_path = self.default_destination
			else:
				raise ValueError("Invalid destination_dir")

			self._file_path = (destination_path / self._file_request.name).absolute()
			if not self._file_path.is_relative_to(destination_path):
				raise ValueError("Invalid name")

			orig_name = self._file_path.name
			ext = 0
			while self._file_path.exists():
				ext += 1
				self._file_path = self._file_path.with_name(f"{orig_name}.{ext}")
			self._file_path.touch()
			self._file_path.chmod(0o660)

		except Exception as error:
			logger.error(error, exc_info=True)
			await self._process_error(str(error), message=self._file_request)
			return

		message = FileUploadResponseMessage(
			sender=self._sender,
			channel=self._response_channel,
			file_id=self._file_id,
			back_channel=self._back_channel,
			path=str(self._file_path),
		)

		await self._send_message(message)

		self._manager_task = self._loop.create_task(self._manager())
		logger.info("Started %r", self)

	async def _manager(self) -> None:
		while True:
			if self._should_stop:
				if not self._completed:
					await self._process_error("File transfer stopped before completion")
					return
				break
			if time() > self._last_chunk_time + self.chunk_timeout:
				await self._process_error("File transfer timed out while waiting for next chunk")
				return
			await asyncio.sleep(1)
		await self._loop.run_in_executor(None, remove_file_transfer, self._file_id)

	def _append_to_file(self, data: bytes) -> None:
		if not self._file_path:
			raise RuntimeError("File path not set")
		with open(self._file_path, mode="ab") as file:
			file.write(data)

	async def process_file_chunk(self, message: FileChunkMessage) -> None:
		if not isinstance(message, FileChunkMessage):
			raise ValueError(f"Received invalid message type {message.type}")

		self._last_chunk_time = time()
		if message.number != self._chunk_number + 1:
			await self._process_error(f"Expected chunk number {self._chunk_number + 1}", message)
			return

		self._chunk_number = message.number

		await self._loop.run_in_executor(None, self._append_to_file, message.data)

		if message.last:
			logger.debug("Last chunk received")
			self._completed = True
			upload_result = FileUploadResultMessage(
				sender=self._sender,
				channel=self._response_channel,
				file_id=self._file_id,
				back_channel=self._back_channel,
				path=str(self._file_path),
			)
			await self._send_message(upload_result)
			self._should_stop = True


class FileDownload(FileTransfer):
	def __init__(
		self,
		send_message: Callable,
		file_download_request: FileDownloadRequestMessage,
		sender: str = CONNECTION_USER_CHANNEL,
		back_channel: str | None = None,
	) -> None:
		super().__init__(
			send_message=send_message,
			file_request=file_download_request,
			sender=sender,
			back_channel=back_channel,
		)
		self._chunk_size = DEFAULT_CHUNK_SIZE
		if file_download_request.chunk_size and file_download_request.chunk_size > 0:
			self._chunk_size = int(file_download_request.chunk_size)
		self._size: int | None = None

	async def start(self) -> None:
		assert isinstance(self._file_request, FileDownloadRequestMessage)
		logger.notice("Received FileDownloadRequestMessage %r", self)

		try:
			if not self._file_request.path:
				raise ValueError("File path missing")
			if not Path(self._file_request.path).is_file():
				raise FileNotFoundError(f"File '{self._file_request.path}' is missing or file path is incorrect")
		except Exception as error:
			logger.error(error, exc_info=True)
			await self._process_error(str(error), message=self._file_request)
			return

		if self._file_request.follow:
			self._size = None
		else:
			self._size = Path(self._file_request.path).stat().st_size

		self._manager_task = self._loop.create_task(self._manager())

		message = FileDownloadResponseMessage(
			sender=self._sender,
			channel=self._response_channel,
			file_id=self._file_id,
			back_channel=self._back_channel,
			size=self._size,
		)

		await self._send_message(message)

		logger.info("Started %r")

	async def _manager(self) -> None:
		logger.debug("Starting download manager")
		assert isinstance(self._file_request, FileDownloadRequestMessage)
		assert isinstance(self._file_request.path, str)
		assert isinstance(self._size, int | None)

		number = 0
		self.last = False
		file_data_stream = self.read_file()
		while not self._should_stop:
			try:
				data = await anext(file_data_stream)  # noqa: F821
			except StopAsyncIteration:
				logger.notice("File interaction stopped")
				break

			chunk_message = FileChunkMessage(
				sender=self._sender,
				channel=self._response_channel,
				back_channel=self._back_channel,
				number=number,
				last=self.last,
				data=data,
			)
			await self._send_message(chunk_message)
			number += 1

		await self._loop.run_in_executor(None, remove_file_transfer, self._file_id)

	async def read_file(self) -> AsyncGenerator[bytes, None]:
		assert isinstance(self._file_request, FileDownloadRequestMessage)
		assert isinstance(self._file_request.path, str)
		logger.notice("Started reading file")
		try:
			async with aiofiles.open(self._file_request.path, "rb") as file:
				while not self.last and not self._should_stop:
					tmp = await file.read(self._chunk_size)
					if tmp:
						yield tmp
					elif self._file_request.follow:
						await asyncio.sleep(0.1)
					else:
						self.last = True
						yield tmp
		except IOError:
			await self._process_error(f"Unexpected IOError: {str(IOError)}")


async def process_messagebus_message(
	message: FileTransferMessage,
	send_message: Callable,
	*,
	sender: str = CONNECTION_USER_CHANNEL,
	back_channel: str | None = None,
) -> None:
	logger.trace("Processing message: %s", message)

	with file_transfers_lock:
		file_transfer = file_transfers.get(message.file_id)
	logger.trace("file_transfer: %s", file_transfer)

	try:
		if isinstance(message, FileUploadRequestMessage):
			if not file_transfer:
				logger.debug("Creating new FileUpload")
				file_transfer = FileUpload(
					file_upload_request=message,
					send_message=send_message,
					sender=sender,
					back_channel=back_channel,
				)
				with file_transfers_lock:
					file_transfers[message.file_id] = file_transfer
				logger.debug("Starting new FileUpload")
				await file_transfer.start()
			else:
				raise RuntimeError(f"File upload already running: {file_transfer!r}")
			return
		elif isinstance(message, FileDownloadRequestMessage):
			if not file_transfer:
				with file_transfers_lock:
					file_transfer = FileDownload(
						file_download_request=message,
						send_message=send_message,
						sender=sender,
						back_channel=back_channel,
					)
					file_transfers[message.file_id] = file_transfer
				await file_transfer.start()
			else:
				raise RuntimeError(f"File download already running: {file_transfer!r}")
			return
		elif file_transfer:
			if isinstance(message, FileChunkMessage) and isinstance(file_transfer, FileUpload):
				await file_transfer.process_file_chunk(message)
			elif isinstance(message, FileDownloadAbortRequestMessage):
				await file_transfer.stop()
			else:
				raise ValueError(f"Invalid message type {type(message)} received")
		else:
			raise RuntimeError(f"FileTransfer {message.file_id} not found")
	except Exception as err:
		logger.warning(err, exc_info=True)
		msg = FileTransferErrorMessage(
			sender=sender,
			channel=message.response_channel,
			ref_id=message.id,
			file_id=message.file_id,
			error=Error(message=str(err)),
		)
		await send_message(msg)
		if file_transfer:
			await file_transfer.stop()


def remove_file_transfer(file_id: str) -> None:
	with file_transfers_lock:
		try:
			del file_transfers[file_id]
		except KeyError:
			pass


async def stop_running_file_transfers() -> None:
	with file_transfers_lock:
		for file_transfer in list(file_transfers.values()):
			await file_transfer.stop()


def get_file_transfers() -> list[FileTransfer]:
	with file_transfers_lock:
		return list(file_transfers.values())
