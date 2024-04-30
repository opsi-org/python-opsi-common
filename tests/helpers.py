# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing opsi.
"""

import asyncio
import io
import os
import time
from contextlib import contextmanager
from typing import Generator, Path, TextIOWrapper

from opsicommon.logging import use_logging_config
from opsicommon.messagebus.message import Message


@contextmanager
def log_stream(new_level: int, format: str | None = None) -> Generator[io.StringIO, None, None]:
	stream = io.StringIO()
	with use_logging_config(stderr_level=new_level, stderr_format=format, stderr_file=stream):
		yield stream


@contextmanager
def environment(**env_vars: str) -> Generator[None, None, None]:
	env_bak = os.environ.copy()
	try:
		os.environ.clear()
		os.environ.update(env_vars)
		yield
	finally:
		os.environ = env_bak  # type: ignore[assignment]

def read_in_chunks(file: TextIOWrapper , chunk_size: int) {
	while True:
		data = file
}

class MessageSender:
	def __init__(self, print_messages: bool = False) -> None:
		self.print_messages = print_messages
		self.messages_sent: list[Message] = []

	async def send_message(self, message: Message) -> None:
		if self.print_messages:
			print(message.to_dict())
		self.messages_sent.append(message)

	async def wait_for_messages(
		self, count: int, timeout: float = 10.0, clear_messages: bool = True, error_on_timeout: bool = True
	) -> list[Message]:
		start = time.time()
		while len(self.messages_sent) < count:
			if time.time() - start > timeout:
				if error_on_timeout:
					raise TimeoutError(f"Timeout waiting for {count} messages")
				break
			await asyncio.sleep(0.1)
		if not clear_messages:
			return self.messages_sent

		messages = self.messages_sent.copy()
		self.messages_sent = []
		return messages


class MessageServer:
	def __init__(self, print_messages: bool = False) -> None:
		self.size: int | None = None
		self.print_messages = print_messages
		self.message_sent: list[Message] = []

	def gen_test_file(self, file_path: str, error_if_file_exists: bool = False) -> None:
		chunk_size = 1000
		test_file = Path(file_path)
		if test_file.is_file():
			if error_if_file_exists:
				raise FileExistsError(f"File {str(test_file)} alredy exists")
			else:
				print(f"File {str(test_file)} alredy exists")
			return
		test_file.write_text("opsi" * chunk_size, encoding="ascii")
		file_size = test_file.stat().st_size
		assert file_size == chunk_size * 4
		self.size = file_size

	async def send_request(self, message: Message) -> None:
		if self.print_messages:
			print(message.to_dict())
		self.message_sent.append(message)

	async def wait_for_messages(
		self, count: int, timeout: float = 10.0, clear_messages: bool = True, error_on_timeout: bool = True
	) -> list[Message]:
		start = time.time()
		while len(self.message_sent) < count:
			if time.time() - start > timeout:
				if error_on_timeout:
					raise TimeoutError(f"Timeout waiting for {count} messages")
				break
			await asyncio.sleep(0.1)
		if not clear_messages:
			return self.messages_sent

		messages = self.message_sent.copy()
		self.message_sent = []
		return messages

	async def responde_to_request() ->None:

		# TODO
		# add FileDownloadInformationMessage return

		# then start Download process aka Data Stream

		# redundant
		# messages = self.message_sent.copy()
		# self.message_sent = []
		# return messages
