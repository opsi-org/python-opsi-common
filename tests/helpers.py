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
from pathlib import Path
from typing import Generator

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


class MessageSender:
	def __init__(self, print_messages: bool = False) -> None:
		self.print_messages = print_messages
		self.messages_sent: list[Message] = []

	async def send_message(self, message: Message) -> None:
		if self.print_messages:
			print(message.to_dict())
		self.messages_sent.append(message)

	async def wait_for_messages(
		self,
		count: int,
		timeout: float = 10.0,
		clear_messages: bool = True,
		error_on_timeout: bool = True,
		true_count: bool = False,
	) -> list[Message]:
		start = time.time()
		while len(self.messages_sent) < count:
			if time.time() - start > timeout:
				if error_on_timeout:
					raise TimeoutError(f"Timeout waiting for {count} messages")
				break
			await asyncio.sleep(0.1)

		if not clear_messages:
			if not true_count:
				return self.messages_sent
			else:
				return self.messages_sent[0:count]

		if true_count:
			messages = self.messages_sent[0:count].copy()
			self.messages_sent = self.messages_sent[count:].copy()
		else:
			messages = self.messages_sent.copy()
			self.messages_sent = []
		return messages


class MessageSenderDownload(MessageSender):
	def __init__(self, print_messages: bool = False) -> None:
		super().__init__(print_messages)


def gen_test_file(file: Path | str, chunk_size: int, error_if_file_exists: bool = False) -> int:
	chunk_size = chunk_size
	file = Path(file)
	file_data = ""
	word = "opsi"
	for letter in word:
		file_data += letter * chunk_size

	if file.is_file():
		if error_if_file_exists:
			raise FileExistsError(f"File {str(file)} alredy exists")
		else:
			print(f"File {str(file)} alredy exists")
		return file.stat().st_size
	file.write_text(file_data, encoding="ascii")
	file_size = file.stat().st_size
	assert file_size == len(word) * chunk_size
	return file_size
