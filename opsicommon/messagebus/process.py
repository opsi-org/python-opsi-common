# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from __future__ import annotations

import asyncio
import locale
import platform
import re
import subprocess
from asyncio.subprocess import PIPE
from asyncio.subprocess import Process as AsyncioProcess
from functools import lru_cache
from threading import Lock
from typing import Callable

from opsicommon.logging import get_logger
from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	Error,
	ProcessDataReadMessage,
	ProcessDataWriteMessage,
	ProcessErrorMessage,
	ProcessMessage,
	ProcessStartEventMessage,
	ProcessStartRequestMessage,
	ProcessStopEventMessage,
	ProcessStopRequestMessage,
)

processes: dict[str, Process] = {}
processes_lock = Lock()
logger = get_logger("opsiclientd")


@lru_cache()
def get_locale_encoding(shell: bool = False) -> str:
	if platform.system().lower() == "windows" and shell:
		# Windows suggests cp1252 even if using something else like cp850
		try:
			output = subprocess.check_output("chcp", shell=True).decode("ascii", errors="replace")
			match = re.search(r": (\d+)", output)
			if match:
				codepage = int(match.group(1))
				return f"cp{codepage}"
		except Exception as error:
			logger.info("Failed to determine codepage, using default. %s", error)
	return locale.getencoding()


class Process:
	block_size = 8192

	def __init__(self, process_start_request: ProcessStartRequestMessage, send_message: Callable) -> None:
		self._proc: AsyncioProcess | None = None
		self._send_message: Callable = send_message
		self._process_start_request = process_start_request
		self._loop = asyncio.get_event_loop()

	@property
	def _command(self) -> tuple[str, ...]:
		return self._process_start_request.command

	@property
	def _process_id(self) -> str:
		return self._process_start_request.process_id

	@property
	def _response_channel(self) -> str:
		return self._process_start_request.response_channel

	def __repr__(self) -> str:
		return f"Process(command={self._command}, id={self._process_id}, shell={self._process_start_request.shell})"

	def __str__(self) -> str:
		info = "running"
		if self._proc and self._proc.returncode:
			info = f"finished - exit code {self._proc.returncode}"
		return f"{self._command[0]} ({info})"

	async def _stdout_reader(self) -> None:
		assert self._proc and self._proc.stdout
		while True:
			data = await self._proc.stdout.read(self.block_size)
			if not data:
				break
			message = ProcessDataReadMessage(
				sender=CONNECTION_USER_CHANNEL, channel=self._response_channel, process_id=self._process_id, stdout=data
			)
			await self._send_message(message)

	async def _stderr_reader(self) -> None:
		assert self._proc and self._proc.stderr
		while True:
			data = await self._proc.stderr.read(self.block_size)
			if not data:
				break
			message = ProcessDataReadMessage(
				sender=CONNECTION_USER_CHANNEL, channel=self._response_channel, process_id=self._process_id, stderr=data
			)
			await self._send_message(message)

	async def write_stdin(self, data: bytes) -> None:
		assert self._proc and self._proc.stdin
		self._proc.stdin.write(data)
		await self._proc.stdin.drain()

	async def start(self) -> None:
		logger.notice("Received ProcessStartRequestMessage %r", self)
		message: ProcessMessage
		try:
			if self._process_start_request.shell:
				self._proc = await asyncio.create_subprocess_shell(" ".join(self._command), stdin=PIPE, stdout=PIPE, stderr=PIPE)
			else:
				self._proc = await asyncio.create_subprocess_exec(*self._command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
		except Exception as error:
			logger.error(error, exc_info=True)
			message = ProcessErrorMessage(
				sender=CONNECTION_USER_CHANNEL,
				channel=self._response_channel,
				process_id=self._process_id,
				error=Error(message=str(error)),
			)
			await self._send_message(message)
			return

		locale_encoding = await self._loop.run_in_executor(None, get_locale_encoding, self._process_start_request.shell)
		message = ProcessStartEventMessage(
			sender=CONNECTION_USER_CHANNEL,
			channel=self._response_channel,
			process_id=self._process_id,
			back_channel=CONNECTION_SESSION_CHANNEL,
			os_process_id=self._proc.pid,
			locale_encoding=locale_encoding,
		)

		await self._send_message(message)
		logger.info("Started %r", self)

		self._loop.create_task(self._stderr_reader())
		self._loop.create_task(self._stdout_reader())
		self._loop.create_task(self._wait_for_process())

	async def stop(self) -> None:
		logger.info("Stopping %r (%r)", self)
		if self._proc:
			if self._proc.stdin:
				self._proc.stdin.close()
			for count in range(40):
				if self._proc.returncode is not None:
					break
				if count == 10:
					# Terminate after waiting 1 second
					self._proc.terminate()
				elif count in (20, 30):
					# Kill after waiting 2 and 3 seconds
					self._proc.kill()
				await asyncio.sleep(0.1)
			if self._proc.returncode is None:
				logger.error("Failed to terminate %r", self)

	async def _wait_for_process(self) -> None:
		assert self._proc
		exit_code = await self._proc.wait()
		logger.info("%r finished with exit code %d", self, exit_code)
		try:
			message = ProcessStopEventMessage(
				sender=CONNECTION_USER_CHANNEL, channel=self._response_channel, process_id=self._process_id, exit_code=exit_code
			)
			await self._send_message(message)
		except Exception as err:
			logger.error(err, exc_info=True)
		finally:
			with processes_lock:
				if self._process_id in processes:
					del processes[self._process_id]


async def process_messagebus_message(message: ProcessMessage, send_message: Callable) -> None:
	with processes_lock:
		process = processes.get(message.process_id)

	try:
		if isinstance(message, ProcessStartRequestMessage):
			if not process:
				with processes_lock:
					process = Process(process_start_request=message, send_message=send_message)
					processes[message.process_id] = process
					await processes[message.process_id].start()
			else:
				raise RuntimeError(f"Process already open: {process!r}")
			return
		if not process:
			raise RuntimeError(f"Process {message.process_id} not found")
		if isinstance(message, ProcessDataWriteMessage):
			await process.write_stdin(message.stdin)
			return
		if isinstance(message, ProcessStopRequestMessage):
			await process.stop()
			return
		raise RuntimeError("Invalid process id")
	except Exception as err:
		logger.warning(err, exc_info=True)
		if process:
			await process.stop()
		else:
			msg = ProcessErrorMessage(
				sender=CONNECTION_USER_CHANNEL,
				channel=message.response_channel,
				process_id=message.process_id,
				error=Error(message=str(err)),
			)
			await send_message(msg)


async def stop_running_processes() -> None:
	for process_id in list(processes.keys()):
		await processes[process_id].stop()
