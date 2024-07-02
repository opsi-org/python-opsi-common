# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from __future__ import annotations

import asyncio
import locale
import os
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
from opsicommon.system.info import is_posix

processes: dict[str, Process] = {}
processes_lock = Lock()
logger = get_logger()


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
	max_data_size = 8192

	def __init__(
		self,
		process_start_request: ProcessStartRequestMessage,
		send_message: Callable,
		sender: str = CONNECTION_USER_CHANNEL,
		back_channel: str | None = None,
	) -> None:
		self._proc: AsyncioProcess | None = None
		self._send_message: Callable = send_message
		self._sender = sender
		self._process_start_request = process_start_request
		self._back_channel = back_channel or CONNECTION_SESSION_CHANNEL
		self._loop = asyncio.get_running_loop()
		self._message_send_lock = asyncio.Lock()

	def __repr__(self) -> str:
		return f"Process(command={self._command}, id={self._process_id}, shell={self._process_start_request.shell})"

	def __str__(self) -> str:
		info = "running"
		if self._proc and self._proc.returncode:
			info = f"finished - exit code {self._proc.returncode}"
		return f"{self._command[0]} ({info})"

	@property
	def _command(self) -> tuple[str, ...]:
		return self._process_start_request.command

	@property
	def _env(self) -> dict[str, str]:
		return self._process_start_request.env

	@property
	def _process_id(self) -> str:
		return self._process_start_request.process_id

	@property
	def _response_channel(self) -> str:
		return self._process_start_request.response_channel

	async def _stdout_reader(self) -> None:
		assert self._proc and self._proc.stdout
		while True:
			data = await self._proc.stdout.read(self.max_data_size)
			if not data:
				break
			async with self._message_send_lock:
				message = ProcessDataReadMessage(
					sender=self._sender,
					channel=self._response_channel,
					process_id=self._process_id,
					stdout=data,
				)
				await self._send_message(message)

	async def _stderr_reader(self) -> None:
		assert self._proc and self._proc.stderr
		while True:
			data = await self._proc.stderr.read(self.max_data_size)
			if not data:
				break
			async with self._message_send_lock:
				message = ProcessDataReadMessage(
					sender=self._sender,
					channel=self._response_channel,
					process_id=self._process_id,
					stderr=data,
				)
				await self._send_message(message)

	async def write_stdin(self, data: bytes) -> None:
		assert self._proc and self._proc.stdin
		self._proc.stdin.write(data)
		await self._proc.stdin.drain()

	async def close_stdin(self) -> None:
		if not self._proc or not self._proc.stdin:
			return
		self._proc.stdin.close()

	async def start(self) -> None:
		logger.notice("Received ProcessStartRequestMessage %r", self)
		message: ProcessMessage
		try:
			if is_posix():
				from opsicommon.system.posix.subprocess import get_subprocess_environment

				sp_env = get_subprocess_environment()
			else:
				sp_env = os.environ.copy()
			sp_env.update(self._env or {})
			sp_env["OPSI_PROCESS_ID"] = self._process_id

			if self._process_start_request.shell:
				self._proc = await asyncio.create_subprocess_shell(
					" ".join(self._command), env=sp_env, stdin=PIPE, stdout=PIPE, stderr=PIPE
				)
			else:
				self._proc = await asyncio.create_subprocess_exec(*self._command, env=sp_env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
		except Exception as error:
			logger.error(error, exc_info=True)
			async with self._message_send_lock:
				message = ProcessErrorMessage(
					sender=self._sender,
					channel=self._response_channel,
					ref_id=self._process_start_request.id,
					process_id=self._process_id,
					error=Error(message=str(error)),
				)
				await self._send_message(message)
			await self._loop.run_in_executor(None, remove_process, self._process_id)
			return

		locale_encoding = await self._loop.run_in_executor(None, get_locale_encoding, self._process_start_request.shell)
		async with self._message_send_lock:
			message = ProcessStartEventMessage(
				sender=self._sender,
				channel=self._response_channel,
				process_id=self._process_id,
				back_channel=self._back_channel,
				os_process_id=self._proc.pid,
				locale_encoding=locale_encoding,
			)
			await self._send_message(message)
			await asyncio.sleep(0.2)
		logger.info("Started %r", self)

		self._loop.create_task(self._stderr_reader())
		self._loop.create_task(self._stdout_reader())
		await asyncio.sleep(0.4)
		self._loop.create_task(self._wait_for_process())

	async def stop(self) -> None:
		logger.info("Stopping %r", self)
		if self._proc:
			await self.close_stdin()
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
			async with self._message_send_lock:
				message = ProcessStopEventMessage(
					sender=self._sender,
					channel=self._response_channel,
					process_id=self._process_id,
					exit_code=exit_code,
				)
				await self._send_message(message)
		except Exception as err:
			logger.error(err, exc_info=True)
		finally:
			await self._loop.run_in_executor(None, remove_process, self._process_id)


async def process_messagebus_message(
	message: ProcessMessage,
	send_message: Callable,
	*,
	sender: str = CONNECTION_USER_CHANNEL,
	back_channel: str | None = None,
) -> None:
	logger.trace("Processing message: %s", message)

	with processes_lock:
		process = processes.get(message.process_id)
	logger.trace("process: %s", process)

	try:
		if isinstance(message, ProcessStartRequestMessage):
			if not process:
				logger.debug("Creating new Process")
				process = Process(
					process_start_request=message,
					send_message=send_message,
					sender=sender,
					back_channel=back_channel,
				)
				with processes_lock:
					processes[message.process_id] = process
				logger.debug("Starting new Process")
				await process.start()
			else:
				raise RuntimeError(f"Process already open: {process!r}")
		elif process:
			if isinstance(message, ProcessDataWriteMessage):
				if not message.stdin:
					await process.close_stdin()
				else:
					await process.write_stdin(message.stdin)
			elif isinstance(message, ProcessStopRequestMessage):
				await process.stop()
			else:
				raise ValueError(f"Invalid message type {type(message)} received")
		else:
			raise RuntimeError(f"Process {message.process_id} not found")
	except Exception as err:
		logger.warning(err, exc_info=True)
		msg = ProcessErrorMessage(
			sender=sender,
			channel=message.response_channel,
			ref_id=message.id,
			process_id=message.process_id,
			error=Error(message=str(err)),
		)
		await send_message(msg)
		if process:
			await process.stop()


def remove_process(process_id: str) -> None:
	with processes_lock:
		try:
			del processes[process_id]
		except KeyError:
			pass


async def stop_running_processes() -> None:
	with processes_lock:
		for process in list(processes.values()):
			await process.stop()
