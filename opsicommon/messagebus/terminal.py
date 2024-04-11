# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from __future__ import annotations

import shlex
from asyncio import Task, get_running_loop, wait_for
from pathlib import Path
from threading import Lock
from time import time
from typing import Callable

from psutil import AccessDenied, NoSuchProcess, Process

from opsicommon.logging import get_logger
from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	Error,
	TerminalCloseEventMessage,
	TerminalCloseRequestMessage,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalErrorMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
	TerminalResizeEventMessage,
	TerminalResizeRequestMessage,
)
from opsicommon.system.info import is_windows

DEFAULT_ROWS = 30
DEFAULT_COLUMNS = 120
PTY_READER_BLOCK_SIZE = 16 * 1024

terminals: dict[str, Terminal] = {}
terminals_lock = Lock()
logger = get_logger()

if is_windows():

	def start_pty(
		shell: str,
		rows: int | None = DEFAULT_ROWS,
		cols: int | None = DEFAULT_COLUMNS,
		cwd: str | None = None,
		env: dict[str, str] | None = None,
	) -> tuple[int, Callable, Callable, Callable, Callable]:
		rows = rows or DEFAULT_ROWS
		cols = cols or DEFAULT_COLUMNS

		logger.info("Starting new pty with shell %r, rows %r, cols %r, cwd %r", shell, rows, cols, cwd)
		try:
			# Import of winpty may sometimes fail because of problems with the needed dll.
			# Therefore we do not import at toplevel
			from winpty import PtyProcess  # type: ignore[import]

			process = PtyProcess.spawn(shlex.split(shell), dimensions=(rows, cols), env=env, cwd=cwd)
		except Exception as err:
			raise RuntimeError(f"Failed to start pty with shell {shell!r}: {err}") from err

		def read(length: int) -> bytes:
			return process.read(length).encode("utf-8")

		def write(data: bytes) -> int:
			return process.write(data.decode("utf-8"))

		return (process.pid, read, write, process.setwinsize, process.close)
else:

	def start_pty(
		shell: str,
		rows: int | None = DEFAULT_ROWS,
		cols: int | None = DEFAULT_COLUMNS,
		cwd: str | None = None,
		env: dict[str, str] | None = None,
	) -> tuple[int, Callable, Callable, Callable, Callable]:
		rows = rows or DEFAULT_ROWS
		cols = cols or DEFAULT_COLUMNS

		logger.info("Starting new pty with shell %r, rows %r, cols %r, cwd %r", shell, rows, cols, cwd)

		from ptyprocess import PtyProcess  # type: ignore[import]

		from opsicommon.system.posix.subprocess import get_subprocess_environment

		env = get_subprocess_environment(env)
		env.update({"TERM": "xterm-256color"})
		try:
			proc = PtyProcess.spawn(shlex.split(shell), dimensions=(rows, cols), env=env, cwd=cwd)
		except Exception as err:
			raise RuntimeError(f"Failed to start pty with shell {shell!r}: {err}") from err
		return (proc.pid, proc.read, proc.write, proc.setwinsize, proc.terminate)


class Terminal:
	default_rows = DEFAULT_ROWS
	default_cols = DEFAULT_COLUMNS
	max_rows = 100
	max_cols = 300
	idle_timeout = 8 * 3600
	read_timeout = 5

	def __init__(
		self,
		terminal_open_request: TerminalOpenRequestMessage,
		send_message: Callable,
		sender: str = CONNECTION_USER_CHANNEL,
		back_channel: str | None = None,
		default_shell: str | None = None,
	) -> None:
		self._send_message = send_message
		self._sender = sender
		self._terminal_open_request = terminal_open_request
		self._back_channel = back_channel or CONNECTION_SESSION_CHANNEL
		self._default_shell = "cmd.exe" if is_windows() else "bash"
		if default_shell:
			self._default_shell = default_shell
		self._loop = get_running_loop()
		self._last_usage = time()
		self._cwd = str(Path.home())
		self._pty_pid: int | None = None
		self._pty_read: Callable | None = None
		self._pty_write: Callable | None = None
		self._pty_set_size: Callable | None = None
		self._pty_stop: Callable | None = None
		self._closing = False
		self._pty_reader_task: Task | None = None
		self._set_size(terminal_open_request.rows, terminal_open_request.cols)

	@property
	def terminal_id(self) -> str:
		return self._terminal_open_request.terminal_id

	async def start(self) -> None:
		shell = self._terminal_open_request.shell or self._default_shell
		if not shell:
			raise RuntimeError("No shell specified")
		(
			self._pty_pid,
			self._pty_read,
			self._pty_write,
			self._pty_set_size,
			self._pty_stop,
		) = await self._loop.run_in_executor(
			None,
			start_pty,
			shell,
			self.rows,
			self.cols,
			self._cwd,
		)
		logger.debug("pty started")

	async def start_reader(self) -> None:
		self._pty_reader_task = self._loop.create_task(self._pty_reader())

	@property
	def _response_channel(self) -> str:
		return self._terminal_open_request.response_channel

	def _set_size(self, rows: int | None = None, cols: int | None = None) -> None:
		self.rows = min(max(1, int(rows or self.default_rows)), self.max_rows)
		self.cols = min(max(1, int(cols or self.default_cols)), self.max_cols)

	async def set_size(self, rows: int | None = None, cols: int | None = None) -> None:
		self._set_size(rows, cols)
		if self._pty_set_size:
			await self._loop.run_in_executor(None, self._pty_set_size, self.rows, self.cols)

	def get_cwd(self) -> Path | None:
		if not self._pty_pid:
			return None
		try:
			proc = Process(self._pty_pid)
		except (NoSuchProcess, ValueError):
			return None

		cwd = proc.cwd()
		for child in proc.children(recursive=True):
			try:
				cwd = child.cwd()
			except AccessDenied:
				# Child owned by an other user (su)
				pass
		return Path(cwd)

	async def _pty_reader(self) -> None:
		pty_reader_block_size = PTY_READER_BLOCK_SIZE
		read_timeout = self.read_timeout
		try:
			while self._pty_read and not self._closing:
				logger.trace("Read from pty")
				future = self._loop.run_in_executor(None, self._pty_read, pty_reader_block_size)
				try:
					data = await wait_for(future, read_timeout)
				except TimeoutError:
					if time() - self._last_usage > self.idle_timeout:
						raise
					continue
				if not data:
					raise EOFError("EOF (no data)")
				logger.trace(data)
				if self._closing:
					break
				self._last_usage = time()
				message = TerminalDataReadMessage(
					sender=self._sender, channel=self._response_channel, terminal_id=self.terminal_id, data=data
				)
				await self._send_message(message)
		except TimeoutError:
			logger.info("Terminal timed out")
			await self.close()
		except (IOError, EOFError):
			await self.close()
		except Exception as err:
			logger.error(err, exc_info=True)
			await self.close()

	async def process_message(self, message: TerminalDataWriteMessage | TerminalResizeRequestMessage | TerminalCloseRequestMessage) -> None:
		if isinstance(message, TerminalDataWriteMessage):
			if not self._closing and self._pty_write:
				# Do not wait for completion to minimize rtt
				self._loop.run_in_executor(None, self._pty_write, message.data)
		elif isinstance(message, TerminalResizeRequestMessage):
			await self.set_size(message.rows, message.cols)
			res_message = TerminalResizeEventMessage(
				sender=self._sender,
				channel=self._response_channel,
				ref_id=message.id,
				terminal_id=self.terminal_id,
				rows=self.rows,
				cols=self.cols,
			)
			await self._send_message(res_message)
		elif isinstance(message, TerminalCloseRequestMessage):
			await self.close()
		else:
			logger.warning("Received invalid message type %r", message.type)

	async def close(self, message: TerminalCloseRequestMessage | None = None, send_close_event: bool = True) -> None:
		if self._closing:
			return
		logger.info("Close terminal")
		self._closing = True
		try:
			if send_close_event:
				res_message = TerminalCloseEventMessage(
					sender=self._sender,
					channel=self._response_channel,
					ref_id=message.id if message else None,
					terminal_id=self.terminal_id,
				)
				await self._send_message(res_message)
			if self.terminal_id in terminals:
				del terminals[self.terminal_id]
			if self._pty_stop:
				self._pty_stop()
			if self._pty_reader_task:
				self._pty_reader_task.cancel()
		except Exception as err:
			logger.error(err, exc_info=True)
		finally:
			self._pty_pid = None
			self._pty_read = None
			self._pty_write = None
			self._pty_set_size = None
			self._pty_stop = None


async def process_messagebus_message(
	message: TerminalOpenRequestMessage | TerminalDataWriteMessage | TerminalResizeRequestMessage | TerminalCloseRequestMessage,
	send_message: Callable,
	*,
	sender: str = CONNECTION_USER_CHANNEL,
	back_channel: str | None = None,
) -> None:
	with terminals_lock:
		terminal = terminals.get(message.terminal_id)

	create_new = False

	try:
		if isinstance(message, TerminalOpenRequestMessage):
			create_new = not terminal
			if create_new:
				terminal = Terminal(
					terminal_open_request=message,
					send_message=send_message,
					sender=sender,
					back_channel=back_channel,
				)
				terminals[message.terminal_id] = terminal
			else:
				assert isinstance(terminal, Terminal)
				# Resize to redraw screen
				if message.rows == terminal.rows and message.cols == terminal.cols:
					await terminal.set_size(message.rows - 1, message.cols)
				await terminal.set_size(message.rows, message.cols)

			if create_new:
				await terminal.start()

			open_event = TerminalOpenEventMessage(
				sender=sender,
				channel=message.response_channel,
				ref_id=message.id,
				terminal_id=message.terminal_id,
				back_channel=back_channel,
				rows=terminal.rows,
				cols=terminal.cols,
			)
			await send_message(open_event)

			if create_new:
				await terminal.start_reader()
		elif terminal:
			await terminal.process_message(message)
		else:
			raise RuntimeError("Invalid terminal id")
	except Exception as err:
		logger.warning(err, exc_info=True)
		terminal_error = TerminalErrorMessage(
			sender=sender,
			channel=message.response_channel,
			ref_id=message.id,
			terminal_id=message.terminal_id,
			error=Error(message=f"Failed to create new terminal: {err}" if create_new else f"Terminal error: {err}"),
		)
		await send_message(terminal_error)
		if terminal:
			# Sending close event for backwards compatibility
			# TerminalErrorMessage was introduced in 2024-01
			await terminal.close(send_close_event=True)


def remove_terminal(terminal_id: str) -> None:
	with terminals_lock:
		try:
			del terminals[terminal_id]
		except KeyError:
			pass


async def stop_running_terminals() -> None:
	with terminals_lock:
		for terminal in list(terminals.values()):
			await terminal.close()
