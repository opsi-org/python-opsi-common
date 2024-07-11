# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from __future__ import annotations

import shlex
from asyncio import Task, get_running_loop, sleep, wait_for
from contextlib import nullcontext
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
	TerminalMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
	TerminalResizeEventMessage,
	TerminalResizeRequestMessage,
)
from opsicommon.system.info import is_windows
from opsicommon.system.subprocess import get_subprocess_environment

DEFAULT_ROWS = 30
DEFAULT_COLUMNS = 120

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

			sp_env = get_subprocess_environment()
			sp_env.update(env or {})

			process = PtyProcess.spawn(shlex.split(shell), dimensions=(rows, cols), env=sp_env, cwd=cwd)
		except Exception as err:
			raise RuntimeError(f"Failed to start pty with shell {shell!r}: {err}") from err

		def read(length: int) -> bytes:
			return process.read(length).encode("utf-8")

		def write(data: bytes) -> int:
			return process.write(data.decode("utf-8"))

		def close() -> None:
			process.close()
			try:
				# Help _read_in_thread to terminate
				process.pty.set_size(1, 1)
			except Exception:
				pass

		return (process.pid, read, write, process.setwinsize, close)
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

		sp_env = get_subprocess_environment()
		sp_env.update(env or {})
		if "TERM" not in sp_env:
			sp_env["TERM"] = "xterm-256color"
		try:
			proc = PtyProcess.spawn(shlex.split(shell), dimensions=(rows, cols), env=sp_env, cwd=cwd)
		except Exception as err:
			raise RuntimeError(f"Failed to start pty with shell {shell!r}: {err}") from err
		return (proc.pid, proc.read, proc.write, proc.setwinsize, proc.terminate)


class Terminal:
	default_rows = DEFAULT_ROWS
	default_cols = DEFAULT_COLUMNS
	pty_reader_block_size = 16 * 1024
	max_rows = 100
	max_cols = 300
	idle_timeout = 8 * 3600

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
		self._close_event_send = False
		self._manager_task: Task | None = None
		self._pty_reader_task: Task | None = None
		self._set_size(terminal_open_request.rows, terminal_open_request.cols)

	@property
	def terminal_id(self) -> str:
		return self._terminal_open_request.terminal_id

	async def _send_open_event(self) -> None:
		open_event = TerminalOpenEventMessage(
			sender=self._sender,
			channel=self._response_channel,
			ref_id=self._terminal_open_request.id,
			terminal_id=self.terminal_id,
			back_channel=self._back_channel,
			rows=self.rows,
			cols=self.cols,
		)
		await self._send_message(open_event)

	async def reuse(self, terminal_open_request: TerminalOpenRequestMessage) -> None:
		self._terminal_open_request = terminal_open_request
		# Resize to redraw screen
		if terminal_open_request.rows == self.rows and terminal_open_request.cols == self.cols:
			await self.set_size(terminal_open_request.rows - 1, terminal_open_request.cols)
		await self.set_size(terminal_open_request.rows, terminal_open_request.cols)
		self._last_usage = time()
		await self._send_open_event()

	async def start(self) -> None:
		shell = self._terminal_open_request.shell or self._default_shell
		if not shell:
			raise RuntimeError("No shell specified")
		logger.debug("Calling start_pty with loop %s", self._loop)
		sp_env = self._terminal_open_request.env or {}
		sp_env["OPSI_TERMINAL_ID"] = self.terminal_id
		future = self._loop.run_in_executor(None, start_pty, shell, self.rows, self.cols, self._cwd, sp_env)
		try:
			(
				self._pty_pid,
				self._pty_read,
				self._pty_write,
				self._pty_set_size,
				self._pty_stop,
			) = await wait_for(future, 10.0)
		except TimeoutError as err:
			raise RuntimeError("Failed to start pty: timed out") from err
		logger.debug("pty started")
		await self._start_manager()
		await self._send_open_event()
		await self._start_reader()

	async def _manager(self) -> None:
		while not self._closing:
			if time() - self._last_usage > self.idle_timeout:
				logger.info("Terminal idle timeout")
				await self.close()
				break
			await sleep(1)

	async def _start_manager(self) -> None:
		self._manager_task = self._loop.create_task(self._manager())

	async def _start_reader(self) -> None:
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
		pty_reader_block_size = self.pty_reader_block_size
		try:
			while self._pty_read and not self._closing:
				logger.trace("Read from pty")
				try:
					data = await self._loop.run_in_executor(None, self._pty_read, pty_reader_block_size)
				except RuntimeError:
					if self._closing:
						break
					raise
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
		except TimeoutError as err:
			logger.info("Terminal timed out: %s", err)
		except (IOError, EOFError) as err:
			logger.debug("Terminal IO error: %s", err)
			if not self._closing:
				await self.close()
		except Exception as err:
			logger.debug("Terminal error: %s", err)
			if not self._closing:
				logger.error(err, exc_info=True)
		if not self._closing:
			await self.close()

	async def process_message(self, message: TerminalDataWriteMessage | TerminalResizeRequestMessage | TerminalCloseRequestMessage) -> None:
		self._last_usage = time()
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
			await self.close(message=message)
		else:
			logger.warning("Received invalid message type %r", message.type)

	async def close(self, message: TerminalCloseRequestMessage | None = None, use_terminals_lock: bool = True) -> None:
		if self._closing:
			return
		logger.info("Close terminal")
		self._closing = True
		try:
			if not self._close_event_send:
				self._close_event_send = True
				res_message = TerminalCloseEventMessage(
					sender=self._sender,
					channel=self._response_channel,
					ref_id=message.id if message else None,
					terminal_id=self.terminal_id,
				)
				await self._send_message(res_message)
			with terminals_lock if use_terminals_lock else nullcontext():  # type: ignore[attr-defined]
				if self.terminal_id in terminals:
					del terminals[self.terminal_id]
			if self._pty_stop:
				await self._loop.run_in_executor(None, self._pty_stop)
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
	message: TerminalMessage,
	send_message: Callable,
	*,
	sender: str = CONNECTION_USER_CHANNEL,
	back_channel: str | None = None,
) -> None:
	logger.trace("Processing message: %s", message)

	with terminals_lock:
		terminal = terminals.get(message.terminal_id)
	logger.trace("terminal: %s", terminal)

	create_new = not terminal
	try:
		if isinstance(message, TerminalOpenRequestMessage):
			if create_new:
				logger.debug("Creating new Terminal")
				terminal = Terminal(
					terminal_open_request=message,
					send_message=send_message,
					sender=sender,
					back_channel=back_channel,
				)
				with terminals_lock:
					terminals[message.terminal_id] = terminal
				logger.debug("Starting new Terminal")
				await terminal.start()
			else:
				logger.debug("Reusing Terminal")
				assert isinstance(terminal, Terminal)
				await terminal.reuse(message)
		elif terminal:
			if isinstance(message, (TerminalDataWriteMessage, TerminalResizeRequestMessage, TerminalCloseRequestMessage)):
				await terminal.process_message(message)
			else:
				raise ValueError(f"Invalid message type {type(message)} received")
		else:
			raise RuntimeError(f"Terminal {message.terminal_id} not found")
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
			await terminal.close()


def remove_terminal(terminal_id: str) -> None:
	with terminals_lock:
		try:
			del terminals[terminal_id]
		except KeyError:
			pass


async def stop_running_terminals() -> None:
	with terminals_lock:
		for terminal in list(terminals.values()):
			await terminal.close(use_terminals_lock=False)
