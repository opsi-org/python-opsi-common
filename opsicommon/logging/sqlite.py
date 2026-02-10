# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

import queue
import sqlite3
import threading
import time
from datetime import datetime, timezone
from logging import Formatter, Handler, LogRecord
from pathlib import Path
from typing import Generator

from colorlog import ColoredFormatter

from opsicommon.logging import ContextSecretFormatter, secret_filter
from opsicommon.logging.constants import (
	DATETIME_FORMAT,
	DEFAULT_COLORED_FORMAT,
	DEFAULT_FORMAT,
	LOG_COLORS,
	OPSI_LEVEL_TO_LEVEL,
	SECRET_REPLACEMENT_STRING,
	LoggingError,
)
from opsicommon.utils import json_decode, json_encode


def _timestamp_ms(time: float | datetime) -> int:
	if isinstance(time, datetime):
		if not time.tzinfo:
			time = time.astimezone()
		time = time.astimezone(timezone.utc).timestamp()
	return int(time * 1000)


class SQLiteLogDatabase:
	"""
	SQLite log database base class.
	"""

	def __init__(self, db_path: Path | str) -> None:
		self.db_path = Path(db_path)
		self._connection: sqlite3.Connection | None = None
		self._lock = threading.RLock()
		try:
			self._initialize_database()
		except Exception as exc:
			raise LoggingError(f"Failed to connect to SQLite database at {self.db_path}: {exc}") from exc

	def _initialize_database(self, recreate: bool = False) -> None:
		"""Initializes the SQLite database and creates the logs table if it doesn't exist."""
		if recreate and self.db_path.exists():
			self.db_path.unlink()

		self._connection = sqlite3.connect(self.db_path, check_same_thread=False)
		try:
			self._connection.execute("PRAGMA synchronous = EXTRA")
		except sqlite3.DatabaseError:
			try:
				self._connection.close()
				self._connection = None
			except Exception:
				pass
			if recreate:
				raise
			return self._initialize_database(recreate=True)

		cursor = self._connection.cursor()
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS log_records (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp_ms INTEGER NOT NULL,
				level INTEGER NOT NULL,
				message TEXT NOT NULL,
				filename TEXT NOT NULL,
				line_number INTEGER NOT NULL,
				context TEXT
			)
		""")
		cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_records_timestamp ON log_records (timestamp_ms)")
		cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_records_level ON log_records (level)")
		self._connection.commit()

	def flush(self) -> None:
		pass

	def get_records(
		self,
		*,
		since: float | datetime | None = None,
		until: float | datetime | None = None,
		max_level: int | None = None,
		context: dict[str, str] | None = None,
		search: str | None = None,
		max_records: int | None = None,
		follow: bool = False,
		timeout: float | None = None,
	) -> Generator[LogRecord, None, None]:
		"""
		Retrieves records from the SQLite database.
		Can filter records based on since, until, max_level, and context.
		Yields LogRecord instances.
		"""
		if self._connection is None:
			raise LoggingError("SQLite database connection is not initialized")

		if max_level is not None and max_level < 10:
			max_level = OPSI_LEVEL_TO_LEVEL[max_level]

		filter_clauses = []
		filter_values = {}
		if since is not None:
			filter_clauses.append("timestamp_ms >= :since")
			filter_values["since"] = _timestamp_ms(since)
		if until is not None:
			filter_clauses.append("timestamp_ms <= :until")
			filter_values["until"] = _timestamp_ms(until)
		if max_level is not None:
			filter_clauses.append("level >= :max_level")
			filter_values["max_level"] = int(max_level)
		if context is not None:
			idx = 0
			for key, value in context.items():
				idx += 1
				filter_clauses.append(f"json_extract(context, :context_key_{idx}) = :context_value_{idx}")
				filter_values[f"context_key_{idx}"] = f"$.{key}"
				filter_values[f"context_value_{idx}"] = value
		if search is not None:
			filter_clauses.append("message LIKE :search")
			filter_values["search"] = f"%{search}%"

		filter_clause = "WHERE " + " AND ".join(filter_clauses) if filter_clauses else ""
		base_query = f"""
			SELECT id, timestamp_ms, level, message, filename, line_number, context
			FROM log_records
			{filter_clause}
			"""
		if max_records is not None:
			query = f"SELECT * FROM ({base_query} ORDER BY id DESC LIMIT :max_records) AS subquery ORDER BY subquery.id ASC"
			filter_values["max_records"] = max_records
		else:
			query = f"{base_query} ORDER BY id ASC"

		self.flush()
		cursor = self._connection.cursor()
		last_record_id_read = 0
		start_time = time.monotonic()
		while True:
			mtime = self.db_path.stat().st_mtime
			cursor.execute(query, filter_values)
			for row in cursor:
				try:
					last_record_id_read = row[0] or 0
					record = LogRecord(name="", level=row[2], pathname=row[4] or "", lineno=row[5], msg=row[3], args=None, exc_info=None)
					record.created = (row[1] or 0) / 1000
					record.msecs = (row[1] or 0) % 1000
					if row[6]:
						setattr(record, "context", json_decode(row[6]))
					yield record
				except Exception:
					continue
			if not follow:
				return

			if "last_record_id_read" not in filter_values:
				query = base_query + (" AND " if filter_clause else " WHERE ") + "id > :last_record_id_read ORDER BY id ASC"
			filter_values["last_record_id_read"] = last_record_id_read

			while True:
				if timeout is not None and time.monotonic() - start_time > timeout:
					return
				# Wait for new records
				if self.db_path.stat().st_mtime != mtime:
					break
				time.sleep(0.2)

	def get_lines(
		self,
		*,
		since: float | datetime | None = None,
		until: float | datetime | None = None,
		max_level: int | None = None,
		context: dict[str, str] | None = None,
		search: str | None = None,
		max_records: int | None = None,
		follow: bool = False,
		format: str | None = None,
		datefmt: str = DATETIME_FORMAT,
		colored: bool = False,
		timeout: float | None = None,
	) -> Generator[str, None, None]:
		format = format or (DEFAULT_COLORED_FORMAT if colored else DEFAULT_FORMAT)
		formatter = ContextSecretFormatter(
			ColoredFormatter(format, datefmt=datefmt, log_colors=LOG_COLORS) if colored else Formatter(format, datefmt=datefmt)
		)

		for record in self.get_records(
			since=since,
			until=until,
			max_level=max_level,
			context=context,
			search=search,
			max_records=max_records,
			follow=follow,
			timeout=timeout,
		):
			yield formatter.format(record)

	def delete_records(self, until: float | datetime | None = None, keep_number: int | None = None) -> None:
		"""
		Deletes log records from the SQLite database.
		If until is provided, deletes records with a timestamp less than or equal to until.
		If until is None, deletes all records.
		If keep_number is provided, keeps the most recent 'keep_number' records.
		"""
		if self._connection is None:
			raise LoggingError("SQLite database connection is not initialized")

		filter_clauses = []
		filter_values = []
		if until is not None:
			filter_clauses.append("timestamp_ms <= ?")
			filter_values.append(_timestamp_ms(until))
		if keep_number is not None:
			filter_clauses.append("id NOT IN (SELECT id FROM log_records ORDER BY id DESC LIMIT ?)")
			filter_values.append(keep_number)

		filter_clause = "WHERE " + " AND ".join(filter_clauses) if filter_clauses else ""
		query = f"DELETE FROM log_records {filter_clause}"
		with self._lock:
			cursor = self._connection.cursor()
			cursor.execute(query, filter_values)
			self._connection.commit()

	def close(self) -> None:
		"""Closes the database connection."""
		try:
			if self._connection:
				self._connection.close()
				self._connection = None
		except Exception:
			pass


class SQLiteHandler(Handler, SQLiteLogDatabase):
	"""
	Logging handler for logging messages to a SQLite database.
	"""

	def __init__(self, db_path: Path | str, max_records: int = 0, flush_interval: float = 0.01, truncate_interval: float = 60.0) -> None:
		Handler.__init__(self)
		self.max_records = max_records

		self._queue: queue.Queue[tuple[int, int, str, str, int, bytes | None]] = queue.Queue()
		self._stop_event = threading.Event()
		self._flush_interval = flush_interval
		self._truncate_interval = truncate_interval
		self._last_truncate_time = time.time()
		self._writer_thread = threading.Thread(target=self._writer_loop, name="SQLiteHandlerWriter", daemon=True)

		SQLiteLogDatabase.__init__(self, db_path)

		self._writer_thread.start()

	def _writer_loop(self) -> None:
		while not self._stop_event.wait(self._flush_interval):
			if self._queue.qsize() > 0:
				self.flush()
			if self.max_records > 0:
				current_time = time.time()
				if current_time - self._last_truncate_time >= self._truncate_interval:
					self._last_truncate_time = current_time
					self.delete_records(keep_number=self.max_records)

	def emit(self, record: LogRecord) -> None:
		"""Queues a log record for insertion into the SQLite database."""
		if self._stop_event.is_set():
			return

		context_json = None
		if context := getattr(record, "context", None):
			context_json = json_encode(context)

		try:
			msg = record.getMessage()
		except TypeError:
			msg = record.msg
		for secret in secret_filter.secrets:
			msg = msg.replace(secret, SECRET_REPLACEMENT_STRING)

		if hasattr(record, "exc_info") and record.exc_info:
			# By calling format the formatted exception information is cached in attribute exc_text
			self.format(record)
			record.exc_info = None

		self._queue.put((int(record.created * 1000), record.levelno, msg, record.filename, record.lineno, context_json))

	def flush(self) -> None:
		if not self._connection:
			return

		with self._lock:
			batch: list[tuple[int, int, str, str, int, bytes | None]] = []
			while True:
				try:
					batch.append(self._queue.get_nowait())
				except queue.Empty:
					break
			if not batch:
				return

			try:
				cursor = self._connection.cursor()
				cursor.executemany(
					"""
						INSERT INTO log_records (timestamp_ms, level, message, filename, line_number, context)
						VALUES (?, ?, ?, ?, ?, ?)
						""",
					batch,
				)
				self._connection.commit()
			except Exception:
				if self._stop_event.is_set():
					return
				raise

	def close(self) -> None:
		"""Closes the database connection."""
		self._stop_event.set()
		if self._writer_thread.is_alive():
			self._writer_thread.join(timeout=2)
		self.flush()
		Handler.close(self)
		SQLiteLogDatabase.close(self)
