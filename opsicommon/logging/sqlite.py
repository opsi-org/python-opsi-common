# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

import queue
import sqlite3
import threading
import time
from logging import Formatter, Handler, LogRecord
from pathlib import Path
from typing import Generator

from colorlog import ColoredFormatter

from opsicommon.logging import secret_filter
from opsicommon.logging.constants import (
	DATETIME_FORMAT,
	DEFAULT_COLORED_FORMAT,
	DEFAULT_FORMAT,
	LOG_COLORS,
	OPSI_LEVEL_TO_LEVEL,
	SECRET_REPLACEMENT_STRING,
)
from opsicommon.utils import json_decode, json_encode


class SQLiteLogReader:
	"""
	Reader for log records stored in a SQLite database.
	"""

	def __init__(self, db_path: Path | str) -> None:
		self.db_path = Path(db_path)
		self.connection = sqlite3.connect(self.db_path, check_same_thread=False)

	def flush(self) -> None:
		pass

	def get_records(
		self,
		*,
		start_time: float | None = None,
		end_time: float | None = None,
		max_level: int | None = None,
		context: dict[str, str] | None = None,
		max_records: int | None = None,
		follow: bool = False,
	) -> Generator[LogRecord, None, None]:
		"""
		Retrieves records from the SQLite database.
		Can filter records based on start_time, end_time, max_level, and context.
		Yields LogRecord instances.
		"""
		if max_level is not None and max_level < 10:
			max_level = OPSI_LEVEL_TO_LEVEL[max_level]

		filter_clauses = []
		filter_values = {}
		if start_time is not None:
			filter_clauses.append("timestamp_ms >= :start_time")
			filter_values["start_time"] = int(start_time * 1000)
		if end_time is not None:
			filter_clauses.append("timestamp_ms <= :end_time")
			filter_values["end_time"] = int(end_time * 1000)
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
		cursor = self.connection.cursor()
		while True:
			cursor.execute(query, filter_values)
			max_id = 0
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
				cursor.execute("SELECT max(id) FROM log_records")
				rec = cursor.fetchone()
				if rec and rec[0] is not None and rec[0] > max_id:
					max_id = rec[0]
					break
				time.sleep(0.1)

	def get_lines(
		self,
		*,
		start_time: float | None = None,
		end_time: float | None = None,
		max_level: int | None = None,
		context: dict[str, str] | None = None,
		max_records: int | None = None,
		follow: bool = False,
		format: str | None = None,
		datefmt: str = DATETIME_FORMAT,
		colored: bool = False,
	) -> Generator[str, None, None]:
		format = format or (DEFAULT_COLORED_FORMAT if colored else DEFAULT_FORMAT)
		formatter = ColoredFormatter(format, datefmt=datefmt, log_colors=LOG_COLORS) if colored else Formatter(format, datefmt=datefmt)

		for record in self.get_records(
			start_time=start_time,
			end_time=end_time,
			max_level=max_level,
			context=context,
			max_records=max_records,
			follow=follow,
		):
			yield formatter.format(record)

	def close(self) -> None:
		"""Closes the database connection."""
		try:
			self.connection.close()
		except Exception:
			pass


class SQLiteHandler(Handler, SQLiteLogReader):
	"""
	Logging handler for logging messages to a SQLite database.
	"""

	def __init__(self, db_path: Path | str, max_records: int = 0, flush_interval: float = 0.01, truncate_interval: float = 60.0) -> None:
		Handler.__init__(self)
		SQLiteLogReader.__init__(self, db_path)
		self.max_records = max_records
		self.connection: sqlite3.Connection
		self._lock = threading.RLock()

		self._queue: queue.Queue[tuple[int, int, str, str, int, bytes | None]] = queue.Queue()
		self._stop_event = threading.Event()
		self._writer_thread = threading.Thread(target=self._writer_loop, name="SQLiteHandlerWriter", daemon=True)
		self._flush_interval = flush_interval
		self._truncate_interval = truncate_interval
		self._last_truncate_time = time.time()

		self._initialize_database()
		self._writer_thread.start()

	def _initialize_database(self, recreate: bool = False) -> None:
		"""Initializes the SQLite database and creates the logs table if it doesn't exist."""
		if recreate and self.db_path.exists():
			self.db_path.unlink()

		self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
		try:
			self.connection.execute("PRAGMA synchronous = EXTRA")
		except sqlite3.DatabaseError:
			if recreate:
				raise
			return self._initialize_database(recreate=True)

		cursor = self.connection.cursor()
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
		self.connection.commit()

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

	def delete_records(self, end_time: float | None = None, keep_number: int | None = None) -> None:
		"""
		Deletes log records from the SQLite database.
		If end_time is provided, deletes records with a timestamp less than or equal to end_time.
		If end_time is None, deletes all records.
		If keep_number is provided, keeps the most recent 'keep_number' records.
		"""
		filter_clauses = []
		filter_values = []
		if end_time is not None:
			filter_clauses.append("timestamp_ms <= ?")
			filter_values.append(int(end_time * 1000))
		if keep_number is not None:
			filter_clauses.append("id NOT IN (SELECT id FROM log_records ORDER BY id DESC LIMIT ?)")
			filter_values.append(keep_number)

		filter_clause = "WHERE " + " AND ".join(filter_clauses) if filter_clauses else ""
		query = f"DELETE FROM log_records {filter_clause}"
		with self._lock:
			cursor = self.connection.cursor()
			cursor.execute(query, filter_values)
			self.connection.commit()

	def flush(self) -> None:
		with self._lock:
			batch: list[tuple[int, int, str, str, int, bytes | None]] = []
			while True:
				try:
					batch.append(self._queue.get_nowait())
				except queue.Empty:
					break
			if not batch:
				return

			cursor = self.connection.cursor()
			cursor.executemany(
				"""
					INSERT INTO log_records (timestamp_ms, level, message, filename, line_number, context)
					VALUES (?, ?, ?, ?, ?, ?)
					""",
				batch,
			)
			self.connection.commit()

	def close(self) -> None:
		"""Closes the database connection."""
		self._stop_event.set()
		if self._writer_thread.is_alive():
			self._writer_thread.join(timeout=2)
		self.flush()
		Handler.close(self)
		SQLiteLogReader.close(self)
