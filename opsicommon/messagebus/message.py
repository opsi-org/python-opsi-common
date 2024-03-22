# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""
from __future__ import annotations

from abc import ABC
from enum import StrEnum
from typing import Annotated, Any, Type, TypeVar, cast
from uuid import uuid4

import msgspec
from pydantic import AfterValidator, AliasChoices, BaseModel, Field, StringConstraints

from opsicommon.utils import unix_timestamp

message_decoder = msgspec.msgpack.Decoder()
message_encoder = msgspec.msgpack.Encoder()


DEFAULT_MESSAGE_VALIDITY_PERIOD = 60000  # Milliseconds


class MessageType(StrEnum):
	GENERAL_ERROR = "general_error"
	EVENT = "event"
	CHANNEL_SUBSCRIPTION_REQUEST = "channel_subscription_request"
	CHANNEL_SUBSCRIPTION_EVENT = "channel_subscription_event"
	TRACE_REQUEST = "trace_request"
	TRACE_RESPONSE = "trace_response"
	JSONRPC_REQUEST = "jsonrpc_request"
	JSONRPC_RESPONSE = "jsonrpc_response"
	TERMINAL_ERROR = "terminal_error"
	TERMINAL_OPEN_REQUEST = "terminal_open_request"
	TERMINAL_OPEN_EVENT = "terminal_open_event"
	TERMINAL_RESIZE_REQUEST = "terminal_resize_request"
	TERMINAL_RESIZE_EVENT = "terminal_resize_event"
	TERMINAL_DATA_READ = "terminal_data_read"
	TERMINAL_DATA_WRITE = "terminal_data_write"
	TERMINAL_CLOSE_REQUEST = "terminal_close_request"
	TERMINAL_CLOSE_EVENT = "terminal_close_event"
	PROCESS_ERROR = "process_error"
	PROCESS_START_REQUEST = "process_start_request"
	PROCESS_START_EVENT = "process_start_event"
	PROCESS_STOP_REQUEST = "process_stop_request"
	PROCESS_STOP_EVENT = "process_stop_event"
	PROCESS_DATA_READ = "process_data_read"
	PROCESS_DATA_WRITE = "process_data_write"
	FILE_TRANSFER_ERROR = "file_transfer_error"
	FILE_UPLOAD_REQUEST = "file_upload_request"
	FILE_UPLOAD_RESPONSE = "file_upload_response"
	FILE_UPLOAD_RESULT = "file_upload_result"
	FILE_CHUNK = "file_chunk"


class ErrorCode(StrEnum):
	FILE_NOT_FOUND = "file_not_found"
	TIMEOUT_REACHED = "timeout_reached"
	PERMISSION_ERROR = "permission_error"


# Legacy name
MessageErrorEnum = ErrorCode


def timestamp(add_seconds: float = 0.0) -> int:
	"""
	Returns the current time (UTC) as messagebus timestamp.
	`add_seconds` can be used to add or subtract seconds from the current time.
	"""
	return int(unix_timestamp(millis=True, add_seconds=add_seconds))


class Error(BaseModel):
	message: str
	code: ErrorCode | Annotated[int, AfterValidator(lambda x: None)] | None = None  # change int to None for backwards compatibility
	details: Any = None


UUID4Str = Annotated[
	str, StringConstraints(pattern=r"^[0-9a-f]{8}\-[0-9a-f]{4}\-4[0-9a-f]{3}\-[89ab][0-9a-f]{3}\-[0-9a-f]{12}$", strict=True)
]

MessageT = TypeVar("MessageT", bound="Message")


class Message(BaseModel, ABC):
	type: str  # Custom message types are allowed
	sender: str
	channel: str
	back_channel: str | None = None
	id: UUID4Str = Field(default_factory=lambda: str(uuid4()))
	created: int = Field(default_factory=timestamp)
	expires: int = Field(default_factory=lambda: timestamp() + DEFAULT_MESSAGE_VALIDITY_PERIOD)
	ref_id: str | None = None

	@classmethod
	def from_dict(cls: Type[MessageT], data: dict[str, Any]) -> MessageT:
		_cls = cls
		if _cls is Message:
			_type = data.get("type")
			if _type:
				if isinstance(_type, MessageType):
					_type = _type.value
				_cls = cast(Type[MessageT], MESSAGE_TYPE_TO_CLASS.get(_type, Message))
		return _cls(**data)

	def to_dict(self, none_values: bool = False) -> dict[str, Any]:
		_dict = self.model_dump()
		if none_values:
			return _dict
		return {k: v for k, v in _dict.items() if v is not None}

	@property
	def response_channel(self) -> str:
		return self.back_channel or self.sender

	@classmethod
	def from_msgpack(cls: Type[MessageT], data: bytes) -> MessageT:
		return cls.from_dict(message_decoder.decode(data))

	def to_msgpack(self, none_values: bool = False) -> bytes:
		return message_encoder.encode(self.to_dict(none_values=none_values))

	def __repr__(self) -> str:
		return f"Message(type={self.type}, channel={self.channel}, sender={self.sender})"

	def __str__(self) -> str:
		return f"({self.type}, {self.channel}, {self.sender})"


# General
class GeneralErrorMessage(Message):
	"""
	Base Class for Error Messages

	Used to transport Error object via messagebus
	"""

	type: str = MessageType.GENERAL_ERROR.value
	error: Error


# Event
class EventMessage(Message):
	"""
	Class for Event Messages

	Used to notify messagebus of an event that occured.
	"""

	type: str = MessageType.EVENT.value
	event: str
	data: dict[str, Any] = Field(default_factory=dict)


class ChannelSubscriptionOperation(StrEnum):
	SET = "set"
	ADD = "add"
	REMOVE = "remove"


class ChannelSubscriptionRequestMessage(Message):
	"""
	Message for requesting channel access

	Can be used to set, add or remove subscribed channels.
	"""

	type: str = MessageType.CHANNEL_SUBSCRIPTION_REQUEST.value
	channels: list[str]
	operation: str = ChannelSubscriptionOperation.SET.value


class ChannelSubscriptionEventMessage(Message):
	"""
	Message for confirming channel access

	Is response to ChannelSubscriptionRequestMessage and contains total subscribed_channels or error.
	"""

	type: str = MessageType.CHANNEL_SUBSCRIPTION_EVENT.value
	error: Error | None = None
	subscribed_channels: list[str] = Field(default_factory=list)


class TraceRequestMessage(Message):
	"""
	Message for tracing transmission times

	It contains trace data (timestamp of sending).
	"""

	type: str = MessageType.TRACE_REQUEST.value
	trace: dict[str, Any] = Field(default_factory=dict)  # type: ignore[assignment]
	payload: bytes | None = None


class TraceResponseMessage(Message):
	"""
	Message for tracing transmission times (response)

	It contains trace data (timestamp of sending, receiving request and response).
	"""

	type: str = MessageType.TRACE_RESPONSE.value
	req_trace: dict[str, Any]
	trace: dict[str, Any]
	payload: bytes | None = None


# JSONRPC
class JSONRPCRequestMessage(Message):
	"""
	Message for triggering an rpc

	Requests the execution of an rpc with given parameters on receiving end.
	"""

	type: str = MessageType.JSONRPC_REQUEST.value
	api_version: str = "1"
	rpc_id: str | int = Field(default_factory=lambda: str(uuid4()))
	method: str
	params: tuple[Any, ...] = tuple()


class JSONRPCResponseMessage(Message):
	"""
	Message for transmitting result of rpc

	Is response to JSONRPCRequestMessage and contains either result or an error.
	rpc_id matches the one specified in the corresponding JSONRPCRequestMessage.
	"""

	type: str = MessageType.JSONRPC_RESPONSE.value
	rpc_id: str | int
	error: Any = None
	result: Any = None


# Terminal
class TerminalMessage(Message, ABC):
	"""
	Message interacting with a terminal

	terminal_id is used as an identifier.
	"""

	terminal_id: str = Field(min_length=1)


class TerminalErrorMessage(TerminalMessage):
	"""
	Message reporting a terminal related Error

	Used to transport Error object via messagebus.
	"""

	type: str = MessageType.TERMINAL_ERROR.value
	error: Error


class TerminalOpenRequestMessage(TerminalMessage):
	"""
	Message requesting to open a terminal

	Shell and number of rows and columns can be specified.
	If a terminal with that id already exists,
	access to this terminal may be granted resulting in shared access to it.
	"""

	type: str = MessageType.TERMINAL_OPEN_REQUEST.value
	rows: int | None = None
	cols: int | None = None
	shell: str | None = None


class TerminalOpenEventMessage(TerminalMessage):
	"""
	Message to respond to TerminalOpenRequestMessage

	Contains number of rows and columns.
	"""

	type: str = MessageType.TERMINAL_OPEN_EVENT.value
	rows: int
	cols: int


class TerminalDataReadMessage(TerminalMessage):
	"""
	Message transmitting terminal output data

	Terminal output data is contained as bytes.
	"""

	type: str = MessageType.TERMINAL_DATA_READ.value
	data: bytes


class TerminalDataWriteMessage(TerminalMessage):
	"""
	Message transmitting terminal input data

	Terminal input data (stdin) is contained as bytes.
	"""

	type: str = MessageType.TERMINAL_DATA_WRITE.value
	data: bytes


class TerminalResizeRequestMessage(TerminalMessage):
	"""
	Message requesting to resize an open terminal

	Contains new number of rows and columns for an already open terminal.
	"""

	type: str = MessageType.TERMINAL_RESIZE_REQUEST.value
	rows: int
	cols: int


class TerminalResizeEventMessage(TerminalMessage):
	"""
	Message to respond to TerminalResizeRequestMessage

	Contains new number of rows and columns.
	"""

	type: str = MessageType.TERMINAL_RESIZE_EVENT.value
	rows: int
	cols: int


class TerminalCloseRequestMessage(TerminalMessage):
	"""
	Message to request a terminal to be closed

	Contains terminal_id for open termial to be closed.
	"""

	type: str = MessageType.TERMINAL_CLOSE_REQUEST.value


class TerminalCloseEventMessage(TerminalMessage):
	"""
	Message to respond to TerminalCloseRequestMessage
	"""

	type: str = MessageType.TERMINAL_CLOSE_EVENT.value


# ProcessExecute
class ProcessMessage(Message, ABC):
	"""
	Message regarding a process.

	Contains a unique process_id.
	"""

	process_id: UUID4Str = Field(default_factory=lambda: str(uuid4()))


class ProcessErrorMessage(ProcessMessage):
	"""
	Message reporting a process related Error

	Used to transport Error object via messagebus.
	"""

	type: str = MessageType.PROCESS_ERROR.value
	error: Error


class ProcessStartRequestMessage(ProcessMessage):
	"""
	Message requesting to start a process

	Contains a unique process_id and the command to execute as tuple. Optional timeout.
	"""

	type: str = MessageType.PROCESS_START_REQUEST.value
	command: tuple[str, ...] = tuple()
	timeout: int = 0
	shell: bool = False


class ProcessStartEventMessage(ProcessMessage):
	"""
	Message to respond to ProcessStartRequestMessage

	Contains the local process id.
	"""

	type: str = MessageType.PROCESS_START_EVENT.value
	# The field was renamed from local_process_id to os_process_id in 4.3.7.5
	os_process_id: int = Field(validation_alias=AliasChoices("os_process_id", "local_process_id"))
	locale_encoding: str | None = None


class ProcessStopRequestMessage(ProcessMessage):
	"""
	Message requesting to stop a running process

	Contains the local process id.
	"""

	type: str = MessageType.PROCESS_STOP_REQUEST.value


class ProcessStopEventMessage(ProcessMessage):
	"""
	Message to respond to ProcessStopRequestMessage

	Contains the exit code of the process. May contain error.
	"""

	type: str = MessageType.PROCESS_STOP_EVENT.value
	exit_code: int


class ProcessDataReadMessage(ProcessMessage):
	"""
	Message transmitting process output data

	Process stdout and stderr output data is contained as bytes.
	"""

	type: str = MessageType.PROCESS_DATA_READ.value
	stdout: bytes = b""
	stderr: bytes = b""


class ProcessDataWriteMessage(ProcessMessage):
	"""
	Message transmitting process input data

	Process input data (stdin) is contained as bytes.
	"""

	type: str = MessageType.PROCESS_DATA_WRITE.value
	stdin: bytes = b""


# File transfer
class FileTransferMessage(Message, ABC):
	"""
	Message regarding a file transfer.

	Contains a unique file_id.
	"""

	file_id: UUID4Str = Field(default_factory=lambda: str(uuid4()))


class FileTransferErrorMessage(FileTransferMessage):
	"""
	Message reporting a file transfer related Error

	Used to transport Error object via messagebus.
	"""

	type: str = MessageType.FILE_TRANSFER_ERROR.value
	error: Error


class FileUploadRequestMessage(FileTransferMessage):
	"""
	Message for requesting a file upload

	Contains a unique file_id and the MIME content type. May contain name, size, destination directory
	and an associated terminal id.
	"""

	type: str = MessageType.FILE_UPLOAD_REQUEST.value
	content_type: str
	name: str | None = None
	size: int | None = None
	destination_dir: str | None = None
	terminal_id: str | None = None


class FileUploadResponseMessage(FileTransferMessage):
	"""
	Message to send as response to a file upload request

	Contains the local path of the file to be uploaded.
	"""

	type: str = MessageType.FILE_UPLOAD_RESPONSE.value
	path: str | None = None


class FileUploadResultMessage(FileTransferMessage):
	"""
	Message to send after file upload concluded

	Contains the path of the uploaded file.
	"""

	type: str = MessageType.FILE_UPLOAD_RESULT.value
	path: str | None = None


class FileChunkMessage(FileTransferMessage):
	"""
	Message to send a chunk of a file

	Contains the chunk number (for ordering in assembly) and the actual data as bytes.
	The last chunk of a file should contain last=True to conclude the upload.
	"""

	type: str = MessageType.FILE_CHUNK.value
	number: int
	last: bool = False
	data: bytes


MESSAGE_TYPE_TO_CLASS = {
	MessageType.GENERAL_ERROR.value: GeneralErrorMessage,
	MessageType.EVENT.value: EventMessage,
	MessageType.CHANNEL_SUBSCRIPTION_REQUEST.value: ChannelSubscriptionRequestMessage,
	MessageType.CHANNEL_SUBSCRIPTION_EVENT.value: ChannelSubscriptionEventMessage,
	MessageType.TRACE_REQUEST.value: TraceRequestMessage,
	MessageType.TRACE_RESPONSE.value: TraceResponseMessage,
	MessageType.JSONRPC_REQUEST.value: JSONRPCRequestMessage,
	MessageType.JSONRPC_RESPONSE.value: JSONRPCResponseMessage,
	MessageType.TERMINAL_ERROR.value: TerminalErrorMessage,
	MessageType.TERMINAL_OPEN_REQUEST.value: TerminalOpenRequestMessage,
	MessageType.TERMINAL_OPEN_EVENT.value: TerminalOpenEventMessage,
	MessageType.TERMINAL_DATA_READ.value: TerminalDataReadMessage,
	MessageType.TERMINAL_DATA_WRITE.value: TerminalDataWriteMessage,
	MessageType.TERMINAL_RESIZE_REQUEST.value: TerminalResizeRequestMessage,
	MessageType.TERMINAL_RESIZE_EVENT.value: TerminalResizeEventMessage,
	MessageType.TERMINAL_CLOSE_REQUEST.value: TerminalCloseRequestMessage,
	MessageType.TERMINAL_CLOSE_EVENT.value: TerminalCloseEventMessage,
	MessageType.PROCESS_ERROR.value: ProcessErrorMessage,
	MessageType.PROCESS_START_REQUEST.value: ProcessStartRequestMessage,
	MessageType.PROCESS_START_EVENT.value: ProcessStartEventMessage,
	MessageType.PROCESS_STOP_REQUEST.value: ProcessStopRequestMessage,
	MessageType.PROCESS_STOP_EVENT.value: ProcessStopEventMessage,
	MessageType.PROCESS_DATA_READ.value: ProcessDataReadMessage,
	MessageType.PROCESS_DATA_WRITE.value: ProcessDataWriteMessage,
	MessageType.FILE_TRANSFER_ERROR.value: FileTransferErrorMessage,
	"file_error": FileTransferErrorMessage,  # Legacy name
	MessageType.FILE_UPLOAD_REQUEST.value: FileUploadRequestMessage,
	MessageType.FILE_UPLOAD_RESPONSE.value: FileUploadResponseMessage,
	MessageType.FILE_UPLOAD_RESULT.value: FileUploadResultMessage,
	MessageType.FILE_CHUNK.value: FileChunkMessage,
}
