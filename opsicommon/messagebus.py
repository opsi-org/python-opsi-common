# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsicommon.messagebus
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from time import time
from typing import Any, Type, TypeVar
from uuid import uuid4

import msgspec

message_decoder = msgspec.msgpack.Decoder()
message_encoder = msgspec.msgpack.Encoder()


def timestamp() -> int:
	return int(time() * 1000)


def message_id() -> str:
	return str(uuid4())


class MessageType(str, Enum):
	GENERAL_ERROR = "general_error"
	EVENT = "event"
	CHANNEL_SUBSCRIPTION_REQUEST = "channel_subscription_request"
	CHANNEL_SUBSCRIPTION_EVENT = "channel_subscription_event"
	TRACE_REQUEST = "trace_request"
	TRACE_RESPONSE = "trace_response"
	JSONRPC_REQUEST = "jsonrpc_request"
	JSONRPC_RESPONSE = "jsonrpc_response"
	TERMINAL_OPEN_REQUEST = "terminal_open_request"
	TERMINAL_OPEN_EVENT = "terminal_open_event"
	TERMINAL_RESIZE_REQUEST = "terminal_resize_request"
	TERMINAL_RESIZE_EVENT = "terminal_resize_event"
	TERMINAL_DATA_READ = "terminal_data_read"
	TERMINAL_DATA_WRITE = "terminal_data_write"
	TERMINAL_CLOSE_REQUEST = "terminal_close_request"
	TERMINAL_CLOSE_EVENT = "terminal_close_event"
	PROCESS_START_REQUEST = "process_start_request"
	PROCESS_START_EVENT = "process_start_event"
	PROCESS_STOP_REQUEST = "process_stop_request"
	PROCESS_STOP_EVENT = "process_stop_event"
	PROCESS_DATA_READ = "process_data_read"
	PROCESS_DATA_WRITE = "process_data_write"
	FILE_UPLOAD_REQUEST = "file_upload_request"
	FILE_UPLOAD_RESULT = "file_upload_result"
	FILE_CHUNK = "file_chunk"


@dataclass(slots=True, kw_only=True)
class Error:
	message: str
	code: int | None = None
	details: str | None = None


MessageT = TypeVar("MessageT", bound="Message")
DEFAULT_PROCESS_EXECUTE_TIMEOUT = 60.0  # Seconds until process should be interrupted


@dataclass(slots=True, kw_only=True, repr=False)
class Message:  # pylint: disable=too-many-instance-attributes
	type: str  # Custom message types are allowed
	sender: str
	channel: str
	back_channel: str | None = None
	id: str = field(default_factory=message_id)  # pylint: disable=invalid-name
	created: int = field(default_factory=timestamp)
	expires: int = field(default_factory=lambda: timestamp() + 60000)
	ref_id: str | None = None

	@classmethod
	def from_dict(cls: Type[MessageT], data: dict[str, Any]) -> MessageT:
		_cls = cls
		if _cls is Message:
			_type = data.get("type")
			if _type:
				if isinstance(_type, MessageType):
					_type = _type.value
				_cls = MESSAGE_TYPE_TO_CLASS.get(_type, Message)
		return _cls(**data)

	def to_dict(self, none_values: bool = False) -> dict[str, Any]:
		_dict = asdict(self)
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
@dataclass(slots=True, kw_only=True, repr=False)
class GeneralErrorMessage(Message):
	"""
	Base Class for Error Messages

	Used to transport Error object via messagebus
	"""

	type: str = MessageType.GENERAL_ERROR.value
	error: Error | None


# Event
@dataclass(slots=True, kw_only=True, repr=False)
class EventMessage(Message):
	"""
	Class for Event Messages

	Used to notify messagebus of an event that occured.
	"""

	type: str = MessageType.EVENT.value
	event: str
	data: dict[str, Any] = field(default_factory=dict)


class ChannelSubscriptionOperation(str, Enum):
	SET = "set"
	ADD = "add"
	REMOVE = "remove"


@dataclass(slots=True, kw_only=True, repr=False)
class ChannelSubscriptionRequestMessage(Message):
	"""
	Message for requesting channel access

	Can be used to set, add or remove subscribed channels.
	"""

	type: str = MessageType.CHANNEL_SUBSCRIPTION_REQUEST.value
	channels: list[str]
	operation: str = ChannelSubscriptionOperation.SET.value


@dataclass(slots=True, kw_only=True, repr=False)
class ChannelSubscriptionEventMessage(Message):
	"""
	Message for confirming channel access

	Is response to ChannelSubscriptionRequestMessage and contains total subscribed_channels or error.
	"""

	type: str = MessageType.CHANNEL_SUBSCRIPTION_EVENT.value
	error: Error | None = None
	subscribed_channels: list[str] = field(default_factory=list)


@dataclass(slots=True, kw_only=True, repr=False)
class TraceRequestMessage(Message):
	"""
	Message for tracing transmission times

	It contains trace data (timestamp of sending).
	"""

	type: str = MessageType.TRACE_REQUEST.value
	trace: dict[str, Any] = field(default_factory=dict)  # type: ignore[assignment]
	payload: bytes | None = None


@dataclass(slots=True, kw_only=True, repr=False)
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
@dataclass(slots=True, kw_only=True, repr=False)
class JSONRPCRequestMessage(Message):
	"""
	Message for triggering an rpc

	Requests the execution of an rpc with given parameters on receiving end.
	"""

	type: str = MessageType.JSONRPC_REQUEST.value
	api_version: str = "1"
	rpc_id: str = field(default_factory=lambda: str(uuid4()))
	method: str
	params: tuple[Any, ...] = tuple()


@dataclass(slots=True, kw_only=True, repr=False)
class JSONRPCResponseMessage(Message):
	"""
	Message for transmitting result of rpc

	Is response to JSONRPCRequestMessage and contains either result or an error.
	rpc_id matches the one specified in the corresponding JSONRPCRequestMessage.
	"""

	type: str = MessageType.JSONRPC_RESPONSE.value
	rpc_id: str
	error: Any = None
	result: Any = None


# Terminal
@dataclass(slots=True, kw_only=True, repr=False)
class TerminalOpenRequestMessage(Message):
	"""
	Message requesting to open a terminal

	Shell and number of rows and columns can be specified.
	terminal_id is used as an identifier. If a terminal with that id already exists,
	access to this terminal may be granted resulting in shared access to it.
	"""

	type: str = MessageType.TERMINAL_OPEN_REQUEST.value
	terminal_id: str
	rows: int | None = None
	cols: int | None = None
	shell: str | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalOpenEventMessage(Message):
	"""
	Message to respond to TerminalOpenRequestMessage

	Contains number of rows and columns. May contain error.
	"""

	type: str = MessageType.TERMINAL_OPEN_EVENT.value
	terminal_id: str
	rows: int
	cols: int
	error: Error | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalDataReadMessage(Message):
	"""
	Message transmitting terminal output data

	Terminal output data is contained as bytes.
	"""

	type: str = MessageType.TERMINAL_DATA_READ.value
	terminal_id: str
	data: bytes


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalDataWriteMessage(Message):
	"""
	Message transmitting terminal input data

	Terminal input data (stdin) is contained as bytes.
	"""

	type: str = MessageType.TERMINAL_DATA_WRITE.value
	terminal_id: str
	data: bytes


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalResizeRequestMessage(Message):
	"""
	Message requesting to resize an open terminal

	Contains new number of rows and columns for an already open terminal.
	"""

	type: str = MessageType.TERMINAL_RESIZE_REQUEST.value
	terminal_id: str
	rows: int
	cols: int


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalResizeEventMessage(Message):
	"""
	Message to respond to TerminalResizeRequestMessage

	Contains new number of rows and columns. May contain error.
	"""

	type: str = MessageType.TERMINAL_RESIZE_EVENT.value
	terminal_id: str
	rows: int
	cols: int
	error: Error | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalCloseRequestMessage(Message):
	"""
	Message to request a terminal to be closed

	Contains terminal_id for open termial to be closed.
	"""

	type: str = MessageType.TERMINAL_CLOSE_REQUEST.value
	terminal_id: str


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalCloseEventMessage(Message):
	"""
	Message to respond to TerminalCloseRequestMessage

	May contain error.
	"""

	type: str = MessageType.TERMINAL_CLOSE_EVENT.value
	terminal_id: str
	error: Error | None = None


# ProcessExecute
@dataclass(slots=True, kw_only=True, repr=False)
class ProcessStartRequestMessage(Message):
	"""
	Message requesting to start a process

	Contains a unique process_id and the command to execute as tuple. Optional timeout.
	"""

	type: str = MessageType.PROCESS_START_REQUEST.value
	process_id: str = field(default_factory=lambda: str(uuid4()))
	command: tuple[str, ...] = tuple()
	timeout: float = DEFAULT_PROCESS_EXECUTE_TIMEOUT


@dataclass(slots=True, kw_only=True, repr=False)
class ProcessStartEventMessage(Message):
	"""
	Message to respond to ProcessStartRequestMessage

	Contains the local process id. May contain error.
	"""

	type: str = MessageType.PROCESS_START_EVENT.value
	process_id: str = field(default_factory=lambda: str(uuid4()))
	local_process_id: int
	error: Error | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class ProcessStopRequestMessage(Message):
	"""
	Message requesting to stop a running process

	Contains the local process id.
	"""

	type: str = MessageType.PROCESS_STOP_REQUEST.value
	process_id: str


@dataclass(slots=True, kw_only=True, repr=False)
class ProcessStopEventMessage(Message):
	"""
	Message to respond to ProcessStopRequestMessage

	Contains the exit code of the process. May contain error.
	"""

	type: str = MessageType.PROCESS_STOP_EVENT.value
	process_id: str
	exit_code: int
	error: Error | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class ProcessDataReadMessage(Message):
	"""
	Message transmitting process output data

	Process stdout and stderr output data is contained as bytes.
	"""

	type: str = MessageType.PROCESS_DATA_READ.value
	process_id: str
	stdout: bytes = b""
	stderr: bytes = b""


@dataclass(slots=True, kw_only=True, repr=False)
class ProcessDataWriteMessage(Message):
	"""
	Message transmitting process input data

	Process input data (stdin) is contained as bytes.
	"""

	type: str = MessageType.PROCESS_DATA_WRITE.value
	process_id: str
	stdin: bytes = b""


# FileUpload
@dataclass(slots=True, kw_only=True, repr=False)
class FileUploadRequestMessage(Message):
	"""
	Message for requesting a file upload

	Contains a unique file_id and the MIME content type. May contain name, size, destination directory
	and an associated terminal id.
	"""

	type: str = MessageType.FILE_UPLOAD_REQUEST.value
	file_id: str
	content_type: str
	name: str | None = None
	size: int | None = None
	destination_dir: str | None = None
	terminal_id: str | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class FileUploadResultMessage(Message):
	"""
	Message to send after file upload concluded

	May contain the path of the uploaded file or an error.
	"""

	type: str = MessageType.FILE_UPLOAD_RESULT.value
	file_id: str
	error: Error | None = None
	path: str | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class FileChunkMessage(Message):
	"""
	Message to send a chunk of a file

	Contains the chunk number (for ordering in assembly) and the actual data as bytes.
	The last chunk of a file should contain last=True to conclude the upload.
	"""

	type: str = MessageType.FILE_CHUNK.value
	file_id: str
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
	MessageType.TERMINAL_OPEN_REQUEST.value: TerminalOpenRequestMessage,
	MessageType.TERMINAL_OPEN_EVENT.value: TerminalOpenEventMessage,
	MessageType.TERMINAL_DATA_READ.value: TerminalDataReadMessage,
	MessageType.TERMINAL_DATA_WRITE.value: TerminalDataWriteMessage,
	MessageType.TERMINAL_RESIZE_REQUEST.value: TerminalResizeRequestMessage,
	MessageType.TERMINAL_RESIZE_EVENT.value: TerminalResizeEventMessage,
	MessageType.TERMINAL_CLOSE_REQUEST.value: TerminalCloseRequestMessage,
	MessageType.TERMINAL_CLOSE_EVENT.value: TerminalCloseEventMessage,
	MessageType.PROCESS_START_REQUEST.value: ProcessStartRequestMessage,
	MessageType.PROCESS_START_EVENT.value: ProcessStartEventMessage,
	MessageType.PROCESS_STOP_REQUEST.value: ProcessStopRequestMessage,
	MessageType.PROCESS_STOP_EVENT.value: ProcessStopEventMessage,
	MessageType.PROCESS_DATA_READ.value: ProcessDataReadMessage,
	MessageType.PROCESS_DATA_WRITE.value: ProcessDataWriteMessage,
	MessageType.FILE_UPLOAD_REQUEST.value: FileUploadRequestMessage,
	MessageType.FILE_UPLOAD_RESULT.value: FileUploadResultMessage,
	MessageType.FILE_CHUNK.value: FileChunkMessage,
}
