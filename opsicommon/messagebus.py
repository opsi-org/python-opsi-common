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
from typing import Any, Optional, Type, TypeVar
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
	PROCESS_EXECUTE_REQUEST = "process_execute_request"
	PROCESS_EXECUTE_RESULT = "process_execute_result"
	PROCESS_DATA_READ = "process_data_read"
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
	type: str = MessageType.GENERAL_ERROR.value
	error: Error | None


# Event
@dataclass(slots=True, kw_only=True, repr=False)
class EventMessage(Message):
	type: str = MessageType.EVENT.value
	event: str
	data: dict[str, Any] = field(default_factory=dict)


class ChannelSubscriptionOperation(str, Enum):
	SET = "set"
	ADD = "add"
	REMOVE = "remove"


@dataclass(slots=True, kw_only=True, repr=False)
class ChannelSubscriptionRequestMessage(Message):
	type: str = MessageType.CHANNEL_SUBSCRIPTION_REQUEST.value
	channels: list[str]
	operation: str = ChannelSubscriptionOperation.SET.value


@dataclass(slots=True, kw_only=True, repr=False)
class ChannelSubscriptionEventMessage(Message):
	type: str = MessageType.CHANNEL_SUBSCRIPTION_EVENT.value
	error: Error | None = None
	subscribed_channels: list[str] = field(default_factory=list)


@dataclass(slots=True, kw_only=True, repr=False)
class TraceRequestMessage(Message):
	type: str = MessageType.TRACE_REQUEST.value
	trace: dict[str, Any] = field(default_factory=dict)  # type: ignore[assignment]
	payload: bytes | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class TraceResponseMessage(Message):
	type: str = MessageType.TRACE_RESPONSE.value
	req_trace: dict[str, Any]
	trace: dict[str, Any]
	payload: bytes | None = None


# JSONRPC
@dataclass(slots=True, kw_only=True, repr=False)
class JSONRPCRequestMessage(Message):
	type: str = MessageType.JSONRPC_REQUEST.value
	api_version: str = "1"
	rpc_id: str = field(default_factory=lambda: str(uuid4()))
	method: str
	params: tuple[Any, ...] = tuple()


@dataclass(slots=True, kw_only=True, repr=False)
class JSONRPCResponseMessage(Message):
	type: str = MessageType.JSONRPC_RESPONSE.value
	rpc_id: str
	error: Any = None
	result: Any = None


# Terminal
@dataclass(slots=True, kw_only=True, repr=False)
class TerminalOpenRequestMessage(Message):
	type: str = MessageType.TERMINAL_OPEN_REQUEST.value
	terminal_id: str
	rows: Optional[int] = None
	cols: Optional[int] = None
	shell: str | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalOpenEventMessage(Message):
	type: str = MessageType.TERMINAL_OPEN_EVENT.value
	terminal_id: str
	rows: int
	cols: int
	error: Optional[Error] = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalDataReadMessage(Message):
	type: str = MessageType.TERMINAL_DATA_READ.value
	terminal_id: str
	data: bytes


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalDataWriteMessage(Message):
	type: str = MessageType.TERMINAL_DATA_WRITE.value
	terminal_id: str
	data: bytes


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalResizeRequestMessage(Message):
	type: str = MessageType.TERMINAL_RESIZE_REQUEST.value
	terminal_id: str
	rows: int
	cols: int


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalResizeEventMessage(Message):
	type: str = MessageType.TERMINAL_RESIZE_EVENT.value
	terminal_id: str
	rows: int
	cols: int
	error: Optional[Error] = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalCloseRequestMessage(Message):
	type: str = MessageType.TERMINAL_CLOSE_REQUEST.value
	terminal_id: str


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalCloseEventMessage(Message):
	type: str = MessageType.TERMINAL_CLOSE_EVENT.value
	terminal_id: str
	error: Optional[Error] = None


# ProcessExecute
@dataclass(slots=True, kw_only=True, repr=False)
class ProcessExecuteRequestMessage(Message):
	type: str = MessageType.PROCESS_EXECUTE_REQUEST.value
	process_id: str = field(default_factory=lambda: str(uuid4()))
	command: tuple[str, ...] = tuple()
	timeout: float = DEFAULT_PROCESS_EXECUTE_TIMEOUT


@dataclass(slots=True, kw_only=True, repr=False)
class ProcessExecuteResultMessage(Message):
	type: str = MessageType.PROCESS_EXECUTE_RESULT.value
	process_id: str
	exit_code: int


@dataclass(slots=True, kw_only=True, repr=False)
class ProcessDataReadMessage(Message):
	type: str = MessageType.PROCESS_DATA_READ.value
	process_id: str
	stdout: str = ""
	stderr: str = ""


# FileUpload
@dataclass(slots=True, kw_only=True, repr=False)
class FileUploadRequestMessage(Message):
	type: str = MessageType.FILE_UPLOAD_REQUEST.value
	file_id: str
	content_type: str
	name: str | None = None
	size: Optional[int] = None
	destination_dir: str | None = None
	terminal_id: str | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class FileUploadResultMessage(Message):
	type: str = MessageType.FILE_UPLOAD_RESULT.value
	file_id: str
	error: Optional[Error] = None
	path: str | None = None


@dataclass(slots=True, kw_only=True, repr=False)
class FileChunkMessage(Message):
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
	MessageType.PROCESS_EXECUTE_REQUEST.value: ProcessExecuteRequestMessage,
	MessageType.PROCESS_EXECUTE_RESULT.value: ProcessExecuteResultMessage,
	MessageType.PROCESS_DATA_READ.value: ProcessDataReadMessage,
	MessageType.FILE_UPLOAD_REQUEST.value: FileUploadRequestMessage,
	MessageType.FILE_UPLOAD_RESULT.value: FileUploadResultMessage,
	MessageType.FILE_CHUNK.value: FileChunkMessage,
}
