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
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar
from uuid import uuid4

from msgpack import dumps as msgpack_dumps  # type: ignore[import]
from msgpack import loads as msgpack_loads  # type: ignore[import]


def timestamp() -> int:
	return int(time() * 1000)


def message_id() -> str:
	return str(uuid4())


class MessageType(str, Enum):
	GENERAL_ERROR = "general_error"
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
	FILE_UPLOAD = "file_upload"
	FILE_UPLOAD_RESULT = "file_upload_result"
	FILE_CHUNK = "file_chunk"


@dataclass(slots=True, kw_only=True)
class Error:
	message: str
	code: Optional[int] = None
	details: Optional[str] = None


MessageT = TypeVar('MessageT', bound='Message')


@dataclass(slots=True, kw_only=True, repr=False)
class Message:
	type: str  # Custom message types are allowed
	sender: str
	channel: str
	back_channel: Optional[str] = None
	id: str = field(default_factory=message_id)  # pylint: disable=invalid-name
	created: int = field(default_factory=timestamp)
	expires: int = 0

	@classmethod
	def from_dict(cls: Type[MessageT], data: Dict[str, Any]) -> MessageT:
		_cls = cls
		if _cls is Message:
			_type = data.get("type")
			if _type:
				if isinstance(_type, MessageType):
					_type = _type.value
				_cls = MESSAGE_TYPE_TO_CLASS.get(_type, Message)
		return _cls(**data)

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)

	@classmethod
	def from_msgpack(cls: Type[MessageT], data: bytes) -> MessageT:
		return cls.from_dict(msgpack_loads(data))

	def to_msgpack(self) -> bytes:
		return msgpack_dumps(self.to_dict())

	def __repr__(self) -> str:
		return f"Message(type={self.type}, channel={self.channel}, sender={self.sender})"

	def __str__(self) -> str:
		return f"({self.type}, {self.channel}, {self.sender})"


# General
@dataclass(slots=True, kw_only=True, repr=False)
class GeneralErrorMessage(Message):
	type: str = MessageType.GENERAL_ERROR.value
	error: Optional[Error]
	ref_message_id: str


class ChannelSubscriptionOperation(str, Enum):
	SET = "set"
	ADD = "add"
	REMOVE = "remove"


@dataclass(slots=True, kw_only=True, repr=False)
class ChannelSubscriptionRequestMessage(Message):
	type: str = MessageType.CHANNEL_SUBSCRIPTION_REQUEST.value
	channels: List[str]
	operation: str = ChannelSubscriptionOperation.SET.value


@dataclass(slots=True, kw_only=True, repr=False)
class ChannelSubscriptionEventMessage(Message):
	type: str = MessageType.CHANNEL_SUBSCRIPTION_EVENT.value
	error: Optional[Error] = None
	subscribed_channels: Optional[List[str]] = None


@dataclass(slots=True, kw_only=True, repr=False)
class TraceRequestMessage(Message):
	type: str = MessageType.TRACE_REQUEST.value
	trace: Dict[str, Any]
	payload: Optional[bytes] = None


@dataclass(slots=True, kw_only=True, repr=False)
class TraceResponseMessage(Message):
	type: str = MessageType.TRACE_RESPONSE.value
	req_id: str
	req_trace: Dict[str, Any]
	trace: Dict[str, Any]
	payload: Optional[bytes] = None


# JSONRPC
@dataclass(slots=True, kw_only=True, repr=False)
class JSONRPCRequestMessage(Message):
	type: str = MessageType.JSONRPC_REQUEST.value
	api_version: str = "1"
	rpc_id: str = field(default_factory=lambda: str(uuid4()))
	method: str
	params: Optional[Tuple[Any, ...]] = tuple()


@dataclass(slots=True, kw_only=True, repr=False)
class JSONRPCResponseMessage(Message):
	type: str = MessageType.JSONRPC_RESPONSE.value
	rpc_id: str
	error: Any = None
	result: Any = None


# Terminal
@dataclass(slots=True, kw_only=True, repr=False)
class TerminalOpenRequest(Message):
	type: str = MessageType.TERMINAL_OPEN_REQUEST.value
	terminal_id: str
	rows: Optional[int] = None
	cols: Optional[int] = None
	shell: Optional[str] = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalOpenEvent(Message):
	type: str = MessageType.TERMINAL_OPEN_EVENT.value
	terminal_id: str
	rows: int
	cols: int
	error: Optional[Error] = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalDataRead(Message):
	type: str = MessageType.TERMINAL_DATA_READ.value
	terminal_id: str
	data: bytes


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalDataWrite(Message):
	type: str = MessageType.TERMINAL_DATA_WRITE.value
	terminal_id: str
	data: bytes


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalResizeRequest(Message):
	type: str = MessageType.TERMINAL_RESIZE_REQUEST.value
	terminal_id: str
	rows: int
	cols: int


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalResizeEvent(Message):
	type: str = MessageType.TERMINAL_RESIZE_EVENT.value
	terminal_id: str
	rows: int
	cols: int
	error: Optional[Error] = None


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalCloseRequest(Message):
	type: str = MessageType.TERMINAL_CLOSE_REQUEST.value
	terminal_id: str


@dataclass(slots=True, kw_only=True, repr=False)
class TerminalCloseEvent(Message):
	type: str = MessageType.TERMINAL_CLOSE_EVENT.value
	terminal_id: str


# FileUpload
@dataclass(slots=True, kw_only=True, repr=False)
class FileUploadMessage(Message):
	type: str = MessageType.FILE_UPLOAD.value
	file_id: str
	content_type: str
	name: Optional[str] = None
	size: Optional[int] = None


@dataclass(slots=True, kw_only=True, repr=False)
class FileUploadResultMessage(Message):
	type: str = MessageType.FILE_UPLOAD_RESULT.value
	file_id: str
	error: Optional[Error] = None
	path: Optional[str] = None


@dataclass(slots=True, kw_only=True, repr=False)
class FileChunk(Message):
	type: str = MessageType.FILE_CHUNK.value
	file_id: str
	number: int
	last: bool = False
	data: bytes


MESSAGE_TYPE_TO_CLASS = {
	MessageType.GENERAL_ERROR.value: GeneralErrorMessage,
	MessageType.CHANNEL_SUBSCRIPTION_REQUEST.value: ChannelSubscriptionRequestMessage,
	MessageType.CHANNEL_SUBSCRIPTION_EVENT.value: ChannelSubscriptionEventMessage,
	MessageType.TRACE_REQUEST.value: TraceRequestMessage,
	MessageType.TRACE_RESPONSE.value: TraceResponseMessage,
	MessageType.JSONRPC_REQUEST.value: JSONRPCRequestMessage,
	MessageType.JSONRPC_RESPONSE.value: JSONRPCResponseMessage,
	MessageType.TERMINAL_OPEN_REQUEST.value: TerminalOpenRequest,
	MessageType.TERMINAL_OPEN_EVENT.value: TerminalOpenEvent,
	MessageType.TERMINAL_DATA_READ.value: TerminalDataRead,
	MessageType.TERMINAL_DATA_WRITE.value: TerminalDataWrite,
	MessageType.TERMINAL_RESIZE_REQUEST.value: TerminalResizeRequest,
	MessageType.TERMINAL_RESIZE_EVENT.value: TerminalResizeEvent,
	MessageType.TERMINAL_CLOSE_REQUEST.value: TerminalCloseRequest,
	MessageType.TERMINAL_CLOSE_EVENT.value: TerminalCloseEvent,
	MessageType.FILE_UPLOAD.value: FileUploadMessage,
	MessageType.FILE_UPLOAD_RESULT.value: FileUploadResultMessage,
	MessageType.FILE_CHUNK.value: FileChunk,
}
