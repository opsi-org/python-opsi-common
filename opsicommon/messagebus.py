# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsicommon.messagebus
"""

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Type, TypeVar, Union
from uuid import uuid4

from msgpack import dumps as msgpack_dumps  # type: ignore[import]
from msgpack import loads as msgpack_loads  # type: ignore[import]


class MessageType(str, Enum):
	JSONRPC_REQUEST = "jsonrpc_request"
	JSONRPC_RESPONSE = "jsonrpc_response"
	FILE_UPLOAD = "file_upload"
	FILE_UPLOAD_RESULT = "file_upload_result"
	FILE_CHUNK = "file_chunk"


@dataclass(slots=True, kw_only=True)
class Error:
	message: str
	code: Union[int, None] = None
	details: Union[str, None] = None


MessageT = TypeVar('MessageT', bound='Message')


@dataclass(slots=True, kw_only=True)
class Message:
	type: str  # Custom message types are allowed
	sender: str
	channel: str
	id: str = field(default_factory=lambda: str(uuid4()))  # pylint: disable=invalid-name
	created: int = field(default_factory=lambda: int(time.time() * 1000))
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
		return f"Message(type={self.type},id={self.id})"

	def __str__(self) -> str:
		return f"({self.type},{self.id})"


@dataclass(slots=True, kw_only=True)
class JSONRPCRequestMessage(Message):

	type: str = MessageType.JSONRPC_REQUEST.value
	api_version: str = "1"
	rpc_id: str = field(default_factory=lambda: str(uuid4()))
	method: str
	params: Optional[Tuple[Any, ...]] = tuple()


@dataclass(slots=True, kw_only=True)
class JSONRPCResponseMessage(Message):
	type: str = MessageType.JSONRPC_RESPONSE.value
	rpc_id: str
	error: Any = None
	result: Any = None


@dataclass(slots=True, kw_only=True)
class FileUploadMessage(Message):
	type: str = MessageType.FILE_UPLOAD.value
	file_id: str
	content_type: str
	name: Optional[str] = None
	size: Optional[int] = None


@dataclass(slots=True, kw_only=True)
class FileUploadResultMessage(Message):
	type: str = MessageType.FILE_UPLOAD_RESULT.value
	file_id: str
	error: Optional[Error] = None
	path: Optional[str] = None


@dataclass(slots=True, kw_only=True)
class FileChunk(Message):
	type: str = MessageType.FILE_CHUNK.value
	file_id: str
	number: int
	last: bool = False
	data: bytes


MESSAGE_TYPE_TO_CLASS = {
	MessageType.JSONRPC_REQUEST.value: JSONRPCRequestMessage,
	MessageType.JSONRPC_RESPONSE.value: JSONRPCResponseMessage,
	MessageType.FILE_UPLOAD.value: FileUploadMessage,
	MessageType.FILE_UPLOAD_RESULT.value: FileUploadResultMessage,
	MessageType.FILE_CHUNK.value: FileChunk,
}
