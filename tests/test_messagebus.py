# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebustypes tests
"""

import time
from typing import Type, Union

import pytest

from opsicommon.messagebus import (
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionRequestMessage,
	GeneralErrorMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageType,
	TerminalCloseEvent,
	TerminalCloseRequest,
	TerminalDataRead,
	TerminalDataWrite,
	TerminalOpenEvent,
	TerminalOpenRequest,
	TerminalResizeEvent,
	TerminalResizeRequest,
)


def test_message() -> None:
	with pytest.raises(TypeError, match="'type', 'sender', and 'channel'"):
		Message()  # type: ignore[call-arg] # pylint: disable=no-value-for-parameter
	msg = Message(type=MessageType.JSONRPC_REQUEST, sender="291b9f3e-e370-428d-be30-1248a906ae86", channel="service:config:jsonrpc")

	assert msg.type == "jsonrpc_request"
	assert abs(time.time() * 1000 - msg.created) <= 1
	assert msg.expires == 0
	assert msg.sender == "291b9f3e-e370-428d-be30-1248a906ae86"
	assert len(msg.id) == 36

	msg = Message(id="83932fac-3a6a-4a8e-aa70-4078ebfde8c1", type="custom_type", sender="291b9f3e-e370-428d-be30-1248a906ae86", channel="test")
	assert msg.type == "custom_type"
	assert msg.id == "83932fac-3a6a-4a8e-aa70-4078ebfde8c1"


def test_message_to_from_dict() -> None:
	msg1 = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
		sender="291b9f3e-e370-428d-be30-1248a906ae86",
		channel="service:config:jsonrpc",
		rpc_id="rpc1",
		method="test"
	)
	data = msg1.to_dict()
	assert isinstance(data, dict)
	msg2 = Message.from_dict(data)
	assert msg1 == msg2
	msg3 = Message.from_dict({
		"type": "jsonrpc_request",
		"sender": "*",
		"channel": "service:config:jsonrpc",
		"rpc_id": "1",
		"method": "noop"
	})
	assert isinstance(msg3, JSONRPCRequestMessage)


def test_message_to_from_msgpack() -> None:
	msg1 = JSONRPCResponseMessage(sender="291b9f3e-e370-428d-be30-1248a906ae86", channel="host:x.y.z", rpc_id="rpc1")  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
	data = msg1.to_msgpack()
	assert isinstance(data, bytes)
	msg2 = Message.from_msgpack(data)
	assert msg1 == msg2


@pytest.mark.parametrize(
	"message_class, attributes, exception",
	[
		(
			GeneralErrorMessage,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service:config:jsonrpc",
				"ref_message_id": "3cd293fd-bad8-4ff0-a7c3-610979e1dae6",
				"error": {
					"message": "general error",
					"code": 4001,
					"details": "error details"
				}
			},
			None,
		),
		(
			ChannelSubscriptionRequestMessage,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "host:aa608319-401c-467b-ae3f-0c1057490df7",
				"channels": ["channel1", "channel2"],
				"operation": "set"
			},
			None,
		),
		(
			ChannelSubscriptionEventMessage,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "host:aa608319-401c-467b-ae3f-0c1057490df7",
				"subscribed_channels": ["channel1", "channel2"]
			},
			None,
		),
		(
			JSONRPCRequestMessage,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service:config:jsonrpc",
				"rpc_id": "1",
				"method": "noop",
				"params": ("1", "2")
			},
			None,
		),
		(
			JSONRPCResponseMessage,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "host:aa608319-401c-467b-ae3f-0c1057490df7",
				"rpc_id": "1",
				"result": None,
				"error": {
					"code": 1230,
					"message": "error",
					"data": {"class": "ValueError", "details": "details"}
				}
			},
			None,
		),
		(
			TerminalCloseEvent,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "user:admin",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
			},
			None,
		),
		(
			TerminalCloseRequest,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service_worker:localhost:1",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
			},
			None,
		),
		(
			TerminalDataRead,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "user:admin",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
				"data": b"data read"
			},
			None,
		),
		(
			TerminalDataWrite,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service_worker:localhost:1",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
				"data": b"data write"
			},
			None,
		),
		(
			TerminalOpenEvent,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "user:admin",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
				"back_channel": "service_worker:localhost:1",
				"rows": 30,
				"cols": 100
			},
			None,
		),
		(
			TerminalOpenRequest,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service_node:localhost",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
				"rows": 22,
				"cols": 44
			},
			None,
		),
		(
			TerminalResizeRequest,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service_node:localhost",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
				"rows": 22,
				"cols": 44
			},
			None,
		),
		(
			TerminalResizeEvent,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "user:admin",
				"terminal_id": "26ca809d-35e3-4739-b79b-b096562b5251",
				"rows": 22,
				"cols": 44
			},
			None,
		),
	],
)
def test_message_types(
	message_class: Type[Message],
	attributes: Union[dict, None],
	exception: Union[Type[BaseException], None]
) -> None:
	attributes = attributes or {}
	if exception:
		with pytest.raises(exception):
			message_class(**attributes)
	else:
		kwargs = attributes.copy()
		msg = message_class(**kwargs)
		assert isinstance(msg, message_class)

		assert repr(msg) == f"Message(type={msg.type}, channel={msg.channel}, sender={msg.sender})"
		assert str(msg) == f"({msg.type}, {msg.channel}, {msg.sender})"

		values = msg.to_dict()
		for key, value in attributes.items():
			assert values[key] == value
