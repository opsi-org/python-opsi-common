# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_server
"""

import json
from unittest.mock import patch

import pytest

from opsicommon.server import _opsiconfd_get_config, get_opsiconfd_config


def test_get_opsiconfd_config() -> None:
	with patch("subprocess.run", side_effect=FileNotFoundError("File not found")):
		assert get_opsiconfd_config() == {}
		_opsiconfd_get_config.cache_clear()

		with pytest.raises(FileNotFoundError):
			get_opsiconfd_config(ignore_error=False)
		_opsiconfd_get_config.cache_clear()

	class Proc:
		stdout = """{
			"websocket_protocol": "wsproto_opsiconfd",
			"websocket_open_timeout": 30,
			"log_slow_async_callbacks": 0.05,
			"addon_dirs": [
				"/usr/lib/opsiconfd/addons",
				"/var/lib/opsiconfd/addons"
			]
		}
		"""

	config = json.loads(Proc.stdout)

	with patch("subprocess.run", return_value=Proc):
		assert get_opsiconfd_config() == config
		_opsiconfd_get_config.cache_clear()

		template = {
			"websocket_protocol": "",
			"websocket_open_timeout": 0,
			"log_level": 99,
		}
		res = get_opsiconfd_config(template=template)
		assert res["websocket_protocol"] == config["websocket_protocol"]
		assert res["websocket_open_timeout"] == config["websocket_open_timeout"]
		assert res["log_level"] == template["log_level"]
		assert "addon_dirs" not in res
		_opsiconfd_get_config.cache_clear()
