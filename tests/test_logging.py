# -*- coding: utf-8 -*-
"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
"""

import io
import pytest
import logging

from opsicommon.logging import logger

@pytest.fixture
def log_stream_handler():
	stream = io.StringIO()
	handler = logging.StreamHandler(stream)
	return (handler, stream)

def test_levels(log_stream_handler):
	(handler, stream) = log_stream_handler
	logger.addHandler(handler)
	handler.setLevel(logging.SECRET)
	logger.setLevel(logging.SECRET)

	expected = ""
	for level in (
		"secret", "confidential", "trace", "debug2", "debug",
		"info", "notice", "warning", "error", "critical", "comment"
	):
		func = getattr(logger, level)
		msg = f"logline {level}"
		func(msg)
		expected += f"{msg}\n"
	
	stream.seek(0)
	assert stream.read() == expected

#with pytest.raises(SectionNotFoundException):
#	config.get('nothing', 'bla')
