# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
from checks.tasks import RFC6844CAARDataParser


def mock_libunbound_caa_raw_data(flags: int, tag: bytes, value: bytes):
    return bytearray([flags, len(tag)]) + bytearray(tag) + bytearray(value)


def test_simple_issue():
    RFC6844CAARDataParser.as_caa_list(
        [mock_libunbound_caa_raw_data(0, b'issue', b'letsencrypt.org')])


def test_rfc6844_insufficient_tag_length():
    with pytest.raises(ValueError):
        RFC6844CAARDataParser.as_caa_list(
            [mock_libunbound_caa_raw_data(0, b'', b'n/a')])


def test_rfc6844_min_permitted_tag_length():
    RFC6844CAARDataParser.as_caa_list(
        [mock_libunbound_caa_raw_data(0, b'0'*1, b'n/a')])


def test_rfc6844_max_permitted_tag_length():
    RFC6844CAARDataParser.as_caa_list(
        [mock_libunbound_caa_raw_data(0, b'0'*15, b'n/a')])


def test_rfc6844_excessive_tag_length():
    with pytest.raises(ValueError):
        RFC6844CAARDataParser.as_caa_list(
            [mock_libunbound_caa_raw_data(0, b'0'*16, b'n/a')])
