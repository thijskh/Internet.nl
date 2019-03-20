# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
#
# Types and methods for DNS Certification Authority Authorization (CAA) Resource Record support.
# See: https://tools.ietf.org/html/rfc6844
from io import BytesIO
from typing import BinaryIO


CAA_TAG_LEN_MIN = 1
CAA_TAG_LEN_MAX = 15


"""
Unbound Python library style helper for Certificate Authority Authorization DNS RDATA parsing, until such time as
the Unbound Python library itself offers an 'as_caa_list' method. This parser makes no attempt to parse CAA tag
values but instead returns them unmodified. For details of the binary format see: https://tools.ietf.org/html/rfc6844#section-5.1
"""
class RFC6844CAARDataParser:
    """
    Parse RDATA bytes for a set of CAA RRs and return per RR the three major fields: flags, tag and value.

    :param data: list of byte arrays, each element being RDATA for a single CAA RR
    :returns: list of tuples (flags: int, tag: str, value: bytes)
    """
    @staticmethod
    def as_caa_list(data):
        return [RFC6844CAARDataParser._parse_rdf(rdf) for rdf in data]

    @staticmethod
    def _read_unsigned_byte(bytestream: BinaryIO):
        return int.from_bytes(bytestream.read(1), byteorder='big', signed=False)

    @staticmethod
    def _parse_rdf(rdf):
        # TODO: Use a parser generated from the ABNF grammar defined in RFC 6844?
        # TODO: Catch streaming exceptions and wrap them in a more friendly exception such as ValueError?
        # TODO: How to handle RFC-noncompliance? E.g. excessive tag length, flags other than the critical flag set, tag
        # consisting of non-US ASCII characters, 'iodef' tag URL of scheme other than mailto, http or https, or a non-empty
        # non-domain for an 'issue' tag? Should these things be flagged up to the end user?
        byte_stream = rdf if rdf is BinaryIO else BytesIO(
            rdf)

        # CAA RDATA (single rdferty) byte layout from RFC-6844 section 5.1:
        # +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
        # | Flags          | Tag Length = n |
        # +----------------+----------------+...+---------------+
        # | Tag char 0     | Tag char 1     |...| Tag char n-1  |
        # +----------------+----------------+...+---------------+
        # +----------------+----------------+.....+----------------+
        # | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
        # +----------------+----------------+.....+----------------+
        flags = RFC6844CAARDataParser._read_unsigned_byte(byte_stream)
        tag_length = RFC6844CAARDataParser._read_unsigned_byte(byte_stream)

        if tag_length not in range(CAA_TAG_LEN_MIN, CAA_TAG_LEN_MAX + 1):
            raise ValueError("RFC-6844 CAA tag length {} MUST be >= {} AND <= {}".format(
                tag_length, CAA_TAG_LEN_MIN, CAA_TAG_LEN_MAX))

        try:
            tag = byte_stream.read(tag_length).decode(encoding='us-ascii', errors='strict')
        except UnicodeDecodeError:
            raise ValueError("RFC-6844 CAA tag MUST only contain US-ASCII characters")

        return (flags, tag, byte_stream.read())
