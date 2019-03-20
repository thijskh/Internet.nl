# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
import unbound
import socket
from checks.tasks import SetupUnboundContext
from typing import NamedTuple


MOCK_IPV4_STR = '1.2.3.4'
MOCK_IPV6_STR = 'fe80::1ff:fe23:4567:890a'
MOCK_MX_TUPLE = (50, 'open.nlnetlabs.nl')
MOCK_CAA_RESULT = [  # based on RFC-6844 examples
    (0, 'issue', b'ca.example.net; account=230123 policy=ev'),
    (0, 'iodef', b'mailto:security@example.com'),
    (0, 'iodef', b'http://iodef.example.com/'),
    (128, 'tbs', b'Unknown')
]


RR_TYPE_TLSA = 52  # TODO: replace with unbound.RR_TYPE_TLSA when available
RR_TYPE_CAA = 257  # TODO: replace with unbound.RR_TYPE_CAA when available


class MockUnboundContext:
    """
    A mock of the Unbound Python library context object, used to replace the real implementation which makes real DNS
    queries, instead providing mock responses as if they came from the Unbound Python library context.
    """
    class MockResult:
        def __init__(self, data):
            self.data = None if data is None else unbound.ub_data(data)
            self.havedata = True
            self.rcode = unbound.RCODE_NOERROR
            self.secure = False
            self.bogus = False
            self.nxdomain = False

    def _resolve_async_with_mock_responses(self, qname, cb_data, callback, qtype, qclass):
        # TODO: In Python 3.6 this could be a NamedTuple. In Python 3.7 this could be a @dataclass.
        result = None

        if qtype == unbound.RR_TYPE_A:
            result = self.create_mock_A_result()
        elif qtype == unbound.RR_TYPE_AAAA:
            result = self.create_mock_AAAA_result()
        elif qtype == unbound.RR_TYPE_MX:
            result = self.create_mock_MX_result()
        elif qtype == unbound.RR_TYPE_TXT:
            # TODO
            pass
        elif qtype == RR_TYPE_TLSA:
            # TODO
            pass
        elif qtype == RR_TYPE_CAA:
            result = self.create_mock_CAA_result()

        status = 0 if result is not None else 1
        callback(cb_data, status, result)

        return (0, 1)

    # Alias the helpfully named override method to the name expected by callers
    resolve_async = _resolve_async_with_mock_responses

    def process(self):
        return 0

    def cancel(self, async_id):
        pass

    def create_mock_A_result(self):
        return MockUnboundContext.MockResult([socket.inet_pton(socket.AF_INET, MOCK_IPV4_STR)])

    def create_mock_AAAA_result(self):
        return MockUnboundContext.MockResult([socket.inet_pton(socket.AF_INET6, MOCK_IPV6_STR)])

    def create_mock_MX_result(self):
        priority_bytes = MOCK_MX_TUPLE[0].to_bytes(
            2, byteorder='big', signed=False)
        dname_bytes = b'.' + bytes(MOCK_MX_TUPLE[1], 'us-ascii')
        return MockUnboundContext.MockResult([priority_bytes + dname_bytes])

    def create_mock_CAA_result(self):
        props = []
        for prop in MOCK_CAA_RESULT:
            flags, tag, value_bytes = prop
            tag_bytes = bytes(tag, 'us-ascii')
            caa_rdata_bytes = bytearray()
            caa_rdata_bytes += flags.to_bytes(1, byteorder='big', signed=False)
            caa_rdata_bytes += len(tag_bytes).to_bytes(1,
                                                       byteorder='big', signed=False)
            caa_rdata_bytes += tag_bytes
            caa_rdata_bytes += value_bytes
            props.append(caa_rdata_bytes)
        return MockUnboundContext.MockResult(props)


class SetupUnboundContextThatReturnsMockResponses(SetupUnboundContext):
    """A customisation of the SetupUnboundContext that responds with mock responses instead of making real DNS queries."""
    @property
    def ub_ctx(self):
        if self._ub_ctx is None:
            self._ub_ctx = MockUnboundContext()
        return self._ub_ctx


@pytest.fixture
def unbound_context():
    return SetupUnboundContextThatReturnsMockResponses()


class TestSetupUnboundContext(object):
    def test_resolve_a(self, unbound_context):
        assert unbound_context.resolve('internet.nl', unbound.RR_TYPE_A) == [
            MOCK_IPV4_STR]

    def test_resolve_aaaa(self, unbound_context):
        assert unbound_context.resolve('internet.nl', unbound.RR_TYPE_AAAA) == [
            MOCK_IPV6_STR]

    def test_resolve_mx(self, unbound_context):
        assert unbound_context.resolve('internet.nl', unbound.RR_TYPE_MX) == [
            MOCK_MX_TUPLE]

    def test_resolve_caa(self, unbound_context):
        assert unbound_context.resolve(
            'internet.nl', RR_TYPE_CAA) == MOCK_CAA_RESULT
