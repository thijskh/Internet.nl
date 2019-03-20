# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
#
# Configuration file for pytest-django controlling the Django configuration used when running tests.
# See: https://pytest-django.readthedocs.io/en/latest/configuring_django.html#using-django-conf-settings-configure
from django.conf import settings

def pytest_configure():
    # TODO: use sensible settings.
    settings.configure(
        CACHE_TTL=0,
        CACHE_WHOIS_TTL=0,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': 'mydatabase',
            }
        },
        ENABLE_BATCH=False,
        PUBLIC_SUFFIX_LIST_RENEWAL=0,
    )
