# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Test API Metadata base.py
"""

import json

import memcache

from nova.api.metadata import base
from nova import db
from nova import test


class BaseTest(test.TestCase):

    def setUp(self):
        super(BaseTest, self).setUp()
        self.meta_base = base
        self.flags(memcached_servers='fake_memcache_server')

    def test_update_vm_stat(self):

        def fake_fixed_ip_get_by_address(context, address):
            return {'instance_uuid': '00000000-0000-0000-0000-000000000001'}

        def fake_instance_metadata_get(context, instance_id):
            return {'HA': True}

        class fake_memcache_Client(object):
            def __init__(self, address, **kwargs):
                pass

            def set(self, key, value):
                return True

        self.stubs.Set(db, 'instance_metadata_get', fake_instance_metadata_get)
        self.stubs.Set(memcache, 'Client', fake_memcache_Client)
        self.stubs.Set(db, 'fixed_ip_get_by_address',
                       fake_fixed_ip_get_by_address)

        fake_remote_address = '1.0.0.0'
        params = 'state=1'
        result = self.meta_base.update_vm_stat(params, fake_remote_address)
        self.assertEqual('00000000-0000-0000-0000-000000000001_heart',
                         json.loads(result).keys()[0])
