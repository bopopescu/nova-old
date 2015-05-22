# Copyright 2011 OpenStack LLC.
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

import webob

from nova import compute
from nova.openstack.common import jsonutils
from nova import test
from nova.tests.api.openstack import fakes


def fake_describe_availability_zones(self, context, **kwargs):
    return {'availability_zones': [
                {
                    'zoneName': 'fake_ava',
                    'zoneState': 'available'
                },
                {
                    'zoneName': 'fake_not',
                    'zoneState': 'not available'
                }
            ]}


class AvailabilityZonesTest(test.TestCase):
    content_type = 'application/json'

    def setUp(self):
        super(AvailabilityZonesTest, self).setUp()
        self.stubs.Set(compute.api.API,
                       'describe_availability_zones',
                       fake_describe_availability_zones)

    def _make_request(self, url):
        req = webob.Request.blank(url)
        req.headers['Accept'] = self.content_type
        res = req.get_response(fakes.wsgi_app())
        return res

    def test_index(self):
        url = '/v2/fake/availability-zones'
        res = self._make_request(url)

        self.assertEqual(res.status_int, 200)
        res_dict = jsonutils.loads(res.body)
        self.assertEqual('available',
                         res_dict['availability_zones'][0]['zoneState'])
        self.assertEqual('not available',
                         res_dict['availability_zones'][1]['zoneState'])
