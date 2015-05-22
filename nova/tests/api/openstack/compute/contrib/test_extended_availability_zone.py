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
from nova import db
from nova.openstack.common import jsonutils
from nova import test
from nova.tests.api.openstack import fakes


UUID1 = '00000000-0000-0000-0000-000000000001'
UUID2 = '00000000-0000-0000-0000-000000000002'


def fake_compute_get(*args, **kwargs):
    return fakes.stub_instance(1, uuid=UUID1)


def fake_compute_get_all(*args, **kwargs):
    return [
        fakes.stub_instance(1, uuid=UUID1),
        fakes.stub_instance(2, uuid=UUID2),
    ]


def fake_service_get_all(context):
    return [{'host': None,
            'availability_zone': 'fake_az'}]


def fake_service_get_all_by_host(context, host):
    return [{'host': None,
            'availability_zone': 'fake_az'}]


class ExtendedAvailabilityZoneTest(test.TestCase):
    content_type = 'application/json'

    def setUp(self):
        super(ExtendedAvailabilityZoneTest, self).setUp()
        fakes.stub_out_nw_api(self.stubs)
        self.stubs.Set(compute.api.API, 'get', fake_compute_get)
        self.stubs.Set(compute.api.API, 'get_all', fake_compute_get_all)
        self.stubs.Set(db, 'service_get_all', fake_service_get_all)
        self.stubs.Set(db, 'service_get_all_by_host',
                       fake_service_get_all_by_host)

    def _make_request(self, url):
        req = webob.Request.blank(url)
        req.headers['Accept'] = self.content_type
        res = req.get_response(fakes.wsgi_app())
        return res

    def test_show(self):
        url = '/v2/fake/servers/%s' % UUID1
        res = self._make_request(url)

        self.assertEqual(res.status_int, 200)
        res_dict = jsonutils.loads(res.body)
        self.assertEqual('fake_az',
                         res_dict['server']['availability_zone'])

    def test_detail(self):
        url = '/v2/fake/servers/detail'
        res = self._make_request(url)

        self.assertEqual(res.status_int, 200)
        res_dict = jsonutils.loads(res.body)
        self.assertEqual('fake_az',
                         res_dict['servers'][0]['availability_zone'])
        self.assertEqual('fake_az',
                         res_dict['servers'][1]['availability_zone'])
