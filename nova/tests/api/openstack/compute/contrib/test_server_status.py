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

import datetime

import memcache
import webob

from nova import compute
from nova import db
from nova.openstack.common import jsonutils
from nova import test
from nova.tests.api.openstack import fakes


UUID = '00000000-0000-0000-0000-000000000001'

UUID1 = '00000000-0000-0000-0000-000000000001'
UUID2 = '00000000-0000-0000-0000-000000000002'
UUID3 = '00000000-0000-0000-0000-000000000003'


def fake_compute_get(*args, **kwargs):
    return fakes.stub_instance(1, uuid=UUID3)


def fake_compute_get_all(*args, **kwargs):
    return [fakes.stub_instance(1, uuid=UUID1),
            fakes.stub_instance(2, uuid=UUID2)]


class fake_memcache_Client(object):
    def __init__(self, address, **kwargs):
        pass

    def get(self, key):
        key = key.rstrip('_heart')
        if key in [UUID, UUID1, UUID2, UUID3]:
            return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')


def fake_instance_get_by_uuid(context, instance_id):
    return {'HA': True,
            'name': 'fake-instance-name',
            'uuid': UUID}


class ServerStatusTest(test.TestCase):
    content_type = 'application/json'

    def setUp(self):
        super(ServerStatusTest, self).setUp()
        self.stubs.Set(db, 'instance_get_by_uuid', fake_instance_get_by_uuid)
        self.stubs.Set(memcache, 'Client', fake_memcache_Client)

    def _make_request(self, url):
        req = webob.Request.blank(url)
        req.headers['Accept'] = self.content_type
        res = req.get_response(fakes.wsgi_app())
        return res

    def test_show_up(self):
        self.flags(memcached_servers='fake_memcache_server')
        url = '/v2/fake/os-server-status/%s' % UUID
        res = self._make_request(url)

        self.assertEqual(res.status_int, 200)
        res_dict = jsonutils.loads(res.body)
        expect_result = {'instance_uuid': UUID,
                         'status': 'up'}
        self.assertEqual(expect_result,
                         res_dict)

    def test_show_500(self):
        self.flags(memcached_servers=None)
        url = '/v2/fake/os-server-status/%s' % UUID
        res = self._make_request(url)
        self.assertEqual(res.status_int, 500)


class TestExtendServerStatus(test.TestCase):
    def setUp(self):
        super(TestExtendServerStatus, self).setUp()
        self.stubs.Set(compute.api.API, 'get', fake_compute_get)
        self.stubs.Set(compute.api.API, 'get_all', fake_compute_get_all)

    def _make_request(self, url):
        req = webob.Request.blank(url)
        req.headers['Accept'] = 'application/json'
        res = req.get_response(fakes.wsgi_app())
        return res

    def test_extend_show_no_memcache(self):
        url = '/v2/fake/servers/%s' % UUID1
        res = jsonutils.loads(self._make_request(url).body)
        self.assertEqual('unknown', res['server']['os-server-status'])

    def test_extend_show_return_up(self):
        # NOTE(gtt): If not set the config item, fake_memcache_client will
        # NOT work.
        self.flags(memcached_servers=['fakeserver'])
        self.stubs.Set(memcache, 'Client', fake_memcache_Client)
        url = '/v2/fake/servers/%s' % UUID1
        res = jsonutils.loads(self._make_request(url).body)
        self.assertEqual('up', res['server']['os-server-status'])

    def test_extend_detail_no_memcache(self):
        url = '/v2/fake/servers/detail'
        res = jsonutils.loads(self._make_request(url).body)
        for server in res['servers']:
            self.assertEqual('unknown', server['os-server-status'])

    def test_extend_detail_return_up(self):
        # NOTE(gtt): If not set the config item, fake_memcache_client will
        # NOT work.
        self.flags(memcached_servers=['fakeserver'])
        self.stubs.Set(memcache, 'Client', fake_memcache_Client)

        url = '/v2/fake/servers/detail'
        res = jsonutils.loads(self._make_request(url).body)
        for server in res['servers']:
            self.assertEqual('up', server['os-server-status'])
