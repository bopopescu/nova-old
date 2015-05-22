# Copyright 2012 Netease
# All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import datetime

import webob

from nova.api.openstack import compute as compute_api
from nova.api.openstack.compute.contrib import action_failover
from nova import compute
from nova.compute import vm_states
from nova import context
from nova import exception
from nova import flags
from nova.openstack.common import jsonutils
from nova.scheduler import rpcapi as scheduler_rpcapi
from nova import test
from nova.tests.api.openstack import fakes
from nova import utils


FLAGS = flags.FLAGS


class FailoverActionTest(test.TestCase):
    def setUp(self):
        super(FailoverActionTest, self).setUp()

        self.exists = True
        self.kwargs = None
        self.uuid = utils.gen_uuid()

        def fake_get(inst, context, instance_id):
            if self.exists:
                return dict(id=1, uuid=instance_id, vm_state=vm_states.ACTIVE)
            raise exception.InstanceNotFound()

        def fake_update(inst, context, instance, **kwargs):
            self.kwargs = kwargs

        self.stubs.Set(compute.API, 'get', fake_get)
        self.stubs.Set(compute.API, 'update', fake_update)
        self.api = action_failover.FailoverActionController()

        url = '/fake/servers/%s/action' % self.uuid
        self.request = fakes.HTTPRequest.blank(url)

    def test_no_body(self):
        body = {}
        result = self.api._failover(self.request, 'inst_id', body)
        self.assertEqual(result.status_int, 202)

    def test_no_method(self):
        body = {'failover': None}
        result = self.api._failover(self.request, 'inst_id', body)
        self.assertEqual(result.status_int, 202)

    def test_right_method(self):
        body = {'failover': 'reboot'}
        result = self.api._failover(self.request, 'inst_id', body)
        self.assertEqual(result.status_int, 202)

        body = {'failover': 'rebuild'}
        result = self.api._failover(self.request, 'inst_id', body)
        self.assertEqual(result.status_int, 202)

        body = {'failover': 'move'}
        result = self.api._failover(self.request, 'inst_id', body)
        self.assertEqual(result.status_int, 202)

    def test_bad_method(self):
        body = {'failover': 'bad'}
        self.assertRaises(webob.exc.HTTPBadRequest, self.api._failover,
                          self.request, 'inst_id', body)
