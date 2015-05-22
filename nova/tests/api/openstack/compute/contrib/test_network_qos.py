# Copyright 2013 Josh Durgin
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

import mox
import webob
from webob import exc

import nova
from nova.api.openstack.compute.contrib import network_qos
from nova import context
from nova import db
from nova import exception
from nova import flags
from nova.openstack.common import jsonutils
from nova.openstack.common import timeutils
from nova import test
from nova.tests.api.openstack import fakes


FLAGS = flags.FLAGS


def fake_get_instance(self, context, instance_id):
    return({'id': instance_id, 'uuid': instance_id})


class NetworkQosTests(test.TestCase):
    def setUp(self):
        super(NetworkQosTests, self).setUp()
        self.stubs.Set(nova.compute.API, 'get', fake_get_instance)
        self.context = context.get_admin_context()
        self.controller = network_qos.NetworkQosController()

    def test_index_ok(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos')
        req.method = 'GET'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        self.mox.StubOutWithMock(nova.network.API, 'get_network_qos')

        fake_qos = {'private': {'ceil': 100, 'rate': 200, 'burst': 300},
                    'public': {'ceil': 1000, 'rate': 2000, 'burst': 3000}}

        nova.network.API.get_network_qos(self.context, mox.IsA(str)). \
                AndReturn(fake_qos)
        self.mox.ReplayAll()

        result = self.controller.index(req, '123')

        expected_result = {'network-qos': [
            {'type': 'private', 'ceil': 100, 'rate': 200, 'burst': 300},
            {'type': 'public', 'ceil': 1000, 'rate': 2000, 'burst': 3000}
        ]}
        self.assertEqual(expected_result, result)

    def test_index_not_found(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos')
        req.method = 'GET'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        self.mox.StubOutWithMock(nova.network.API, 'get_network_qos')

        fake_qos = {'private': {'ceil': 100, 'rate': 200, 'burst': 300},
                    'public': {'ceil': 1000, 'rate': 2000, 'burst': 3000}}

        nova.network.API.get_network_qos(self.context, mox.IsA(str)). \
            AndRaise(exception.NotFound())
        self.mox.ReplayAll()

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.index,
                          req, '123')

    def test_check_qos_format_ok(self):
        body = {'rate': 1, 'ceil': 2, 'burst': 3}
        expected_result = {'rate': 1, 'ceil': 2, 'burst': 3}
        result = self.controller._check_qos_format(body)
        self.assertEqual(expected_result, result)

    def test_check_qos_format_with_other_fields(self):
        body = {'rate': 1, 'other': 123, 'test': 'lala'}
        expected_result = {'rate': 1}
        result = self.controller._check_qos_format(body)
        self.assertEqual(expected_result, result)

    def test_check_qos_format_not_int(self):
        body = {'rate': '1'}
        self.assertRaises(exc.HTTPBadRequest,
                          self.controller._check_qos_format,
                          body)

        body = {'rate': 1, 'ceil': '1'}
        self.assertRaises(exc.HTTPBadRequest,
                          self.controller._check_qos_format,
                          body)

        body = {'rate': 1, 'burst': '2'}
        self.assertRaises(exc.HTTPBadRequest,
                          self.controller._check_qos_format,
                          body)

    def test_check_qos_format_without_rate(self):
        body = {'1': '1'}
        self.assertRaises(exc.HTTPBadRequest,
                          self.controller._check_qos_format,
                          body)

    def test_modify_url_error(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos/error')
        req.method = 'PUT'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        body = {'rate': 1}

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.update,
                          req, '123', 'error', body)

    def test_modify_private_qos_ok(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos/private')
        req.method = 'PUT'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        body = {'rate': 1}
        result = self.controller.update(req, '123', 'private', body)

        self.assertEqual(202, result.status_int)

    def test_modify_public_qos_ok(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos/public')
        req.method = 'PUT'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        body = {'rate': 1}
        result = self.controller.update(req, '123', 'public', body)

        self.assertEqual(202, result.status_int)

    def test_update_is_not_admin(self):
        req = webob.Request.blank(
               '/v2/{tenant_id}/servers/{server-id}/network-qos/private')
        req.method = 'PUT'
        req.headers['context-type'] = 'application/json'
        mycontext = self.context
        mycontext.is_admin = False
        req.environ['nova.context'] = mycontext

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.update,
                          req, '123', 'private', None)

    def test_update_flavor_not_found(self):
        req = webob.Request.blank(
                 '/v2/{tenant_id}/servers/{server-id}/network-qos/public')
        req.method = 'PUT'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        body = {'rate': 1, 'flavor_id': 99999999}

        #flavor_id=body.get('flavor_id',None)
        self.mox.StubOutWithMock(db, 'instance_type_get_by_flavor_id')
        db.instance_type_get_by_flavor_id(
            req.environ['nova.context'], mox.IgnoreArg()).\
            AndRaise(exception.FlavorNotFound)
        self.mox.ReplayAll()

        self.assertRaises(exc.HTTPBadRequest,
                                self.controller.update,
                                req, '123', 'public', body)

    def test_update_empty_body(self):
        req = webob.Request.blank(
             '/v2/{tenant_id}/servers/{server-id}/network-qos/public')
        req.method = 'PUT'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        body = {}

        self.assertRaises(exc.HTTPUnprocessableEntity,
                                self.controller.update,
                                req, '123', 'public', body)

    def test_update_bad_request(self):
        req = webob.Request.blank(
              '/v2/{tenant_id}/servers/{server-id}/network-qos/public')
        req.method = 'PUT'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        body = {'rate': 1}

        self.mox.StubOutWithMock(nova.network.API, 'modify_network_qos')
        nova.network.API.modify_network_qos(req.environ['nova.context'],
                               'public', mox.IsA(str), mox.IgnoreArg()).\
                               AndRaise(exception.TcInvalid)
        self.mox.ReplayAll()

        self.assertRaises(exc.HTTPBadRequest,
                                self.controller.update,
                                req, '123', 'public', body)

    def test_show_public_ok(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos')
        req.method = 'GET'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        fake_qos = {'private': {'rate': 100, 'prio': 4, 'ceil': 200},
                        'public': {'rate': 100, 'prio': 4, 'ceil': 300}}

        self.mox.StubOutWithMock(nova.network.API, 'get_network_qos')

        nova.network.API.get_network_qos(mox.IgnoreArg(), mox.IgnoreArg()).\
                AndReturn(fake_qos)
        self.mox.ReplayAll()

        result_public = self.controller.show(req, '123', 'public')

        expected_result = {'rate': 100, 'prio': 4, 'ceil': 300}
        self.assertEqual(result_public, expected_result)

    def test_show_private_ok(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos')
        req.method = 'GET'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        fake_qos = {'private': {'rate': 100, 'prio': 4, 'ceil': 200},
                        'public': {'rate': 100, 'prio': 4, 'ceil': 300}}

        self.mox.StubOutWithMock(nova.network.API, 'get_network_qos')

        nova.network.API.get_network_qos(mox.IgnoreArg(), mox.IgnoreArg()).\
                AndReturn(fake_qos)
        self.mox.ReplayAll()

        result_private = self.controller.show(req, '123', 'private')

        expected_result = {'rate': 100, 'prio': 4, 'ceil': 200}
        self.assertEqual(result_private, expected_result)

    def test_show_qos_type_error(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos')
        req.method = 'GET'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.show,
                          req, '123', 'error_qos_type')

    def test_show_not_found(self):
        req = webob.Request.blank('/v2/tid/servers/123/network-qos')
        req.method = 'GET'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        self.mox.StubOutWithMock(nova.network.API, 'get_network_qos')

        nova.network.API.get_network_qos(self.context, mox.IgnoreArg()).\
            AndRaise(exception.NotFound())
        self.mox.ReplayAll()

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.show,
                          req, '123', 'public')
