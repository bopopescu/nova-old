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
from dateutil import tz
import webob

from nosclient import operate_private_key as nos_api
from nova.api.openstack.compute.contrib import extended_keypairs
from nova.api.openstack.compute.contrib import keypairs
from nova.compute import api as compute_api
from nova import db
from nova import exception
from nova import flags
from nova.openstack.common import jsonutils
from nova import test
from nova.tests.api.openstack import fakes


FLAGS = flags.FLAGS


def fake_db_key_pair_get(context, user_id, name):
    return {'name': 'foo', 'public_key': 'XXX', 'fingerprint': 'YYY.create',
            'created_at': datetime.datetime(2011, 11, 19, 2, 39, 1)}


def fake_db_key_pair_get_all_by_user(context, user_id):
    return [{'name': 'foo', 'public_key': 'XXX', 'fingerprint': 'YYY.create',
             'created_at': datetime.datetime(2011, 11, 19, 2, 39, 1)}]


def fake_db_key_pair_destroy(context, user_id, name):
    if not (user_id and name):
        raise Exception()


def fake_key_pair_update_fingerprint(context, user_id, name, fingerprint):
    return fingerprint


class ExtendedKeypairsTest(test.TestCase):

    def setUp(self):
        super(ExtendedKeypairsTest, self).setUp()
        self.stubs.Set(db, "key_pair_destroy", fake_db_key_pair_destroy)
        self.stubs.Set(db, "key_pair_get", fake_db_key_pair_get)
        self.stubs.Set(db, "key_pair_get_all_by_user",
                       fake_db_key_pair_get_all_by_user)
        self.stubs.Set(db, "key_pair_update_fingerprint",
                       fake_key_pair_update_fingerprint)

        self._keypair_nos_call_stubs()

    def _keypair_nos_call_stubs(self):

        def fake_nos_check_bucket_exist(self, bucket_name):
            return False

        def fake_nos_create_bucket(self, bucket_name):
            pass

        def fake_nos_upload_private_key(self, bucket_name, private_key_name,
                                    private_key_content, expires, use_domain):
            return 'http://fake_url'

        def fake_nos_check_object_exist(self, bucket_name, private_key_name):
            return True

        def fake_nos_delete_private_key(self, bucket_name, private_key_name):
            pass

        def fake_nos_get_object_url(self, buckey_name,
                                    private_key_name, expires, use_domain):
            return 'http://fake_url'

        self.stubs.Set(nos_api.OperatePrivateKey, "check_bucket_exist",
                       fake_nos_check_bucket_exist)
        self.stubs.Set(nos_api.OperatePrivateKey, "create_bucket",
                       fake_nos_create_bucket)
        self.stubs.Set(nos_api.OperatePrivateKey, "upload_private_key",
                       fake_nos_upload_private_key)
        self.stubs.Set(nos_api.OperatePrivateKey, "check_object_exist",
                       fake_nos_check_object_exist)
        self.stubs.Set(nos_api.OperatePrivateKey, "delete_private_key",
                       fake_nos_delete_private_key)
        self.stubs.Set(nos_api.OperatePrivateKey, "get_object_url",
                       fake_nos_get_object_url)

    def test_create(self):

        def fake_keypair_create(self, req, body):
            return {'keypair': {'name': 'foo',
                                'user_id': 'fake_id',
                                'public_key': 'XXX',
                                'fingerprint': 'YYY',
                                'private_key': 'KKK'}}

        self.stubs.Set(keypairs.KeypairController, "create",
                       fake_keypair_create)

        body = {'keypair': {'name': 'foo'}}
        req = webob.Request.blank('/v2/fake/os-keypairs')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['Content-Type'] = 'application/json'
        res = req.get_response(fakes.wsgi_app())
        self.assertEqual(res.status_int, 200)
        res_dict = jsonutils.loads(res.body)
        self.assertTrue(len(res_dict['keypair']['private_key_url']) > 0)

    def test_create_NOS_connect_error_500(self):

        def fake_keypair_create(self, req, body):
            return {'keypair': {'name': 'foo',
                                'user_id': 'fake_id',
                                'public_key': 'XXX',
                                'fingerprint': 'YYY',
                                'private_key': 'KKK'}}

        self.stubs.Set(keypairs.KeypairController, "create",
                       fake_keypair_create)

        def fake_nos_upload_private_key_error(self, bucket_name,
                                              private_key_name,
                                              private_key_content,
                                              expires,
                                              use_domain):
            raise webob.exc.HTTPClientError

        self.stubs.Set(nos_api.OperatePrivateKey, "upload_private_key",
                       fake_nos_upload_private_key_error)
        body = {'keypair': {'name': 'foo'}}
        req = webob.Request.blank('/v2/fake/os-keypairs')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['Content-Type'] = 'application/json'
        res = req.get_response(fakes.wsgi_app())
        self.assertEqual(res.status_int, 500)

    def test_show_not_expired(self):

        def fake_keypair_show(self, req, id):
            return {'keypair': {'name': 'foo',
                                'public_key': 'XXX',
                                'fingerprint': 'YYY.create'}}

        self.stubs.Set(keypairs.KeypairController, "show",
                       fake_keypair_show)

        time_now = datetime.datetime.utcnow()

        def fake_db_key_pair_get_not_expired(context, user_id, name):
            return {'name': 'foo', 'public_key': 'XXX',
                    'fingerprint': 'YYY.create', 'created_at': time_now}

        self.stubs.Set(db, "key_pair_get", fake_db_key_pair_get_not_expired)
        req = webob.Request.blank('/v2/fake/os-keypairs/foo')
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res = req.get_response(fakes.wsgi_app())
        res_dict = jsonutils.loads(res.body)
        self.assertEqual(res.status_int, 200)
        from_zone = tz.tzutc()
        to_zone = tz.tzlocal()
        if time_now.tzinfo is None:
            time_now = time_now.replace(tzinfo=from_zone)
        local_time = time_now.astimezone(to_zone)
        self.assertEqual(local_time.strftime('%Y-%m-%d %H:%M:%S'),
                         res_dict['keypair']['created_at'])
        self.assertNotEqual('expired', res_dict['keypair']['private_key_url'])

    def test_show_expired(self):

        def fake_keypair_show(self, req, id):
            return {'keypair': {'name': 'foo',
                                'public_key': 'XXX',
                                'fingerprint': 'YYY.create'}}

        self.stubs.Set(keypairs.KeypairController, "show",
                       fake_keypair_show)

        def string_to_datetime(string):
            return datetime.datetime.strptime(string, '%Y-%m-%d %H:%M:%S')

        req = webob.Request.blank('/v2/fake/os-keypairs/foo')
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res = req.get_response(fakes.wsgi_app())
        res_dict = jsonutils.loads(res.body)
        self.assertEqual(res.status_int, 200)
        result_datetime = string_to_datetime('2011-11-19 02:39:01')
        from_zone = tz.tzutc()
        to_zone = tz.tzlocal()
        if result_datetime.tzinfo is None:
            result_datetime = result_datetime.replace(tzinfo=from_zone)
        local_time = result_datetime.astimezone(to_zone)
        self.assertEqual(local_time.strftime('%Y-%m-%d %H:%M:%S'),
                         res_dict['keypair']['created_at'])
        self.assertEqual('expired', res_dict['keypair']['private_key_url'])

    def test_index(self):

        def fake_keypair_index(self, req):
            return {'keypairs': [{'keypair': {'name': 'foo',
                                              'public_key': 'XXX',
                                              'fingerprint': 'YYY.create'}}]}

        self.stubs.Set(keypairs.KeypairController, "index",
                       fake_keypair_index)

        def string_to_datetime(string):
            return datetime.datetime.strptime(string, '%Y-%m-%d %H:%M:%S')

        req = webob.Request.blank('/v2/fake/os-keypairs')
        req.method = 'GET'
        req.headers['Content-Type'] = 'application/json'
        res = req.get_response(fakes.wsgi_app())
        res_dict = jsonutils.loads(res.body)
        self.assertEqual(res.status_int, 200)
        result_datetime = string_to_datetime('2011-11-19 02:39:01')
        from_zone = tz.tzutc()
        to_zone = tz.tzlocal()
        if result_datetime.tzinfo is None:
            result_datetime = result_datetime.replace(tzinfo=from_zone)
        local_time = result_datetime.astimezone(to_zone)
        self.assertEqual(local_time.strftime('%Y-%m-%d %H:%M:%S'),
                         res_dict['keypairs'][0]['keypair']['created_at'])
        self.assertEqual('expired',
                         res_dict['keypairs'][0]['keypair']['private_key_url'])
