# Copyright 2011 Eldar Nugaev
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

from lxml import etree

from nova.api.openstack.compute.contrib import keypairs_search
from nova import db
from nova import exception
from nova import quota
from nova import test
from nova.tests.api.openstack import fakes


QUOTAS = quota.QUOTAS


def fake_keypair(name):
    return {'public_key': 'FAKE_KEY',
            'fingerprint': 'FAKE_FINGERPRINT',
            'name': name,
            'user_id': None}


def db_key_pair_get_all_by_user(context, user_id):
    return [fake_keypair('FAKE')]


def db_key_pair_get_all(context):
    return [fake_keypair('FAKE'),
            fake_keypair('FAKE1')]


class KeypairsTest(test.TestCase):

    def setUp(self):
        super(KeypairsTest, self).setUp()
        fakes.stub_out_networking(self.stubs)
        fakes.stub_out_rate_limiting(self.stubs)

        self.stubs.Set(db, "key_pair_get_all_by_user",
                       db_key_pair_get_all_by_user)
        self.stubs.Set(db, "key_pair_get_all",
                       db_key_pair_get_all)
        self.controller = keypairs_search.KeypairSearchController()

    def test_keypair_list(self):
        req = fakes.HTTPRequest.blank('/v2/fake/os-keypairs-search',
                                  use_admin_context=True)
        context = req.environ['nova.context']
        context.roles = ["admin"]
        res = self.controller.index(req)
        response = {'keypairs': [{'keypair': fake_keypair('FAKE')}]}
        self.assertEqual(response, res)

    def test_keypair_search(self):
        req = fakes.HTTPRequest.blank(
                                '/v2/fake/os-keypairs-search?all_tenants=true',
                                use_admin_context=True)
        context = req.environ['nova.context']
        context.roles = ["admin"]
        res = self.controller.index(req)
        response = {'keypairs': [{'keypair': fake_keypair('FAKE')},
                                  {"keypair": fake_keypair('FAKE1')}]}
        self.assertEqual(response, res)

    def test_keypair_policy(self):
        req = fakes.HTTPRequest.blank(
                                '/v2/fake/os-keypairs-search?all_tenants=true')
        self.assertRaises(exception.PolicyNotAuthorized,
                          self.controller.index, req)


class KeypairsXMLSerializerTest(test.TestCase):

    def setUp(self):
        super(KeypairsXMLSerializerTest, self).setUp()

    def test_index_serializer(self):
        exemplar = dict(keypairs=[
                dict(keypair=dict(
                        name='key1_name',
                        public_key='key1_key',
                        fingerprint='key1_fingerprint')),
                dict(keypair=dict(
                        name='key2_name',
                        public_key='key2_key',
                        fingerprint='key2_fingerprint'))])
        serializer = keypairs_search.KeypairsTemplate()
        text = serializer.serialize(exemplar)

        tree = etree.fromstring(text)

        self.assertEqual('keypairs', tree.tag)
        self.assertEqual(len(exemplar['keypairs']), len(tree))
        for idx, keypair in enumerate(tree):
            self.assertEqual('keypair', keypair.tag)
            kp_data = exemplar['keypairs'][idx]['keypair']
            for child in keypair:
                self.assertTrue(child.tag in kp_data)
                self.assertEqual(child.text, kp_data[child.tag])
