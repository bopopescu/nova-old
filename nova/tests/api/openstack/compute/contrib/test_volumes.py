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

from lxml import etree
import webob

import nova
from nova.api.openstack.compute.contrib import volumes
from nova.compute import instance_types
from nova import context
import nova.db
from nova import flags
from nova.openstack.common import jsonutils
from nova.openstack.common import timeutils
from nova import test
from nova.tests.api.openstack import fakes
from nova import volume
from webob import exc


FLAGS = flags.FLAGS

FAKE_UUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
FAKE_UUID_A = '00000000-aaaa-aaaa-aaaa-000000000000'
FAKE_UUID_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
FAKE_UUID_C = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
FAKE_UUID_D = 'dddddddd-dddd-dddd-dddd-dddddddddddd'

IMAGE_UUID = 'c905cedb-7281-47e4-8a62-f26bc5fc4c77'


def fake_compute_api_create(cls, context, instance_type, image_href, **kwargs):
    global _block_device_mapping_seen
    _block_device_mapping_seen = kwargs.get('block_device_mapping')

    inst_type = instance_types.get_instance_type_by_flavor_id(2)
    resv_id = None
    return ([{'id': 1,
             'display_name': 'test_server',
             'uuid': FAKE_UUID,
             'instance_type': dict(inst_type),
             'access_ip_v4': '1.2.3.4',
             'access_ip_v6': 'fead::1234',
             'image_ref': IMAGE_UUID,
             'user_id': 'fake',
             'project_id': 'fake',
             'created_at': datetime.datetime(2010, 10, 10, 12, 0, 0),
             'updated_at': datetime.datetime(2010, 11, 11, 11, 0, 0),
             'progress': 0,
             'fixed_ips': []
             }], resv_id)


def fake_get_instance(self, context, instance_id):
    return({'uuid': instance_id})


def fake_attach_volume(self, context, instance, volume_id, device):
    return()


def fake_detach_volume(self, context, volume_id):
    return()


def fake_get_instance_bdms(self, context, instance):
    return([{'id': 1,
             'instance_uuid': instance['uuid'],
             'device_name': '/dev/fake0',
             'delete_on_termination': 'False',
             'virtual_name': 'MyNamesVirtual',
             'snapshot_id': None,
             'volume_id': FAKE_UUID_A,
             'volume_size': 1},
            {'id': 2,
             'instance_uuid':instance['uuid'],
             'device_name': '/dev/fake1',
             'delete_on_termination': 'False',
             'virtual_name': 'MyNamesVirtual',
             'snapshot_id': None,
             'volume_id': FAKE_UUID_B,
             'volume_size': 1}])


class BootFromVolumeTest(test.TestCase):

    def setUp(self):
        super(BootFromVolumeTest, self).setUp()
        self.stubs.Set(nova.compute.API, 'create', fake_compute_api_create)
        fakes.stub_out_nw_api(self.stubs)

    def test_create_root_volume(self):
        body = dict(server=dict(
                name='test_server', imageRef=IMAGE_UUID,
                flavorRef=2, min_count=1, max_count=1,
                block_device_mapping=[dict(
                        volume_id=1,
                        device_name='/dev/vda',
                        virtual='root',
                        delete_on_termination=False,
                        )]
                ))
        global _block_device_mapping_seen
        _block_device_mapping_seen = None
        req = webob.Request.blank('/v2/fake/os-volumes_boot')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        res = req.get_response(fakes.wsgi_app())
        self.assertEqual(res.status_int, 202)
        server = jsonutils.loads(res.body)['server']
        self.assertEqual(FAKE_UUID, server['id'])
        self.assertEqual(FLAGS.password_length, len(server['adminPass']))
        self.assertEqual(len(_block_device_mapping_seen), 1)
        self.assertEqual(_block_device_mapping_seen[0]['volume_id'], 1)
        self.assertEqual(_block_device_mapping_seen[0]['device_name'],
                '/dev/vda')


def return_volume(context, volume_id):
    return {'id': volume_id}


class VolumeApiTest(test.TestCase):
    def setUp(self):
        super(VolumeApiTest, self).setUp()
        fakes.stub_out_networking(self.stubs)
        fakes.stub_out_rate_limiting(self.stubs)
        self.stubs.Set(nova.db, 'volume_get', return_volume)

        self.stubs.Set(volume.api.API, "delete", fakes.stub_volume_delete)
        self.stubs.Set(volume.api.API, "get", fakes.stub_volume_get)
        self.stubs.Set(volume.api.API, "get_all", fakes.stub_volume_get_all)

        self.context = context.get_admin_context()

    def test_volume_create(self):
        self.stubs.Set(volume.api.API, "create", fakes.stub_volume_create)

        vol = {"size": 100,
               "display_name": "Volume Test Name",
               "display_description": "Volume Test Desc",
               "availability_zone": "zone1:host1"}
        body = {"volume": vol}
        req = webob.Request.blank('/v2/fake/os-volumes')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())

        self.assertEqual(resp.status_int, 200)

        resp_dict = jsonutils.loads(resp.body)
        self.assertTrue('volume' in resp_dict)
        self.assertEqual(resp_dict['volume']['size'],
                         vol['size'])
        self.assertEqual(resp_dict['volume']['displayName'],
                         vol['display_name'])
        self.assertEqual(resp_dict['volume']['displayDescription'],
                         vol['display_description'])
        self.assertEqual(resp_dict['volume']['availabilityZone'],
                         vol['availability_zone'])

    def test_volume_index(self):
        req = webob.Request.blank('/v2/fake/os-volumes')
        resp = req.get_response(fakes.wsgi_app())
        self.assertEqual(resp.status_int, 200)

    def test_volume_detail(self):
        req = webob.Request.blank('/v2/fake/os-volumes/detail')
        resp = req.get_response(fakes.wsgi_app())
        self.assertEqual(resp.status_int, 200)

    def test_volume_show(self):
        req = webob.Request.blank('/v2/fake/os-volumes/123')
        resp = req.get_response(fakes.wsgi_app())
        self.assertEqual(resp.status_int, 200)

    def test_volume_show_no_volume(self):
        self.stubs.Set(volume.api.API, "get", fakes.stub_volume_get_notfound)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        resp = req.get_response(fakes.wsgi_app())
        self.assertEqual(resp.status_int, 404)

    def test_volume_delete(self):
        req = webob.Request.blank('/v2/fake/os-volumes/123')
        req.method = 'DELETE'
        resp = req.get_response(fakes.wsgi_app())
        self.assertEqual(resp.status_int, 202)

    def test_volume_delete_no_volume(self):
        self.stubs.Set(volume.api.API, "get", fakes.stub_volume_get_notfound)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'DELETE'
        resp = req.get_response(fakes.wsgi_app())
        self.assertEqual(resp.status_int, 404)

    def test_volume_cinder_update(self):
        # test cinder backend
        self.flags(ebs_backend='cinder')

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 123})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        self.assertEqual(resp.status_int, 400)

    def test_volume_nbs_update_no_server(self):
        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server=None)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 123})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['computeFault']['message']
        self.assertEqual(message,
                    u'Cannot extend nbs volume, nbs server is None.')
        self.assertEqual(resp.status_int, 500)

    def test_volume_nbs_update_body_error(self):
        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 12.3, "size1": 123})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['computeFault']['message']
        self.assertEqual(message, u'Invalid paramater in body.')
        self.assertEqual(resp.status_int, 422)

    def test_volume_nbs_update_can_not_extend(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': [{'size': 4}]}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 1})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['forbidden']['message']
        self.assertEqual(message,
                    u'Cannot extend volume, invalid size is given.')
        self.assertEqual(resp.status_int, 403)

    def test_volume_nbs_update_not_found(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': []}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 1})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['itemNotFound']['message']
        self.assertEqual(message, u'Volume not found.')
        self.assertEqual(resp.status_int, 404)

    def test_volume_nbs_update_nbs_exception(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': [['size']]}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 1})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['computeFault']['message']
        self.assertEqual(message, u'Nbs volume server error.')
        self.assertEqual(resp.status_int, 500)

    def test_volume_nbs_update_not_attached(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': [
                        {'status': 'available',
                         'size': 1,
                         'attachments': [{}]}]}

        def fake_extend_nbs_volume(*args, **kwargs):
            self.assertEqual(len(args), 4)

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)
        self.stubs.Set(nova.compute.API, 'extend_nbs_volume',
                        fake_extend_nbs_volume)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 4})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['size']
        self.assertEqual(message, 4)
        self.assertEqual(resp.status_int, 200)

    def test_volume_nbs_update_inst_not_found(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': [
                        {'status': 'available',
                         'size': 1,
                         'attachments': [{'instanceId': 'fake-inst-uuid'}]}]}

        def fake_extend_nbs_volume(*args, **kwargs):
            self.assertEqual(len(args), 4)

        def fake_compute_api_get(*args, **kwargs):
            from nova import exception
            raise exception.NotFound()

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)
        self.stubs.Set(nova.compute.API, 'extend_nbs_volume',
                        fake_extend_nbs_volume)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 4})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['size']
        self.assertEqual(message, 4)
        self.assertEqual(resp.status_int, 200)

    def test_volume_nbs_update_inst_not_booted(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': [
                        {'status': 'available',
                         'size': 1,
                         'attachments': [
                            {'instanceId': 'fake-inst-uuid',
                             'status': 'attachedInVM'}]}]}

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE, 'uuid': 'fake-inst-uuid'}

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'down'}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)
        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 4})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['forbidden']['message']
        self.assertEqual(message,
                    u'Cannot extend volume while instance os is starting.')
        self.assertEqual(resp.status_int, 403)

    def test_volume_nbs_update_no_memcache_client(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': [
                        {'status': 'available',
                         'size': 1,
                         'attachments': [
                            {'instanceId': 'fake-inst-uuid',
                             'status': 'attachedInVM'}]}]}

        def fake_compute_api_get(*args, **kwargs):
            from nova import exception
            raise exception.MemCacheClientNotFound()

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'down'}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)
        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 4})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['computeFault']['message']
        self.assertEqual(message, u'Memory cache client is not found.')
        self.assertEqual(resp.status_int, 500)

    def test_volume_nbs_update_attached(self):

        def fake_nbs_get(*args, **kwargs):
            return {'volumes': [
                        {'status': 'available',
                         'size': 1,
                         'attachments': [
                            {'instanceId': 'fake-inst-uuid',
                             'status': 'attachedInVM'}]}]}

        def fake_extend_nbs_volume(*args, **kwargs):
            self.assertEqual(len(args), 5)

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE, 'uuid': 'fake-inst-uuid'}

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'up'}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)
        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)
        self.stubs.Set(nova.compute.API, 'extend_nbs_volume',
                        fake_extend_nbs_volume)

        req = webob.Request.blank('/v2/fake/os-volumes/456')
        req.method = 'PUT'
        req.body = jsonutils.dumps({"size": 4})
        req.headers['content-type'] = 'application/json'
        resp = req.get_response(fakes.wsgi_app())
        message = jsonutils.loads(resp.body)['size']
        self.assertEqual(message, 4)
        self.assertEqual(resp.status_int, 200)


class VolumeAttachTests(test.TestCase):
    def setUp(self):
        super(VolumeAttachTests, self).setUp()
        self.stubs.Set(nova.compute.API,
                       'get_instance_bdms',
                       fake_get_instance_bdms)
        self.stubs.Set(nova.compute.API, 'get', fake_get_instance)
        self.context = context.get_admin_context()
        self.expected_show = {'volumeAttachment':
            {'device': '/dev/fake0',
             'serverId': FAKE_UUID,
             'id': FAKE_UUID_A,
             'volumeId': FAKE_UUID_A
            }}

    def test_show(self):
        attachments = volumes.VolumeAttachmentController()
        req = webob.Request.blank('/v2/fake/os-volumes/show')
        req.method = 'POST'
        req.body = jsonutils.dumps({})
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        result = attachments.show(req, FAKE_UUID, FAKE_UUID_A)
        self.assertEqual(self.expected_show, result)

    def test_delete(self):
        self.flags(ebs_backend='cinder')
        self.stubs.Set(nova.compute.API, 'detach_volume', fake_detach_volume)
        attachments = volumes.VolumeAttachmentController()
        req = webob.Request.blank('/v2/fake/os-volumes/delete')
        req.method = 'POST'
        req.body = jsonutils.dumps({})
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        result = attachments.delete(req, FAKE_UUID, FAKE_UUID_A)
        self.assertEqual('202 Accepted', result.status)

    def test_delete_vol_not_found(self):
        self.flags(ebs_backend='cinder')
        self.stubs.Set(nova.compute.API, 'detach_volume', fake_detach_volume)
        attachments = volumes.VolumeAttachmentController()
        req = webob.Request.blank('/v2/fake/os-volumes/delete')
        req.method = 'POST'
        req.body = jsonutils.dumps({})
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        self.assertRaises(exc.HTTPNotFound,
                          attachments.delete,
                          req,
                          FAKE_UUID,
                          FAKE_UUID_C)

    def test_detach_nbs_volume(self):

        def fake_compute_api_get(*args, **kwargs):
            return {'uuid': FAKE_UUID}

        def fake_get_instance_bdms(*args, **kwargs):
            return [{'volume_id': FAKE_UUID_A,
                     'updated_at': datetime.datetime(2000, 10, 10, 12, 0, 0)}]

        def fake_utcnow(*args, **kwargs):
            return datetime.datetime(2013, 10, 10, 12, 0, 0)

        def fake_detach_nbs_volume(*args, **kwargs):
            return

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(attach_detach_interval=0)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'get_instance_bdms', fake_get_instance_bdms)
        self.stubs.Set(nova.compute.API,
                        'detach_nbs_volume', fake_detach_nbs_volume)
        self.stubs.Set(nova.openstack.common.timeutils, 'utcnow', fake_utcnow)

        attachments = volumes.VolumeAttachmentController()
        req = webob.Request.blank('/v2/fake/os-volumes/delete')
        req.method = 'DELETE'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        result = attachments.delete(req, FAKE_UUID, FAKE_UUID_A)
        self.assertTrue(result['return'])

    def test_detach_nbs_volume_no_server(self):

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server=None)

        attachments = volumes.VolumeAttachmentController()
        req = webob.Request.blank('/v2/fake/os-volumes/delete')
        req.method = 'DELETE'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.delete(req, FAKE_UUID, FAKE_UUID_A)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPServerError))
            self.assertEqual('Cannot detach nbs volume, nbs server is None.',
                            ex.explanation)

    def test_detach_nbs_volume_inst_not_found(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova import exception
            raise exception.NotFound()

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)

        attachments = volumes.VolumeAttachmentController()
        req = webob.Request.blank('/v2/fake/os-volumes/delete')
        req.method = 'DELETE'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.delete(req, FAKE_UUID, FAKE_UUID_A)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPNotFound))
            self.assertEqual('Instance aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa '
                             'not found.', ex.explanation)

    def test_detach_nbs_volume_not_attached(self):

        def fake_compute_api_get(*args, **kwargs):
            return {'locked': False, 'uuid': FAKE_UUID}

        def fake_get_instance_bdms(*args, **kwargs):
            return [{'volume_id': FAKE_UUID_A,
                     'updated_at': datetime.datetime(2000, 10, 10, 12, 0, 0)}]

        def fake_utcnow(*args, **kwargs):
            return datetime.datetime(2013, 10, 10, 12, 0, 0)

        def fake_nbs_get(*args, **kwargs):
            return {"volumes": [
                                {"status": "in-use",
                                 "size": 1234,
                                 "attachments":[]}]}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(attach_detach_interval=0)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'get_instance_bdms', fake_get_instance_bdms)
        self.stubs.Set(nova.openstack.common.timeutils, 'utcnow', fake_utcnow)
        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        attachments = volumes.VolumeAttachmentController()
        req = webob.Request.blank('/v2/fake/os-volumes/delete')
        req.method = 'DELETE'
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.delete(req, FAKE_UUID, FAKE_UUID_A)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPNotFound))
            self.assertEqual('Volume is not attached.', ex.explanation)

    def test_attach_volume(self):
        self.flags(ebs_backend='cinder')
        self.stubs.Set(nova.compute.API, 'attach_volume', fake_attach_volume)
        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A,
                                    'device': '/dev/fake'}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        result = attachments.create(req, FAKE_UUID, body)
        self.assertEqual(result['volumeAttachment']['id'],
            '00000000-aaaa-aaaa-aaaa-000000000000')

    def test_attach_nbs_volume(self):

        def fake_attach_nbs_volume(*args, **kwargs):
            return '/dev/vdd'

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE, 'uuid': 'fake-inst-uuid'}

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'up'}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(server_heartbeat_period=1)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)
        self.stubs.Set(nova.compute.API,
                        'attach_nbs_volume', fake_attach_nbs_volume)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        result = attachments.create(req, FAKE_UUID, body)
        self.assertEqual(result['attachment']['volumeId'],
            '00000000-aaaa-aaaa-aaaa-000000000000')

    def test_attach_nbs_volume_no_server(self):

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server=None)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPServerError))
            self.assertEqual('Cannot attach nbs volume, nbs server is None.',
                            ex.explanation)

    def test_attach_nbs_volume_body_error(self):

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeattachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPUnprocessableEntity))
            self.assertEqual('Invalid paramater in body.', ex.explanation)

    def test_attach_nbs_volume_inst_not_found(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova import exception
            raise exception.NotFound()

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPNotFound))
            self.assertEqual('Instance aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa '
                             'not found.', ex.explanation)

    def test_attach_nbs_volume_not_booted(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE, 'uuid': 'fake-inst-uuid'}

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'down'}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(server_heartbeat_period=1)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPForbidden))
            self.assertEqual('Cannot attach volume while instance os is '
                             'starting.', ex.explanation)

    def test_attach_nbs_volume_no_memcache_client(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE, 'uuid': 'fake-inst-uuid'}

        def fake_instance_os_boot_ready(*args, **kwargs):
            from nova import exception
            raise exception.MemCacheClientNotFound()

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(server_heartbeat_period=1)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPServerError))
            self.assertEqual('Memory cache client is not found.',
                            ex.explanation)

    def test_attach_nbs_volume_not_allow_attach(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE, 'uuid': 'fake-inst-uuid',
                    'locked': False, 'task_state': None}

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'up'}

        def fake_check_allow_attach(*args, **kwargs):
            return False

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(server_heartbeat_period=1)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)
        self.stubs.Set(nova.compute.API,
                        'check_allow_attach', fake_check_allow_attach)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPForbidden))
            self.assertEqual("Instance aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa "
                             "is forbidden to attach volume.", ex.explanation)

    def test_attach_nbs_volume_no_free_device(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE, 'uuid': 'fake-inst-uuid'}

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'up'}

        def fake_attach_nbs_volume(*args, **kwargs):
            from nova import exception
            raise exception.NoFreeDevice()

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(server_heartbeat_period=1)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)
        self.stubs.Set(nova.compute.API,
                        'attach_nbs_volume', fake_attach_nbs_volume)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPUnprocessableEntity))
            self.assertEqual('No free device to attach volume.',
                                ex.explanation)

    def test_attach_nbs_volume_not_available(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE,
                    'task_state': None,
                    'uuid': 'fake-inst-uuid',
                    'locked': False}

        def fake_instance_os_boot_ready(*args, **kwargs):
            return {'instance_uuid': 'fake-inst-uuid', 'status': 'up'}

        def fake_check_allow_attach(*args, **kwargs):
            return True

        def fake_nbs_get(*args, **kwargs):
            return {"volumes": [
                                {"status": "in-use",
                                 "size": 1234,
                                 "attachments":[]}]}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')
        self.flags(server_heartbeat_period=1)

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API, 'check_allow_attach',
                        fake_check_allow_attach)
        self.stubs.Set(nova.compute.API,
                        'instance_os_boot_ready', fake_instance_os_boot_ready)
        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        attachments = volumes.VolumeAttachmentController()
        body = {'volumeAttachment': {'volumeId': FAKE_UUID_A}}
        req = webob.Request.blank('/v2/fake/os-volumes/attach')
        req.method = 'POST'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.create(req, FAKE_UUID, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPForbidden))
            self.assertEqual('Volume is not available.', ex.explanation)

    def test_attach_volume_cinder_update(self):
        # test cinder backend
        self.flags(ebs_backend='cinder')

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': 123, 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        self.assertRaises(exc.HTTPBadRequest,
            attachments.update, req, FAKE_UUID, FAKE_UUID_A, body)

    def test_update_nbs_volume_qos_no_server(self):
        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server=None)

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': 123, 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.update(req, FAKE_UUID, FAKE_UUID_A, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPServerError))
            self.assertEqual('Cannot update nbs qos info, nbs server is None.',
                            ex.explanation)

    def test_update_nbs_volume_qos_by_admin_no_project(self):
        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': '123', 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        self.assertRaises(exc.HTTPUnprocessableEntity,
            attachments.update, req, FAKE_UUID, 123, body)

        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context

        try:
            attachments.update(req, FAKE_UUID, FAKE_UUID_A, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPUnprocessableEntity))
            self.assertEqual('Project ID of volume is invalid.',
                            ex.explanation)

    def test_update_nbs_volume_qos_body_error(self):
        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': '123', 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.environ['nova.context'] = self.context
        self.assertRaises(exc.HTTPUnprocessableEntity,
            attachments.update, req, FAKE_UUID, 123, body)

        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        self.context.is_admin = False
        req.environ['nova.context'] = self.context

        try:
            attachments.update(req, FAKE_UUID, FAKE_UUID_A, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPUnprocessableEntity))
            self.assertEqual('Invalid paramater in body.', ex.explanation)
        finally:
            self.context.is_admin = True

    def test_update_nbs_volume_qos_inst_not_found(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova import exception
            raise exception.NotFound()

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': 123, 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.headers['x-vol-project'] = 'fake-vol-project-id'
        self.context.is_admin = False
        req.environ['nova.context'] = self.context

        try:
            attachments.update(req, FAKE_UUID, FAKE_UUID_A, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPNotFound))
            self.assertEqual('Instance aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa '
                             'not found.', ex.explanation)
        finally:
            self.context.is_admin = True

    def test_update_nbs_volume_qos_vol_not_found(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE,
                    'task_state': None,
                    'uuid': 'fake-inst-uuid',
                    'locked': False}

        def fake_nbs_get(*args, **kwargs):
            return {"volumes": []}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': 123, 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.headers['x-vol-project'] = 'fake-vol-project-id'
        self.context.is_admin = False
        req.environ['nova.context'] = self.context

        try:
            attachments.update(req, FAKE_UUID, FAKE_UUID_A, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPNotFound))
            self.assertEqual('Volume not found.', ex.explanation)
        finally:
            self.context.is_admin = True

    def test_update_nbs_volume_qos_vol_not_attached(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE,
                    'task_state': None,
                    'uuid': 'fake-inst-uuid',
                    'locked': False}

        def fake_nbs_get(*args, **kwargs):
            return {"volumes": [
                                {"status": "in-use",
                                 "attachments":[]}]}

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': 123, 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.headers['x-vol-project'] = 'fake-vol-project-id'
        req.environ['nova.context'] = self.context
        self.context.is_admin = False
        req.environ['nova.context'] = self.context

        try:
            attachments.update(req, FAKE_UUID, FAKE_UUID_A, body)
        except Exception as ex:
            self.assertTrue(isinstance(ex, exc.HTTPNotFound))
            self.assertEqual('Volume is not attached.', ex.explanation)
        finally:
            self.context.is_admin = True

    def test_update_nbs_volume_qos(self):

        def fake_compute_api_get(*args, **kwargs):
            from nova.compute import vm_states
            return {'vm_state': vm_states.ACTIVE,
                    'task_state': None,
                    'uuid': 'fake-inst-uuid',
                    'locked': False}

        def fake_nbs_get(*args, **kwargs):
            return {"volumes": [
                                {"status": "in-use",
                                 "attachments":[
                                    {"status": "attachedInVM",
                                     "instanceId": "fake-inst-uuid"}]}]}

        def fake_update_nbs_qos(*args, **kwargs):
            self.assertEqual(args[3], FAKE_UUID_A)

        self.flags(ebs_backend='nbs')
        self.flags(nbs_api_server='127.0.0.1')

        self.stubs.Set(nova.compute.API, 'get', fake_compute_api_get)
        self.stubs.Set(nova.compute.API, 'update_nbs_qos', fake_update_nbs_qos)
        self.stubs.Set(nova.compute.nbs_client.API, 'get', fake_nbs_get)

        attachments = volumes.VolumeAttachmentController()
        body = {'maxBandWidth': 123, 'maxIOPS': 456}
        req = webob.Request.blank('/v2/fake/os-volumes/update')
        req.method = 'PUT'
        req.body = jsonutils.dumps(body)
        req.headers['content-type'] = 'application/json'
        req.headers['x-vol-project'] = 'fake-vol-project-id'
        req.environ['nova.context'] = self.context
        result = attachments.update(req, FAKE_UUID, FAKE_UUID_A, body)
        self.assertTrue(result['return'])


class VolumeSerializerTest(test.TestCase):
    def _verify_volume_attachment(self, attach, tree):
        for attr in ('id', 'volumeId', 'serverId', 'device'):
            self.assertEqual(str(attach[attr]), tree.get(attr))

    def _verify_volume(self, vol, tree):
        self.assertEqual(tree.tag, 'volume')

        for attr in ('id', 'status', 'size', 'availabilityZone', 'createdAt',
                     'displayName', 'displayDescription', 'volumeType',
                     'snapshotId'):
            self.assertEqual(str(vol[attr]), tree.get(attr))

        for child in tree:
            self.assertTrue(child.tag in ('attachments', 'metadata'))
            if child.tag == 'attachments':
                self.assertEqual(1, len(child))
                self.assertEqual('attachment', child[0].tag)
                self._verify_volume_attachment(vol['attachments'][0], child[0])
            elif child.tag == 'metadata':
                not_seen = set(vol['metadata'].keys())
                for gr_child in child:
                    self.assertTrue(gr_child.get("key") in not_seen)
                    self.assertEqual(str(vol['metadata'][gr_child.get("key")]),
                                     gr_child.text)
                    not_seen.remove(gr_child.get("key"))
                self.assertEqual(0, len(not_seen))

    def test_attach_show_create_serializer(self):
        serializer = volumes.VolumeAttachmentTemplate()
        raw_attach = dict(
            id='vol_id',
            volumeId='vol_id',
            serverId='instance_uuid',
            device='/foo')
        text = serializer.serialize(dict(volumeAttachment=raw_attach))

        print text
        tree = etree.fromstring(text)

        self.assertEqual('volumeAttachment', tree.tag)
        self._verify_volume_attachment(raw_attach, tree)

    def test_attach_index_serializer(self):
        serializer = volumes.VolumeAttachmentsTemplate()
        raw_attaches = [dict(
                id='vol_id1',
                volumeId='vol_id1',
                serverId='instance1_uuid',
                device='/foo1'),
                        dict(
                id='vol_id2',
                volumeId='vol_id2',
                serverId='instance2_uuid',
                device='/foo2')]
        text = serializer.serialize(dict(volumeAttachments=raw_attaches))

        print text
        tree = etree.fromstring(text)

        self.assertEqual('volumeAttachments', tree.tag)
        self.assertEqual(len(raw_attaches), len(tree))
        for idx, child in enumerate(tree):
            self.assertEqual('volumeAttachment', child.tag)
            self._verify_volume_attachment(raw_attaches[idx], child)

    def test_volume_show_create_serializer(self):
        serializer = volumes.VolumeTemplate()
        raw_volume = dict(
            id='vol_id',
            status='vol_status',
            size=1024,
            availabilityZone='vol_availability',
            createdAt=timeutils.utcnow(),
            attachments=[dict(
                    id='vol_id',
                    volumeId='vol_id',
                    serverId='instance_uuid',
                    device='/foo')],
            displayName='vol_name',
            displayDescription='vol_desc',
            volumeType='vol_type',
            snapshotId='snap_id',
            metadata=dict(
                foo='bar',
                baz='quux',
                ),
            )
        text = serializer.serialize(dict(volume=raw_volume))

        print text
        tree = etree.fromstring(text)

        self._verify_volume(raw_volume, tree)

    def test_volume_index_detail_serializer(self):
        serializer = volumes.VolumesTemplate()
        raw_volumes = [dict(
                id='vol1_id',
                status='vol1_status',
                size=1024,
                availabilityZone='vol1_availability',
                createdAt=timeutils.utcnow(),
                attachments=[dict(
                        id='vol1_id',
                        volumeId='vol1_id',
                        serverId='instance_uuid',
                        device='/foo1')],
                displayName='vol1_name',
                displayDescription='vol1_desc',
                volumeType='vol1_type',
                snapshotId='snap1_id',
                metadata=dict(
                    foo='vol1_foo',
                    bar='vol1_bar',
                    ),
                ),
                       dict(
                id='vol2_id',
                status='vol2_status',
                size=1024,
                availabilityZone='vol2_availability',
                createdAt=timeutils.utcnow(),
                attachments=[dict(
                        id='vol2_id',
                        volumeId='vol2_id',
                        serverId='instance_uuid',
                        device='/foo2')],
                displayName='vol2_name',
                displayDescription='vol2_desc',
                volumeType='vol2_type',
                snapshotId='snap2_id',
                metadata=dict(
                    foo='vol2_foo',
                    bar='vol2_bar',
                    ),
                )]
        text = serializer.serialize(dict(volumes=raw_volumes))

        print text
        tree = etree.fromstring(text)

        self.assertEqual('volumes', tree.tag)
        self.assertEqual(len(raw_volumes), len(tree))
        for idx, child in enumerate(tree):
            self._verify_volume(raw_volumes[idx], child)


class TestVolumeCreateRequestXMLDeserializer(test.TestCase):

    def setUp(self):
        super(TestVolumeCreateRequestXMLDeserializer, self).setUp()
        self.deserializer = volumes.CreateDeserializer()

    def test_minimal_volume(self):
        self_request = """
<volume xmlns="http://docs.openstack.org/compute/api/v1.1"
        size="1"></volume>"""
        request = self.deserializer.deserialize(self_request)
        expected = {
            "volume": {
                "size": "1",
            },
        }
        self.assertEquals(request['body'], expected)

    def test_display_name(self):
        self_request = """
<volume xmlns="http://docs.openstack.org/compute/api/v1.1"
        size="1"
        display_name="Volume-xml"></volume>"""
        request = self.deserializer.deserialize(self_request)
        expected = {
            "volume": {
                "size": "1",
                "display_name": "Volume-xml",
            },
        }
        self.assertEquals(request['body'], expected)

    def test_display_description(self):
        self_request = """
<volume xmlns="http://docs.openstack.org/compute/api/v1.1"
        size="1"
        display_name="Volume-xml"
        display_description="description"></volume>"""
        request = self.deserializer.deserialize(self_request)
        expected = {
            "volume": {
                "size": "1",
                "display_name": "Volume-xml",
                "display_description": "description",
            },
        }
        self.assertEquals(request['body'], expected)

    def test_volume_type(self):
        self_request = """
<volume xmlns="http://docs.openstack.org/compute/api/v1.1"
        size="1"
        display_name="Volume-xml"
        display_description="description"
        volume_type="289da7f8-6440-407c-9fb4-7db01ec49164"></volume>"""
        request = self.deserializer.deserialize(self_request)
        expected = {
            "volume": {
                "display_name": "Volume-xml",
                "size": "1",
                "display_name": "Volume-xml",
                "display_description": "description",
                "volume_type": "289da7f8-6440-407c-9fb4-7db01ec49164",
            },
        }
        self.assertEquals(request['body'], expected)

    def test_availability_zone(self):
        self_request = """
<volume xmlns="http://docs.openstack.org/compute/api/v1.1"
        size="1"
        display_name="Volume-xml"
        display_description="description"
        volume_type="289da7f8-6440-407c-9fb4-7db01ec49164"
        availability_zone="us-east1"></volume>"""
        request = self.deserializer.deserialize(self_request)
        expected = {
            "volume": {
                "size": "1",
                "display_name": "Volume-xml",
                "display_description": "description",
                "volume_type": "289da7f8-6440-407c-9fb4-7db01ec49164",
                "availability_zone": "us-east1",
            },
        }
        self.assertEquals(request['body'], expected)

    def test_metadata(self):
        self_request = """
<volume xmlns="http://docs.openstack.org/compute/api/v1.1"
        display_name="Volume-xml"
        size="1">
        <metadata><meta key="Type">work</meta></metadata></volume>"""
        request = self.deserializer.deserialize(self_request)
        expected = {
            "volume": {
                "display_name": "Volume-xml",
                "size": "1",
                "metadata": {
                    "Type": "work",
                },
            },
        }
        self.assertEquals(request['body'], expected)

    def test_full_volume(self):
        self_request = """
<volume xmlns="http://docs.openstack.org/compute/api/v1.1"
        size="1"
        display_name="Volume-xml"
        display_description="description"
        volume_type="289da7f8-6440-407c-9fb4-7db01ec49164"
        availability_zone="us-east1">
        <metadata><meta key="Type">work</meta></metadata></volume>"""
        request = self.deserializer.deserialize(self_request)
        expected = {
            "volume": {
                "size": "1",
                "display_name": "Volume-xml",
                "display_description": "description",
                "volume_type": "289da7f8-6440-407c-9fb4-7db01ec49164",
                "availability_zone": "us-east1",
                "metadata": {
                    "Type": "work",
                },
            },
        }
        self.maxDiff = None
        self.assertEquals(request['body'], expected)


class CommonUnprocessableEntityTestCase(object):

    resource = None
    entity_name = None
    controller_cls = None
    kwargs = {}

    """
    Tests of places we throw 422 Unprocessable Entity from
    """

    def setUp(self):
        super(CommonUnprocessableEntityTestCase, self).setUp()
        self.controller = self.controller_cls()

    def _unprocessable_create(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/' + self.resource)
        req.method = 'POST'

        kwargs = self.kwargs.copy()
        kwargs['body'] = body
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.create, req, **kwargs)

    def test_create_no_body(self):
        self._unprocessable_create(body=None)

    def test_create_missing_volume(self):
        body = {'foo': {'a': 'b'}}
        self._unprocessable_create(body=body)

    def test_create_malformed_entity(self):
        body = {self.entity_name: 'string'}
        self._unprocessable_create(body=body)


class UnprocessableVolumeTestCase(CommonUnprocessableEntityTestCase,
                                  test.TestCase):

    resource = 'os-volumes'
    entity_name = 'volume'
    controller_cls = volumes.VolumeController


class UnprocessableAttachmentTestCase(CommonUnprocessableEntityTestCase,
                                      test.TestCase):

    resource = 'servers/' + FAKE_UUID + '/os-volume_attachments'
    entity_name = 'volumeAttachment'
    controller_cls = volumes.VolumeAttachmentController
    kwargs = {'server_id': FAKE_UUID}


class UnprocessableSnapshotTestCase(CommonUnprocessableEntityTestCase,
                                    test.TestCase):

    resource = 'os-snapshots'
    entity_name = 'snapshot'
    controller_cls = volumes.SnapshotController
