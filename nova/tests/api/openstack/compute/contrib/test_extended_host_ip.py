# author: hzwangpan@corp.netease.com
# The UT for extended API of getting host ip by instance uuid.

from lxml import etree
import webob

from nova.api.openstack.compute.contrib import extended_host_ip
from nova import compute
from nova import db
from nova import exception
from nova import flags
from nova.openstack.common import jsonutils
from nova import test
from nova.tests.api.openstack import fakes


FLAGS = flags.FLAGS


UUID1 = '00000000-0000-0000-0000-000000000001'


def fake_compute_get(*args, **kwargs):
    return fakes.stub_instance(1, uuid=UUID1, host="host-fake")


def fake_cn_get(context, host):
    return {"hypervisor_hostname": host}


def fake_service_get_all_by_host(context, host):
    return [{'host_ip': 'fake_host_ip'}]


class ExtendedHostIpTest(test.TestCase):
    content_type = 'application/json'
    prefix = 'OS-EXT-SRV-ATTR:'

    def setUp(self):
        super(ExtendedHostIpTest, self).setUp()
        fakes.stub_out_nw_api(self.stubs)
        self.stubs.Set(compute.api.API, 'get', fake_compute_get)
        self.stubs.Set(db, 'compute_node_get_by_host', fake_cn_get)
        self.stubs.Set(db, 'service_get_all_by_host',
                       fake_service_get_all_by_host)

    def _make_request(self, url):
        req = webob.Request.blank(url)
        req.headers['Accept'] = self.content_type
        res = req.get_response(fakes.wsgi_app())
        return res

    def _get_server(self, body):
        return jsonutils.loads(body).get('server')

    def assertServerAttributes(self, server, host, instance_name):
        self.assertEqual(server.get('%shost' % self.prefix), host)
        self.assertEqual(server.get('%sinstance_name' % self.prefix),
                         instance_name)
        self.assertEqual(server.get('%shypervisor_hostname' % self.prefix),
                         host)

    def test_show(self):
        url = '/v2/fake/servers/%s' % UUID1
        res = self._make_request(url)

        self.assertEqual(res.status_int, 200)
        self.assertServerAttributes(self._get_server(res.body),
                                host='host-fake',
                                instance_name='instance-1')

    def test_no_instance_passthrough_404(self):

        def fake_compute_get(*args, **kwargs):
            raise exception.InstanceNotFound()

        self.stubs.Set(compute.api.API, 'get', fake_compute_get)
        url = '/v2/fake/servers/70f6db34-de8d-4fbd-aafb-4065bdfa6115'
        res = self._make_request(url)

        self.assertEqual(res.status_int, 404)
