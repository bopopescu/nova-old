#
# Created on Dec 13, 2012
#
# @author: hzzhoushaoyu
#

from lxml import etree

from nova.api.openstack.compute.contrib import floating_ips_search
from nova import compute
from nova import context
from nova import db
from nova import exception
from nova import network
from nova import test
from nova.tests.api.openstack import fakes
from nova import utils

FAKE_UUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'


def network_api_get_fixed_ip(self, context, id):
    if id is None:
        return None
    return {'address': '10.0.0.1', 'id': id, 'instance_uuid': FAKE_UUID}


def network_api_get_allocated_fixed_ips(self, context):
    return [{'address': '10.0.0.1', 'id': 20, 'instance_uuid': FAKE_UUID}]


def network_api_get_floating_ip(self, context, id):
    return {'id': 1, 'address': '10.10.10.10', 'pool': 'nova',
            'fixed_ip_id': None}


def network_api_get_floating_ips(self, context, search_opts=None):
    if "all_tenants" in search_opts:
        return [{'id': 1,
             'address': '10.10.10.10',
             'pool': 'nova',
             'fixed_ip_id': 20},
            {'id': 2,
             'pool': 'nova', 'interface': 'eth0',
             'address': '10.10.10.11',
             'fixed_ip_id': None},
            {'id': 3,
             'pool': 'nova', 'interface': 'eth0',
             'address': '10.10.10.12',
             'fixed_ip_id': None}]
    else:
        return [{'id': 1,
             'address': '10.10.10.10',
             'pool': 'nova',
             'fixed_ip_id': 20},
            {'id': 2,
             'pool': 'nova', 'interface': 'eth0',
             'address': '10.10.10.11',
             'fixed_ip_id': None}]


def compute_api_get(self, context, instance_id):
    return dict(uuid=FAKE_UUID, hostname="instance001",
                 id=instance_id, instance_type_id=1, host='bob')


def compute_api_get_all(self, context, *args, **kwargs):
    return [dict(uuid=FAKE_UUID, hostname="instance001",
                 id=1, instance_type_id=1, host='bob')]


def fake_instance_get(context, instance_id):
        return {
        "id": 1,
        "uuid": utils.gen_uuid(),
        "name": 'fake',
        "user_id": 'fakeuser',
        "project_id": '123'}


class FloatingIpTest(test.TestCase):
    floating_ip = "10.10.10.10"
    floating_ip_2 = "10.10.10.11"

    def _create_floating_ips(self, floating_ips=None):
        """Create a floating ip object."""
        if floating_ips is None:
            floating_ips = [self.floating_ip]
        elif not isinstance(floating_ips, (list, tuple)):
            floating_ips = [floating_ips]

        def make_ip_dict(ip):
            """Shortcut for creating floating ip dict."""
            return

        dict_ = {'pool': 'nova', 'host': 'fake_host'}
        return db.floating_ip_bulk_create(
            self.context, [dict(address=ip, **dict_) for ip in floating_ips],
        )

    def _delete_floating_ip(self):
        db.floating_ip_destroy(self.context, self.floating_ip)

    def setUp(self):
        super(FloatingIpTest, self).setUp()
        self.stubs.Set(network.api.API, "get_fixed_ip",
                       network_api_get_fixed_ip)
        self.stubs.Set(compute.api.API, "get",
                       compute_api_get)
        self.stubs.Set(network.api.API, "get_floating_ips",
                       network_api_get_floating_ips)
        self.stubs.Set(compute.api.API, "get_all",
                       compute_api_get_all)
        self.stubs.Set(network.api.API, "get_allocated_fixed_ips",
                       network_api_get_allocated_fixed_ips)

        self.context = context.get_admin_context()
        self._create_floating_ips()

        self.controller = floating_ips_search.FloatingIPSearchController()

    def tearDown(self):
        self._delete_floating_ip()
        super(FloatingIpTest, self).tearDown()

    def test_translate_floating_ip_view(self):
        floating_ip_address = self.floating_ip
        floating_ip = db.floating_ip_get_by_address(self.context,
                                                    floating_ip_address)
        floating_ip['fixed_ip'] = None
        floating_ip['instance'] = None
        view = floating_ips_search._translate_floating_ip_view(floating_ip)
        self.assertTrue('floating_ip' in view)
        self.assertTrue(view['floating_ip']['id'])
        self.assertEqual(view['floating_ip']['ip'], self.floating_ip)
        self.assertEqual(view['floating_ip']['fixed_ip'], None)
        self.assertEqual(view['floating_ip']['instance_id'], None)

    def test_translate_floating_ip_view_dict(self):
        floating_ip = {'id': 0, 'address': '10.0.0.10', 'pool': 'nova',
                       'fixed_ip': None}
        view = floating_ips_search._translate_floating_ip_view(floating_ip)
        self.assertTrue('floating_ip' in view)

    def test_floating_ips_list(self):
        req = fakes.HTTPRequest.blank('/v2/fake/os-floating-ips',
                                      use_admin_context=True)
        context = req.environ['nova.context']
        context.roles = ["admin"]
        res_dict = self.controller.index(req)

        response = {'floating_ips': [{'propject_id': None,
                        'ip': '10.10.10.10',
                        'fixed_ip': '10.0.0.1',
                        'instance_id': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                        'instance_name': 'instance001',
                        'id': 1,
                        'pool': 'nova'},
                        {'propject_id': None,
                        'ip': '10.10.10.11',
                        'fixed_ip': None,
                        'instance_id': None,
                        'instance_name': None,
                        'id': 2,
                        'pool': 'nova'}]}
        self.assertEqual(res_dict, response)

    def test_floating_ips_list_search(self):
        req = fakes.HTTPRequest.blank(
                            '/v2/fake/os-floating-ips?all_tenants=true',
                            use_admin_context=True)
        context = req.environ['nova.context']
        context.roles = ["admin"]
        res_dict = self.controller.index(req)
        response = {'floating_ips': [{'propject_id': None,
                        'ip': '10.10.10.10',
                        'fixed_ip': '10.0.0.1',
                        'instance_id': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                        'instance_name': 'instance001',
                        'id': 1,
                        'pool': 'nova'},
                        {'propject_id': None,
                        'ip': '10.10.10.11',
                        'fixed_ip': None,
                        'instance_id': None,
                        'instance_name': None,
                        'id': 2,
                        'pool': 'nova'},
                        {'propject_id': None,
                         'id': 3,
                         'ip': '10.10.10.12',
                         'fixed_ip': None,
                         'instance_id': None,
                         'instance_name': None,
                         'pool': 'nova'}]}
        self.assertEqual(res_dict, response)

    def test_floating_ips_list_policy(self):
        req = fakes.HTTPRequest.blank(
                            '/v2/fake/os-floating-ips')
        self.assertRaises(exception.PolicyNotAuthorized,
                          self.controller.index, req)


class FloatingIpSerializerTest(test.TestCase):

    def test_index_serializer(self):
        serializer = floating_ips_search.FloatingIPsTemplate()
        text = serializer.serialize(dict(
                floating_ips=[
                    dict(instance_id=1,
                         ip='10.10.10.10',
                         fixed_ip='10.0.0.1',
                         id=1),
                    dict(instance_id=None,
                         ip='10.10.10.11',
                         fixed_ip=None,
                         id=2)]))

        tree = etree.fromstring(text)

        self.assertEqual('floating_ips', tree.tag)
        self.assertEqual(2, len(tree))
        self.assertEqual('floating_ip', tree[0].tag)
        self.assertEqual('floating_ip', tree[1].tag)
        self.assertEqual('1', tree[0].get('instance_id'))
        self.assertEqual('None', tree[1].get('instance_id'))
        self.assertEqual('10.10.10.10', tree[0].get('ip'))
        self.assertEqual('10.10.10.11', tree[1].get('ip'))
        self.assertEqual('10.0.0.1', tree[0].get('fixed_ip'))
        self.assertEqual('None', tree[1].get('fixed_ip'))
        self.assertEqual('1', tree[0].get('id'))
        self.assertEqual('2', tree[1].get('id'))
