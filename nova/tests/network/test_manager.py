# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Rackspace
# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import mox
import shutil
import sys
import tempfile

from nova import context
from nova import db
from nova.db.sqlalchemy import models
from nova import exception
from nova import flags
from nova.network import linux_net
from nova.network import manager as network_manager
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova.openstack.common import rpc
import nova.policy
from nova import quota
from nova import test
from nova.tests import fake_network
from nova.tests import matchers
from nova import utils


LOG = logging.getLogger(__name__)

QUOTAS = quota.QUOTAS

HOST = "testhost"
FAKEUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


networks = [{'id': 0,
             'uuid': FAKEUUID,
             'label': 'test0',
             'injected': False,
             'multi_host': False,
             'cidr': '192.168.0.0/24',
             'cidr_v6': '2001:db8::/64',
             'gateway_v6': '2001:db8::1',
             'netmask_v6': '64',
             'netmask': '255.255.255.0',
             'bridge': 'fa0',
             'bridge_interface': 'fake_fa0',
             'gateway': '192.168.0.1',
             'broadcast': '192.168.0.255',
             'dns1': '192.168.0.1',
             'dns2': '192.168.0.2',
             'vlan': None,
             'host': HOST,
             'project_id': 'fake_project',
             'vpn_public_address': '192.168.0.2',
             'vpn_public_port': '22',
             'vpn_private_address': '10.0.0.2'},
            {'id': 1,
             'uuid': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
             'label': 'test1',
             'injected': False,
             'multi_host': False,
             'cidr': '192.168.1.0/24',
             'cidr_v6': '2001:db9::/64',
             'gateway_v6': '2001:db9::1',
             'netmask_v6': '64',
             'netmask': '255.255.255.0',
             'bridge': 'fa1',
             'bridge_interface': 'fake_fa1',
             'gateway': '192.168.1.1',
             'broadcast': '192.168.1.255',
             'dns1': '192.168.0.1',
             'dns2': '192.168.0.2',
             'vlan': None,
             'host': HOST,
             'project_id': 'fake_project',
             'vpn_public_address': '192.168.1.2',
             'vpn_public_port': '22',
             'vpn_private_address': '10.0.0.2'}]

fixed_ips = [{'id': 0,
              'network_id': FAKEUUID,
              'address': '192.168.0.100',
              'instance_uuid': 0,
              'allocated': False,
              'virtual_interface_id': 0,
              'floating_ips': []},
             {'id': 0,
              'network_id': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
              'address': '192.168.1.100',
              'instance_uuid': 0,
              'allocated': False,
              'virtual_interface_id': 0,
              'floating_ips': []}]


flavor = {'id': 0,
          'rxtx_cap': 3}


floating_ip_fields = {'id': 0,
                      'address': '192.168.10.100',
                      'pool': 'nova',
                      'interface': 'eth0',
                      'fixed_ip_id': 0,
                      'project_id': None,
                      'auto_assigned': False}

vifs = [{'id': 0,
         'address': 'DE:AD:BE:EF:00:00',
         'uuid': '00000000-0000-0000-0000-0000000000000000',
         'network_id': 0,
         'instance_uuid': 0},
        {'id': 1,
         'address': 'DE:AD:BE:EF:00:01',
         'uuid': '00000000-0000-0000-0000-0000000000000001',
         'network_id': 1,
         'instance_uuid': 0},
        {'id': 2,
         'address': 'DE:AD:BE:EF:00:02',
         'uuid': '00000000-0000-0000-0000-0000000000000002',
         'network_id': 2,
         'instance_uuid': 0}]


Fake_Network_QoS_Config = {
    "policy":
    {
            "key": "vcpu",
            "private":
            {
                        "fixed_ip":
                        {
                                        "egress": True,
                                        "ingress": True
                                    },
                        "floating_ip":
                        {
                                        "egress": True,
                                        "ingress": True
                                    }
                    },
            "public":
            {
                        "floating_ip":
                        {
                                        "egress": True,
                                        "ingress": True
                                    },
                        "default_snat":
                        {
                                        "egress": True,
                                        "shared_ingress": True
                                    }
                    }
        },
    "shaping":
    {
            "public":
            {
                        "1":
                        {
                                        "rate": 5,
                                        "ceil": 1000,
                                        "prio": 4
                                    },
                        "default_snat":
                        {
                                        "shared_ingress":
                                        {
                                                            "rate": 5,
                                                            "ceil": 1000,
                                                            "prio": 5
                                                        }
                                    },
                        "default":
                        {
                                        "rate": 5,
                                        "ceil": 1000,
                                        "prio": 4
                                    }
                    },
            "private":
            {
                        "1":
                        {
                                        "rate": 20,
                                        "ceil": 200,
                                        "prio": 4
                                    },
                        "2":
                        {
                                        "rate": 40,
                                        "ceil": 200,
                                        "prio": 4
                                    },
                        "4":
                        {
                                        "rate": 80,
                                        "ceil": 400,
                                        "prio": 4
                                    },
                        "8":
                        {
                                        "rate": 160,
                                        "ceil": 400,
                                        "prio": 4
                                    },
                        "16":
                        {
                                        "rate": 320,
                                        "ceil": 1000,
                                        "prio": 4
                                    },
                        "32":
                        {
                                        "rate": 640,
                                        "ceil": 1000,
                                        "prio": 4
                                    },
                        "default":
                        {
                                        "rate": 20,
                                        "ceil": 200,
                                        "prio": 4
                                    }
                    }
    }
}

FLAGS = flags.FLAGS


def network_qos_opt():
    private_band = int(FLAGS.network_qos_host_private_bandwidth *
                           FLAGS.network_qos_private_allocation_ratio -
                           FLAGS.reserved_host_network_private_bandwidth)
    public_band = int(FLAGS.network_qos_host_public_bandwidth *
                            FLAGS.network_qos_public_allocation_ratio -
                            FLAGS.reserved_host_network_public_bandwidth)
    eth0 = FLAGS.network_qos_physical_interface
    network_phy_interface = ','.join(eth0)
    eth1 = FLAGS.private_interfaces
    network_pvt_interface = ','.join(eth1)
    network_qos_opts = dict(
        ifb0=FLAGS.network_qos_egress_interface,
        ifb1=FLAGS.network_qos_ingress_interface,
        phy_inf=network_phy_interface,
        pvt_inf=network_pvt_interface,
        fwmark=FLAGS.tc_private_to_public_fwmark,
        pvt_to_pub_dst=FLAGS.private_to_public_dst,
        pub_band=public_band,
        pvt_band=private_band,
        tc_mark=FLAGS.tc_fw_mask,
        tc_class_pvt_mask=FLAGS.tc_class_pvt_mask,
        tc_class_pub_mask=FLAGS.tc_class_pub_mask,
        tc_filter_pvt_mask=FLAGS.tc_filter_pvt_mask,
        tc_filter_pub_mask=FLAGS.tc_filter_pub_mask,
        tc_filter_snat_mask=FLAGS.tc_filter_snat_mask,
        tc_private_to_public_pref=FLAGS.tc_private_to_public_pref,
        pvt_to_pub_whitelist_setname=FLAGS.private_to_public_whitelist_setname,
        private_to_public_whitelist_dst=FLAGS.private_to_public_whitelist_dst,
        network_qos_whitelist=FLAGS.network_qos_whitelist
        )

    return network_qos_opts


class FlatNetworkTestCase(test.TestCase):
    def setUp(self):
        super(FlatNetworkTestCase, self).setUp()
        self.tempdir = tempfile.mkdtemp()
        self.flags(logdir=self.tempdir)
        self.network = network_manager.FlatManager(host=HOST)
        temp = importutils.import_object('nova.network.minidns.MiniDNS')
        self.network.instance_dns_manager = temp
        self.network.instance_dns_domain = ''
        self.network.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=False)

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super(FlatNetworkTestCase, self).tearDown()

    def test_get_instance_nw_info(self):
        fake_get_instance_nw_info = fake_network.fake_get_instance_nw_info

        nw_info = fake_get_instance_nw_info(self.stubs, 0, 2)
        self.assertFalse(nw_info)

        nw_info = fake_get_instance_nw_info(self.stubs, 1, 2)

        for i, (nw, info) in enumerate(nw_info):
            nid = i + 1
            check = {'bridge': 'fake_br%d' % nid,
                     'cidr': '192.168.%s.0/24' % nid,
                     'cidr_v6': '2001:db8:0:%x::/64' % nid,
                     'id': '00000000-0000-0000-0000-00000000000000%02d' % nid,
                     'multi_host': False,
                     'injected': False,
                     'bridge_interface': None,
                     'vlan': None}

            self.assertThat(nw, matchers.DictMatches(check))

            check = {'broadcast': '192.168.%d.255' % nid,
                     'dhcp_server': '192.168.1.1',
                     'dns': ['192.168.%d.3' % nid, '192.168.%d.4' % nid],
                     'gateway': '192.168.%d.1' % nid,
                     'gateway_v6': 'fe80::def',
                     'ip6s': 'DONTCARE',
                     'ips': 'DONTCARE',
                     'label': 'test%d' % nid,
                     'mac': 'DE:AD:BE:EF:00:%02x' % nid,
                     'rxtx_cap': 30,
                     'vif_uuid':
                        '00000000-0000-0000-0000-00000000000000%02d' % nid,
                     'should_create_vlan': False,
                     'should_create_bridge': False}
            self.assertThat(info, matchers.DictMatches(check))

            check = [{'enabled': 'DONTCARE',
                      'ip': '2001:db8:0:1::%x' % nid,
                      'netmask': 64,
                      'gateway': 'fe80::def'}]
            self.assertThat(info['ip6s'], matchers.DictListMatches(check))

            num_fixed_ips = len(info['ips'])
            check = [{'enabled': 'DONTCARE',
                      'ip': '192.168.%d.%03d' % (nid, ip_num + 99),
                      'netmask': '255.255.255.0',
                      'gateway': '192.168.%d.1' % nid}
                      for ip_num in xrange(1, num_fixed_ips + 1)]
            self.assertThat(info['ips'], matchers.DictListMatches(check))

    def test_validate_networks(self):
        self.mox.StubOutWithMock(db, 'network_get')
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')
        self.mox.StubOutWithMock(db, 'fixed_ip_get_by_address')

        requested_networks = [('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                               '192.168.1.100')]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)
        db.network_get(mox.IgnoreArg(),
                       mox.IgnoreArg(),
                       project_only=mox.IgnoreArg()).AndReturn(networks[1])

        ip = fixed_ips[1].copy()
        ip['instance_uuid'] = None
        db.fixed_ip_get_by_address(mox.IgnoreArg(),
                                   mox.IgnoreArg()).AndReturn(ip)

        self.mox.ReplayAll()
        self.network.validate_networks(self.context, requested_networks)

    def test_validate_reserved(self):
        context_admin = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)
        nets = self.network.create_networks(context_admin, 'fake',
                                       '192.168.0.0/24', False, 1,
                                       256, None, None, None, None, None)
        self.assertEqual(1, len(nets))
        network = nets[0]
        self.assertEqual(3, db.network_count_reserved_ips(context_admin,
                        network['id']))

    def test_validate_networks_none_requested_networks(self):
        self.network.validate_networks(self.context, None)

    def test_validate_networks_empty_requested_networks(self):
        requested_networks = []
        self.mox.ReplayAll()

        self.network.validate_networks(self.context, requested_networks)

    def test_validate_networks_invalid_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')
        requested_networks = [(1, "192.168.0.100.1")]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)
        self.mox.ReplayAll()

        self.assertRaises(exception.FixedIpInvalid,
                          self.network.validate_networks, self.context,
                          requested_networks)

    def test_validate_networks_empty_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')

        requested_networks = [(1, "")]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)
        self.mox.ReplayAll()

        self.assertRaises(exception.FixedIpInvalid,
                          self.network.validate_networks,
                          self.context, requested_networks)

    def test_validate_networks_none_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')

        requested_networks = [(1, None)]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)
        self.mox.ReplayAll()

        self.network.validate_networks(self.context, requested_networks)

    def test_add_fixed_ip_instance_using_id_without_vpn(self):
        self.mox.StubOutWithMock(db, 'network_get')
        self.mox.StubOutWithMock(db, 'network_update')
        self.mox.StubOutWithMock(db, 'fixed_ip_associate_pool')
        self.mox.StubOutWithMock(db, 'instance_get')
        self.mox.StubOutWithMock(db,
                              'virtual_interface_get_by_instance_and_network')
        self.mox.StubOutWithMock(db, 'fixed_ip_update')

        db.fixed_ip_update(mox.IgnoreArg(),
                           mox.IgnoreArg(),
                           mox.IgnoreArg())
        db.virtual_interface_get_by_instance_and_network(mox.IgnoreArg(),
                mox.IgnoreArg(), mox.IgnoreArg()).AndReturn({'id': 0})

        db.instance_get(self.context,
                        1).AndReturn({'display_name': HOST,
                                      'uuid': 'test-00001'})
        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'security_groups':
                                                             [{'id': 0}]})
        db.fixed_ip_associate_pool(mox.IgnoreArg(),
                                   mox.IgnoreArg(),
                                   mox.IgnoreArg()).AndReturn('192.168.0.101')
        db.network_get(mox.IgnoreArg(),
                       mox.IgnoreArg(),
                       project_only=mox.IgnoreArg()).AndReturn(networks[0])
        db.network_update(mox.IgnoreArg(), mox.IgnoreArg(), mox.IgnoreArg())
        self.mox.ReplayAll()
        self.network.add_fixed_ip_to_instance(self.context, 1, HOST,
                                              networks[0]['id'])

    def test_add_fixed_ip_instance_using_uuid_without_vpn(self):
        self.mox.StubOutWithMock(db, 'network_get_by_uuid')
        self.mox.StubOutWithMock(db, 'network_update')
        self.mox.StubOutWithMock(db, 'fixed_ip_associate_pool')
        self.mox.StubOutWithMock(db, 'instance_get')
        self.mox.StubOutWithMock(db,
                              'virtual_interface_get_by_instance_and_network')
        self.mox.StubOutWithMock(db, 'fixed_ip_update')

        db.fixed_ip_update(mox.IgnoreArg(),
                           mox.IgnoreArg(),
                           mox.IgnoreArg())
        db.virtual_interface_get_by_instance_and_network(mox.IgnoreArg(),
                mox.IgnoreArg(), mox.IgnoreArg()).AndReturn({'id': 0})

        db.instance_get(self.context,
                        1).AndReturn({'display_name': HOST,
                                      'uuid': 'test-00001'})
        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'security_groups':
                                                             [{'id': 0}]})
        db.fixed_ip_associate_pool(mox.IgnoreArg(),
                                   mox.IgnoreArg(),
                                   mox.IgnoreArg()).AndReturn('192.168.0.101')
        db.network_get_by_uuid(mox.IgnoreArg(),
                               mox.IgnoreArg()).AndReturn(networks[0])
        db.network_update(mox.IgnoreArg(), mox.IgnoreArg(), mox.IgnoreArg())
        self.mox.ReplayAll()
        self.network.add_fixed_ip_to_instance(self.context, 1, HOST,
                                              networks[0]['uuid'])

    def test_mini_dns_driver(self):
        zone1 = "example.org"
        zone2 = "example.com"
        driver = self.network.instance_dns_manager
        driver.create_entry("hostone", "10.0.0.1", "A", zone1)
        driver.create_entry("hosttwo", "10.0.0.2", "A", zone1)
        driver.create_entry("hostthree", "10.0.0.3", "A", zone1)
        driver.create_entry("hostfour", "10.0.0.4", "A", zone1)
        driver.create_entry("hostfive", "10.0.0.5", "A", zone2)

        driver.delete_entry("hostone", zone1)
        driver.modify_address("hostfour", "10.0.0.1", zone1)
        driver.modify_address("hostthree", "10.0.0.1", zone1)
        names = driver.get_entries_by_address("10.0.0.1", zone1)
        self.assertEqual(len(names), 2)
        self.assertIn('hostthree', names)
        self.assertIn('hostfour', names)

        names = driver.get_entries_by_address("10.0.0.5", zone2)
        self.assertEqual(len(names), 1)
        self.assertIn('hostfive', names)

        addresses = driver.get_entries_by_name("hosttwo", zone1)
        self.assertEqual(len(addresses), 1)
        self.assertIn('10.0.0.2', addresses)

        self.assertRaises(exception.InvalidInput,
                driver.create_entry,
                "hostname",
                "10.10.10.10",
                "invalidtype",
                zone1)

    def test_instance_dns(self):
        fixedip = '192.168.0.101'
        self.mox.StubOutWithMock(db, 'network_get')
        self.mox.StubOutWithMock(db, 'network_update')
        self.mox.StubOutWithMock(db, 'fixed_ip_associate_pool')
        self.mox.StubOutWithMock(db, 'instance_get')
        self.mox.StubOutWithMock(db, 'instance_get_by_uuid')
        self.mox.StubOutWithMock(db,
                              'virtual_interface_get_by_instance_and_network')
        self.mox.StubOutWithMock(db, 'fixed_ip_update')

        db.fixed_ip_update(mox.IgnoreArg(),
                           mox.IgnoreArg(),
                           mox.IgnoreArg())
        db.virtual_interface_get_by_instance_and_network(mox.IgnoreArg(),
                mox.IgnoreArg(), mox.IgnoreArg()).AndReturn({'id': 0})

        db.instance_get(self.context,
                        1).AndReturn({'display_name': HOST,
                                      'uuid': 'test-00001'})
        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'security_groups':
                                                             [{'id': 0}]})

        db.fixed_ip_associate_pool(mox.IgnoreArg(),
                                   mox.IgnoreArg(),
                                   mox.IgnoreArg()).AndReturn(fixedip)
        db.network_get(mox.IgnoreArg(),
                       mox.IgnoreArg(),
                       project_only=mox.IgnoreArg()).AndReturn(networks[0])
        db.network_update(mox.IgnoreArg(), mox.IgnoreArg(), mox.IgnoreArg())

        self.mox.ReplayAll()
        self.network.add_fixed_ip_to_instance(self.context, 1, HOST,
                                              networks[0]['id'])
        instance_manager = self.network.instance_dns_manager
        addresses = instance_manager.get_entries_by_name(HOST,
                                             self.network.instance_dns_domain)
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0], fixedip)
        addresses = instance_manager.get_entries_by_name('test-00001',
                                              self.network.instance_dns_domain)
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0], fixedip)


class FlatDHCPNetworkTestCase(test.TestCase):
    def setUp(self):
        super(FlatDHCPNetworkTestCase, self).setUp()
        self.network = network_manager.FlatDHCPManager(host=HOST)
        self.network.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

    def test_add_fixed_ip_to_ipset(self):
        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        def fake_list(*args, **kwargs):
            return ['test', 'test2']

        def fake_members(*args, **kwargs):
            return ['192.168.1.11']

        self.mox.StubOutWithMock(db, 'fixed_ip_get_by_address')
        self.mox.StubOutWithMock(db, 'instance_get_by_uuid')
        self.mox.StubOutWithMock(db, 'instance_get_all_by_project')
        self.mox.StubOutWithMock(db, 'fixed_ip_get_by_instance')

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.ipsets_manager, 'list', fake_list)
        self.stubs.Set(linux_net.ipsets_manager, 'members', fake_members)
        self.executes = []

        db.fixed_ip_get_by_address(mox.IgnoreArg(),
                                   mox.IgnoreArg()).\
                                   AndReturn({'address': '192.168.0.1',
                                              'instance_uuid': 'testvm'})
        db.instance_get_by_uuid(mox.IgnoreArg(),
                                mox.IgnoreArg()).\
                                AndReturn({'project_id': 'testproject',
                                           'uuid': 'testvm'})
        db.instance_get_all_by_project(mox.IgnoreArg(),
                                       mox.IgnoreArg()).\
                                       AndReturn([
                                            {'uuid': 'vm1'},
                                            {'uuid': 'vm2'},
                                        ])
        db.fixed_ip_get_by_instance(mox.IgnoreArg(),
                                    mox.IgnoreArg()).\
                                    AndReturn([{'address': '192.168.1.10',
                                                'instance_uuid':'vm1'}])
        db.fixed_ip_get_by_instance(mox.IgnoreArg(),
                                    mox.IgnoreArg()).\
                                    AndReturn([{'address': '192.168.1.11',
                                                'instance_uuid':'vm2'}])

        self.mox.ReplayAll()
        self.network.add_fixed_ip_to_ipset(self.context, '192.168.0.1')

        expected = [('ipset', 'create', 'testproject',
                     'bitmap:ip', 'range', '10.0.0.0/22'),
                    ('ipset', 'add', 'testproject', '192.168.1.10'),
                    ('ipset', 'add', 'testproject', '192.168.0.1')]
        self.assertEqual(self.executes, expected)

    def del_fixed_ip_from_ipset(self):
        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        def fake_list(*args, **kwargs):
            return ['testproject']

        def fake_members(*args, **kwargs):
            return ['192.168.1.10', '192.168.1.11']

        self.mox.StubOutWithMock(db, 'fixed_ip_get_by_address')
        self.mox.StubOutWithMock(db, 'instance_get_by_uuid')

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.ipsets_manager, 'list', fake_list)
        self.stubs.Set(linux_net.ipsets_manager, 'members', fake_members)
        self.executes = []

        db.fixed_ip_get_by_address(mox.IgnoreArg(),
                                   mox.IgnoreArg()).\
                                   AndReturn({'address': '192.168.1.10',
                                              'instance_uuid': 'testvm'})
        db.instance_get_by_uuid(mox.IgnoreArg(),
                                mox.IgnoreArg()).\
                                AndReturn({'project_id': 'testproject',
                                           'uuid': 'testvm'})

        self.mox.ReplayAll()
        self.network.del_fixed_ip_from_ipset(self.context, '192.168.1.10')

        expected = [('ipset', 'del', 'testproject', '192.168.1.10')]
        self.assertEqual(self.executes, expected)


class VlanNetworkTestCase(test.TestCase):
    def setUp(self):
        super(VlanNetworkTestCase, self).setUp()
        self.network = network_manager.VlanManager(host=HOST)
        self.network.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=False)

    def test_vpn_allocate_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'instance_get')
        self.mox.StubOutWithMock(db, 'fixed_ip_associate')
        self.mox.StubOutWithMock(db, 'fixed_ip_update')
        self.mox.StubOutWithMock(db,
                              'virtual_interface_get_by_instance_and_network')

        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'uuid': '42'})
        db.fixed_ip_associate(mox.IgnoreArg(),
                              mox.IgnoreArg(),
                              mox.IgnoreArg(),
                              mox.IgnoreArg(),
                              reserved=True).AndReturn('192.168.0.1')
        db.fixed_ip_update(mox.IgnoreArg(),
                           mox.IgnoreArg(),
                           mox.IgnoreArg())
        db.virtual_interface_get_by_instance_and_network(mox.IgnoreArg(),
                mox.IgnoreArg(), mox.IgnoreArg()).AndReturn({'id': 0})
        self.mox.ReplayAll()

        network = dict(networks[0])
        network['vpn_private_address'] = '192.168.0.2'
        self.network.allocate_fixed_ip(None, 0, network, vpn=True)

    def test_vpn_allocate_fixed_ip_no_network_id(self):
        network = dict(networks[0])
        network['vpn_private_address'] = '192.168.0.2'
        network['id'] = None
        instance = db.instance_create(self.context, {})
        context_admin = context.RequestContext('testuser', 'testproject',
                is_admin=True)
        self.assertRaises(exception.FixedIpNotFoundForNetwork,
                self.network.allocate_fixed_ip,
                context_admin,
                instance['id'],
                network,
                vpn=True)

    def test_allocate_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'fixed_ip_associate_pool')
        self.mox.StubOutWithMock(db, 'fixed_ip_update')
        self.mox.StubOutWithMock(db,
                              'virtual_interface_get_by_instance_and_network')
        self.mox.StubOutWithMock(db, 'instance_get')

        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'uuid': FAKEUUID})
        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'security_groups':
                                                             [{'id': 0}]})
        db.fixed_ip_associate_pool(mox.IgnoreArg(),
                                   mox.IgnoreArg(),
                                   mox.IgnoreArg()).AndReturn('192.168.0.1')
        db.fixed_ip_update(mox.IgnoreArg(),
                           mox.IgnoreArg(),
                           mox.IgnoreArg())
        db.virtual_interface_get_by_instance_and_network(mox.IgnoreArg(),
                mox.IgnoreArg(), mox.IgnoreArg()).AndReturn({'id': 0})
        self.mox.ReplayAll()

        network = dict(networks[0])
        network['vpn_private_address'] = '192.168.0.2'
        self.network.allocate_fixed_ip(self.context, 0, network)

    def test_create_networks_too_big(self):
        self.assertRaises(ValueError, self.network.create_networks, None,
                          num_networks=4094, vlan_start=1)

    def test_create_networks_too_many(self):
        self.assertRaises(ValueError, self.network.create_networks, None,
                          num_networks=100, vlan_start=1,
                          cidr='192.168.0.1/24', network_size=100)

    def test_validate_networks(self):
        def network_get(_context, network_id, project_only='allow_none'):
            return networks[network_id]

        self.stubs.Set(db, 'network_get', network_get)
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')
        self.mox.StubOutWithMock(db, "fixed_ip_get_by_address")

        requested_networks = [("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                               "192.168.1.100")]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)

        fixed_ips[1]['network_id'] = networks[1]['id']
        fixed_ips[1]['instance_uuid'] = None
        db.fixed_ip_get_by_address(mox.IgnoreArg(),
                                    mox.IgnoreArg()).AndReturn(fixed_ips[1])

        self.mox.ReplayAll()
        self.network.validate_networks(self.context, requested_networks)

    def test_validate_networks_none_requested_networks(self):
        self.network.validate_networks(self.context, None)

    def test_validate_networks_empty_requested_networks(self):
        requested_networks = []
        self.mox.ReplayAll()

        self.network.validate_networks(self.context, requested_networks)

    def test_validate_networks_invalid_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')
        requested_networks = [(1, "192.168.0.100.1")]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)
        self.mox.ReplayAll()

        self.assertRaises(exception.FixedIpInvalid,
                          self.network.validate_networks, self.context,
                          requested_networks)

    def test_validate_networks_empty_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')

        requested_networks = [(1, "")]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)
        self.mox.ReplayAll()

        self.assertRaises(exception.FixedIpInvalid,
                          self.network.validate_networks,
                          self.context, requested_networks)

    def test_validate_networks_none_fixed_ip(self):
        self.mox.StubOutWithMock(db, 'network_get_all_by_uuids')

        requested_networks = [(1, None)]
        db.network_get_all_by_uuids(mox.IgnoreArg(), mox.IgnoreArg(),
                project_only=mox.IgnoreArg()).AndReturn(networks)
        self.mox.ReplayAll()
        self.network.validate_networks(self.context, requested_networks)

    def test_floating_ip_owned_by_project(self):
        ctxt = context.RequestContext('testuser', 'testproject',
                                      is_admin=False)

        # raises because floating_ip project_id is None
        floating_ip = {'address': '10.0.0.1',
                       'project_id': None}
        self.assertRaises(exception.NotAuthorized,
                          self.network._floating_ip_owned_by_project,
                          ctxt,
                          floating_ip)

        # raises because floating_ip project_id is not equal to ctxt project_id
        floating_ip = {'address': '10.0.0.1',
                       'project_id': ctxt.project_id + '1'}
        self.assertRaises(exception.NotAuthorized,
                          self.network._floating_ip_owned_by_project,
                          ctxt,
                          floating_ip)

        # does not raise (floating ip is owned by ctxt project)
        floating_ip = {'address': '10.0.0.1',
                       'project_id': ctxt.project_id}
        self.network._floating_ip_owned_by_project(ctxt, floating_ip)

        ctxt = context.RequestContext(None, None,
                                      is_admin=True)

        # does not raise (ctxt is admin)
        floating_ip = {'address': '10.0.0.1',
                       'project_id': None}
        self.network._floating_ip_owned_by_project(ctxt, floating_ip)

        # does not raise (ctxt is admin)
        floating_ip = {'address': '10.0.0.1',
                       'project_id': 'testproject'}
        self.network._floating_ip_owned_by_project(ctxt, floating_ip)

    def test_allocate_floating_ip(self):
        ctxt = context.RequestContext('testuser', 'testproject',
                                      is_admin=False)

        def fake_allocate_address(*args, **kwargs):
            return {'address': '10.0.0.1', 'project_id': ctxt.project_id}

        self.stubs.Set(self.network.db, 'floating_ip_allocate_address',
                       fake_allocate_address)

        self.network.allocate_floating_ip(ctxt, ctxt.project_id)

    def test_deallocate_floating_ip(self):
        ctxt = context.RequestContext('testuser', 'testproject',
                                      is_admin=False)

        def fake1(*args, **kwargs):
            pass

        def fake2(*args, **kwargs):
            return {'address': '10.0.0.1', 'fixed_ip_id': 1}

        def fake3(*args, **kwargs):
            return {'address': '10.0.0.1', 'fixed_ip_id': None,
                    'project_id': ctxt.project_id}

        self.stubs.Set(self.network.db, 'floating_ip_deallocate', fake1)
        self.stubs.Set(self.network, '_floating_ip_owned_by_project', fake1)

        # this time should raise because floating ip is associated to fixed_ip
        self.stubs.Set(self.network.db, 'floating_ip_get_by_address', fake2)
        self.assertRaises(exception.FloatingIpAssociated,
                          self.network.deallocate_floating_ip,
                          ctxt,
                          mox.IgnoreArg())

        # this time should not raise
        self.stubs.Set(self.network.db, 'floating_ip_get_by_address', fake3)
        self.network.deallocate_floating_ip(ctxt, ctxt.project_id)

    def test_associate_floating_ip(self):
        ctxt = context.RequestContext('testuser', 'testproject',
                                      is_admin=False)

        def fake1(*args, **kwargs):
            return '10.0.0.1'

        # floating ip that's already associated
        def fake2(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'fixed_ip_id': 1}

        # floating ip that isn't associated
        def fake3(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'fixed_ip_id': None}

        # fixed ip with remote host
        def fake4(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'network_id': 'blah',
                    'instance_uuid': 'fake_uuid'}

        def fake4_network(*args, **kwargs):
            return {'multi_host': False, 'host': 'jibberjabber'}

        # fixed ip with local host
        def fake5(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'network_id': 'blahblah',
                    'instance_uuid': 'fake_uuid'}

        def fake5_network(*args, **kwargs):
            return {'multi_host': False, 'host': 'testhost'}

        def fake6(*args, **kwargs):
            self.local = False

        def fake7(*args, **kwargs):
            self.local = True

        def fake8(*args, **kwargs):
            raise exception.ProcessExecutionError('',
                    'Cannot find device "em0"\n')

        def fake9(*args, **kwargs):
            raise test.TestingException()

        def fake10(*args, **kwargs):
            return {'host': 'fake_host'}

        self.stubs.Set(self.network,
                       'associate_floating_ip',
                       self.network.do_associate_floating_ip)

        # raises because interface doesn't exist
        self.stubs.Set(self.network.db,
                       'floating_ip_fixed_ip_associate',
                       fake1)
        self.stubs.Set(self.network.db, 'floating_ip_disassociate', fake1)
        self.stubs.Set(self.network.driver, 'bind_floating_ip', fake8)
        self.assertRaises(exception.NoFloatingIpInterface,
                          self.network._associate_floating_ip,
                          ctxt,
                          mox.IgnoreArg(),
                          mox.IgnoreArg(),
                          mox.IgnoreArg(),
                          mox.IgnoreArg(),
                          mox.IgnoreArg())

        self.stubs.Set(self.network, '_floating_ip_owned_by_project', fake1)

        # raises because floating_ip is already associated to a fixed_ip
        self.stubs.Set(self.network.db, 'floating_ip_get_by_address', fake2)
        self.stubs.Set(self.network, 'disassociate_floating_ip', fake9)

        self.stubs.Set(self.network.db, 'instance_get_by_uuid', fake10)

        def fake_fixed_ip_get(context, fixed_ip_id):
            return {'instance_uuid': 'fake_uuid'}

        self.stubs.Set(self.network.db, 'fixed_ip_get', fake_fixed_ip_get)

        self.assertRaises(test.TestingException,
                          self.network.associate_floating_ip,
                          ctxt,
                          mox.IgnoreArg(),
                          mox.IgnoreArg())

        self.stubs.Set(self.network.db, 'floating_ip_get_by_address', fake3)

        # does not raise and makes call remotely
        self.local = True
        self.stubs.Set(self.network.db, 'fixed_ip_get_by_address', fake4)
        self.stubs.Set(self.network.db, 'network_get', fake4_network)
        self.stubs.Set(rpc, 'call', fake6)
        self.network.associate_floating_ip(ctxt, mox.IgnoreArg(),
                                                 mox.IgnoreArg())
        self.assertFalse(self.local)

        # does not raise and makes call locally
        self.local = False
        self.stubs.Set(self.network.db, 'fixed_ip_get_by_address', fake5)
        self.stubs.Set(self.network.db, 'network_get', fake5_network)
        self.stubs.Set(self.network, '_associate_floating_ip', fake7)
        self.network.associate_floating_ip(ctxt, mox.IgnoreArg(),
                                                 mox.IgnoreArg())
        self.assertTrue(self.local)

    def test_floating_ip_init_host(self):

        def get_all_by_host(_context, _host):
            return [{'interface': 'foo',
                     'address': 'foo'},
                    {'interface': 'fakeiface',
                     'address': 'fakefloat',
                     'fixed_ip_id': 1},
                    {'interface': 'bar',
                     'address': 'bar',
                     'fixed_ip_id': 2}]

        def get_all_by_host_wo_interface(_context, _host):
            return [{'interface': None,
                     'address': 'foo'},
                    {'interface': None,
                     'address': 'fakefloat',
                     'fixed_ip_id': 1},
                    {'interface': None,
                     'address': 'bar',
                     'fixed_ip_id': 2}]

        self.stubs.Set(self.network.db, 'floating_ip_get_all_by_host',
                       get_all_by_host)

        def fixed_ip_get(_context, fixed_ip_id):
            if fixed_ip_id == 1:
                return {'address': 'fakefixed'}
            raise exception.FixedIpNotFound()
        self.stubs.Set(self.network.db, 'fixed_ip_get', fixed_ip_get)

        self.mox.StubOutWithMock(self.network.l3driver, 'add_floating_ip')
        self.flags(public_interface=False)
        self.network.l3driver.add_floating_ip('fakefloat',
                                              'fakefixed',
                                              'fakeiface')
        self.mox.ReplayAll()
        self.network.init_host_floating_ips()
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

        self.mox.StubOutWithMock(self.network.l3driver, 'add_floating_ip')
        self.flags(public_interface='fooiface')
        self.network.l3driver.add_floating_ip('fakefloat',
                                              'fakefixed',
                                              'fakeiface')
        self.mox.ReplayAll()
        self.network.init_host_floating_ips()
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

        self.stubs.Set(self.network.db, 'floating_ip_get_all_by_host',
                       get_all_by_host_wo_interface)

        self.mox.StubOutWithMock(self.network.l3driver, 'add_floating_ip')
        self.flags(public_interface='fooiface')
        self.network.l3driver.add_floating_ip('fakefloat',
                                              'fakefixed',
                                              'fooiface')
        self.mox.ReplayAll()
        self.network.init_host_floating_ips()
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_disassociate_floating_ip(self):
        ctxt = context.RequestContext('testuser', 'testproject',
                                      is_admin=False)

        def fake1(*args, **kwargs):
            pass

        # floating ip that isn't associated
        def fake2(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'fixed_ip_id': None}

        # floating ip that is associated
        def fake3(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'fixed_ip_id': 1,
                    'project_id': ctxt.project_id}

        # fixed ip with remote host
        def fake4(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'network_id': 'blah',
                    'instance_uuid': 'fake_uuid'}

        def fake4_network(*args, **kwargs):
            return {'multi_host': False,
                    'host': 'jibberjabber'}

        # fixed ip with local host
        def fake5(*args, **kwargs):
            return {'address': '10.0.0.1',
                    'pool': 'nova',
                    'interface': 'eth0',
                    'network_id': 'blahblah',
                    'instance_uuid': 'fake_uuid'}

        def fake5_network(*args, **kwargs):
            return {'multi_host': False, 'host': 'testhost'}

        def fake6(*args, **kwargs):
            self.local = False

        def fake7(*args, **kwargs):
            self.local = True

        def fake10(*args, **kwargs):
            return {'host': 'fake_host'}

        self.stubs.Set(self.network, 'disassociate_floating_ip',
                       self.network.do_disassociate_floating_ip)
        self.stubs.Set(self.network, '_floating_ip_owned_by_project', fake1)

        # raises because floating_ip is not associated to a fixed_ip
        self.stubs.Set(self.network.db, 'floating_ip_get_by_address', fake2)
        self.assertRaises(exception.FloatingIpNotAssociated,
                          self.network.disassociate_floating_ip,
                          ctxt,
                          mox.IgnoreArg())

        self.stubs.Set(self.network.db, 'floating_ip_get_by_address', fake3)
        self.stubs.Set(self.network.db, 'instance_get_by_uuid', fake10)

        # does not raise and makes call remotely
        self.local = True
        self.stubs.Set(self.network.db, 'fixed_ip_get', fake4)
        self.stubs.Set(self.network.db, 'network_get', fake4_network)
        self.stubs.Set(rpc, 'call', fake6)
        self.network.disassociate_floating_ip(ctxt, mox.IgnoreArg())
        self.assertFalse(self.local)

        # does not raise and makes call locally
        self.local = False
        self.stubs.Set(self.network.db, 'fixed_ip_get', fake5)
        self.stubs.Set(self.network.db, 'network_get', fake5_network)
        self.stubs.Set(self.network, '_disassociate_floating_ip', fake7)
        self.network.disassociate_floating_ip(ctxt, mox.IgnoreArg())
        self.assertTrue(self.local)

    def test_add_fixed_ip_instance_without_vpn_requested_networks(self):
        self.mox.StubOutWithMock(db, 'network_get')
        self.mox.StubOutWithMock(db, 'fixed_ip_associate_pool')
        self.mox.StubOutWithMock(db, 'instance_get')
        self.mox.StubOutWithMock(db,
                              'virtual_interface_get_by_instance_and_network')
        self.mox.StubOutWithMock(db, 'fixed_ip_update')

        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'uuid': FAKEUUID})
        db.fixed_ip_update(mox.IgnoreArg(),
                           mox.IgnoreArg(),
                           mox.IgnoreArg())
        db.virtual_interface_get_by_instance_and_network(mox.IgnoreArg(),
                mox.IgnoreArg(), mox.IgnoreArg()).AndReturn({'id': 0})

        db.instance_get(mox.IgnoreArg(),
                        mox.IgnoreArg()).AndReturn({'security_groups':
                                                             [{'id': 0}],
                                                    'availability_zone': '',
                                                    'uuid': FAKEUUID})
        db.fixed_ip_associate_pool(mox.IgnoreArg(),
                                   mox.IgnoreArg(),
                                   mox.IgnoreArg()).AndReturn('192.168.0.101')
        db.network_get(mox.IgnoreArg(),
                       mox.IgnoreArg(),
                       project_only=mox.IgnoreArg()).AndReturn(networks[0])
        self.mox.ReplayAll()
        self.network.add_fixed_ip_to_instance(self.context, 1, HOST,
                                              networks[0]['id'])

    def test_ip_association_and_allocation_of_other_project(self):
        """Makes sure that we cannot deallocaate or disassociate
        a public ip of other project"""

        def network_get(_context, network_id, project_only="allow_none"):
            return networks[network_id]

        self.stubs.Set(db, 'network_get', network_get)
        self.stubs.Set(self.network, 'associate_floating_ip',
                       self.network.do_associate_floating_ip)
        self.stubs.Set(self.network, 'disassociate_floating_ip',
                       self.network.do_disassociate_floating_ip)

        context1 = context.RequestContext('user', 'project1')
        context2 = context.RequestContext('user', 'project2')

        address = '1.2.3.4'
        float_addr = db.floating_ip_create(context1.elevated(),
                                           {'address': address,
                                            'project_id': context1.project_id})

        instance = db.instance_create(context1,
                                      {'project_id': 'project1'})

        fix_addr = db.fixed_ip_associate_pool(context1.elevated(),
                                              1, instance['uuid'])

        # Associate the IP with non-admin user context
        self.assertRaises(exception.NotAuthorized,
                          self.network.associate_floating_ip,
                          context2,
                          float_addr,
                          fix_addr)

        # Deallocate address from other project
        self.assertRaises(exception.NotAuthorized,
                          self.network.deallocate_floating_ip,
                          context2,
                          float_addr)

        # Now Associates the address to the actual project
        self.network.associate_floating_ip(context1, float_addr, fix_addr)

        # Now try dis-associating from other project
        self.assertRaises(exception.NotAuthorized,
                          self.network.disassociate_floating_ip,
                          context2,
                          float_addr)

        # Clean up the ip addresses
        self.network.disassociate_floating_ip(context1, float_addr)
        self.network.deallocate_floating_ip(context1, float_addr)
        self.network.deallocate_fixed_ip(context1, fix_addr, 'fake')
        db.floating_ip_destroy(context1.elevated(), float_addr)
        db.fixed_ip_disassociate(context1.elevated(), fix_addr)

    def test_deallocate_fixed(self):
        """Verify that release is called properly.

        Ensures https://bugs.launchpad.net/nova/+bug/973442 doesn't return"""

        def network_get(_context, network_id, project_only="allow_none"):
            return networks[network_id]

        self.stubs.Set(db, 'network_get', network_get)

        def vif_get(_context, _vif_id):
            return {'address': 'fake_mac'}

        self.stubs.Set(db, 'virtual_interface_get', vif_get)
        context1 = context.RequestContext('user', 'project1')

        instance = db.instance_create(context1,
                {'project_id': 'project1'})

        elevated = context1.elevated()
        fix_addr = db.fixed_ip_associate_pool(elevated, 1, instance['uuid'])
        values = {'allocated': True,
                  'virtual_interface_id': 3}
        db.fixed_ip_update(elevated, fix_addr, values)
        fixed = db.fixed_ip_get_by_address(elevated, fix_addr)
        network = db.network_get(elevated, fixed['network_id'])

        self.flags(force_dhcp_release=True)
        self.mox.StubOutWithMock(linux_net, 'release_dhcp')
        linux_net.release_dhcp(network['bridge'], fixed['address'], 'fake_mac')
        self.mox.ReplayAll()
        self.network.deallocate_fixed_ip(context1, fix_addr, 'fake')
        fixed = db.fixed_ip_get_by_address(elevated, fix_addr)
        self.assertFalse(fixed['allocated'])

    def test_deallocate_fixed_deleted(self):
        """Verify doesn't deallocate deleted fixed_ip from deleted network"""

        def network_get(_context, network_id, project_only="allow_none"):
            return networks[network_id]

        def teardown_network_on_host(_context, network):
            if network['id'] == 0:
                raise test.TestingException()

        self.stubs.Set(db, 'network_get', network_get)
        self.stubs.Set(self.network, '_teardown_network_on_host',
                       teardown_network_on_host)

        context1 = context.RequestContext('user', 'project1')

        instance = db.instance_create(context1,
                {'project_id': 'project1'})

        elevated = context1.elevated()
        fix_addr = db.fixed_ip_associate_pool(elevated, 1, instance['uuid'])
        db.fixed_ip_update(elevated, fix_addr, {'deleted': 1})
        elevated.read_deleted = 'yes'
        delfixed = db.fixed_ip_get_by_address(elevated, fix_addr)
        values = {'address': fix_addr,
                  'network_id': 0,
                  'instance_uuid': delfixed['instance_uuid']}
        db.fixed_ip_create(elevated, values)
        elevated.read_deleted = 'no'
        newfixed = db.fixed_ip_get_by_address(elevated, fix_addr)
        elevated.read_deleted = 'yes'

        deallocate = self.network.deallocate_fixed_ip
        self.assertRaises(test.TestingException, deallocate, context1,
                          fix_addr, 'fake')

    def test_deallocate_fixed_no_vif(self):
        """Verify that deallocate doesn't raise when no vif is returned.

        Ensures https://bugs.launchpad.net/nova/+bug/968457 doesn't return"""

        def network_get(_context, network_id, project_only="allow_none"):
            return networks[network_id]

        self.stubs.Set(db, 'network_get', network_get)

        def vif_get(_context, _vif_id):
            return None

        self.stubs.Set(db, 'virtual_interface_get', vif_get)
        context1 = context.RequestContext('user', 'project1')

        instance = db.instance_create(context1,
                                      {'project_id': 'project1'})

        elevated = context1.elevated()
        fix_addr = db.fixed_ip_associate_pool(elevated, 1, instance['uuid'])
        values = {'allocated': True,
                 'virtual_interface_id': 3}
        db.fixed_ip_update(elevated, fix_addr, values)

        self.flags(force_dhcp_release=True)
        self.network.deallocate_fixed_ip(context1, fix_addr, 'fake')

    def test_fixed_ip_cleanup_fail(self):
        """Verify IP is not deallocated if the security group refresh fails."""
        def network_get(_context, network_id, project_only="allow_none"):
            return networks[network_id]

        self.stubs.Set(db, 'network_get', network_get)

        context1 = context.RequestContext('user', 'project1')

        instance = db.instance_create(context1,
                {'project_id': 'project1'})

        elevated = context1.elevated()
        fix_addr = db.fixed_ip_associate_pool(elevated, 1, instance['uuid'])
        values = {'allocated': True,
                  'virtual_interface_id': 3}
        db.fixed_ip_update(elevated, fix_addr, values)
        fixed = db.fixed_ip_get_by_address(elevated, fix_addr)
        network = db.network_get(elevated, fixed['network_id'])

        def fake_refresh(instance_uuid):
            raise test.TestingException()
        self.stubs.Set(self.network,
                '_do_trigger_security_group_members_refresh_for_instance',
                fake_refresh)
        self.assertRaises(test.TestingException,
                          self.network.deallocate_fixed_ip,
                          context1, fix_addr, 'fake')
        fixed = db.fixed_ip_get_by_address(elevated, fix_addr)
        self.assertTrue(fixed['allocated'])


class CommonNetworkTestCase(test.TestCase):

    def setUp(self):
        super(CommonNetworkTestCase, self).setUp()
        self.context = context.RequestContext('fake', 'fake')

    def fake_create_fixed_ips(self, context, network_id, fixed_cidr=None):
        return None

    def test_deallocate_for_instance_passes_host_info(self):
        manager = fake_network.FakeNetworkManager()
        db = manager.db
        db.instance_get = lambda _x, _y: dict(uuid='ignoreduuid')
        db.virtual_interface_delete_by_instance = lambda _x, _y: None
        ctx = context.RequestContext('igonre', 'igonre')

        db.fixed_ip_get_by_instance = lambda x, y: [dict(address='1.2.3.4')]

        manager.deallocate_for_instance(
            ctx, instance_id='ignore', host='somehost')

        self.assertEquals([
            (ctx, '1.2.3.4', 'somehost')
        ], manager.deallocate_fixed_ip_calls)

    def test_remove_fixed_ip_from_instance(self):
        manager = fake_network.FakeNetworkManager()
        manager.remove_fixed_ip_from_instance(self.context, 99, HOST,
                                              '10.0.0.1')

        self.assertEquals(manager.deallocate_called, '10.0.0.1')

    def test_remove_fixed_ip_from_instance_bad_input(self):
        manager = fake_network.FakeNetworkManager()
        self.assertRaises(exception.FixedIpNotFoundForSpecificInstance,
                          manager.remove_fixed_ip_from_instance,
                          self.context, 99, HOST, 'bad input')

    def test_validate_cidrs(self):
        manager = fake_network.FakeNetworkManager()
        nets = manager.create_networks(None, 'fake', '192.168.0.0/24',
                                       False, 1, 256, None, None, None,
                                       None, None)
        self.assertEqual(1, len(nets))
        cidrs = [str(net['cidr']) for net in nets]
        self.assertTrue('192.168.0.0/24' in cidrs)

    def test_validate_cidrs_split_exact_in_half(self):
        manager = fake_network.FakeNetworkManager()
        nets = manager.create_networks(None, 'fake', '192.168.0.0/24',
                                       False, 2, 128, None, None, None,
                                       None, None)
        self.assertEqual(2, len(nets))
        cidrs = [str(net['cidr']) for net in nets]
        self.assertTrue('192.168.0.0/25' in cidrs)
        self.assertTrue('192.168.0.128/25' in cidrs)

    def test_validate_cidrs_split_cidr_in_use_middle_of_range(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        manager.db.network_get_all(ctxt).AndReturn([{'id': 1,
                                     'cidr': '192.168.2.0/24'}])
        self.mox.ReplayAll()
        nets = manager.create_networks(None, 'fake', '192.168.0.0/16',
                                       False, 4, 256, None, None, None,
                                       None, None)
        self.assertEqual(4, len(nets))
        cidrs = [str(net['cidr']) for net in nets]
        exp_cidrs = ['192.168.0.0/24', '192.168.1.0/24', '192.168.3.0/24',
                     '192.168.4.0/24']
        for exp_cidr in exp_cidrs:
            self.assertTrue(exp_cidr in cidrs)
        self.assertFalse('192.168.2.0/24' in cidrs)

    def test_validate_cidrs_smaller_subnet_in_use(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        manager.db.network_get_all(ctxt).AndReturn([{'id': 1,
                                     'cidr': '192.168.2.9/25'}])
        self.mox.ReplayAll()
        # ValueError: requested cidr (192.168.2.0/24) conflicts with
        #             existing smaller cidr
        args = (None, 'fake', '192.168.2.0/24', False, 1, 256, None, None,
                None, None, None)
        self.assertRaises(ValueError, manager.create_networks, *args)

    def test_validate_cidrs_split_smaller_cidr_in_use(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        manager.db.network_get_all(ctxt).AndReturn([{'id': 1,
                                     'cidr': '192.168.2.0/25'}])
        self.mox.ReplayAll()
        nets = manager.create_networks(None, 'fake', '192.168.0.0/16',
                                       False, 4, 256, None, None, None, None,
                                       None)
        self.assertEqual(4, len(nets))
        cidrs = [str(net['cidr']) for net in nets]
        exp_cidrs = ['192.168.0.0/24', '192.168.1.0/24', '192.168.3.0/24',
                     '192.168.4.0/24']
        for exp_cidr in exp_cidrs:
            self.assertTrue(exp_cidr in cidrs)
        self.assertFalse('192.168.2.0/24' in cidrs)

    def test_validate_cidrs_split_smaller_cidr_in_use2(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        manager.db.network_get_all(ctxt).AndReturn([{'id': 1,
                                     'cidr': '192.168.2.9/29'}])
        self.mox.ReplayAll()
        nets = manager.create_networks(None, 'fake', '192.168.2.0/24',
                                       False, 3, 32, None, None, None, None,
                                       None)
        self.assertEqual(3, len(nets))
        cidrs = [str(net['cidr']) for net in nets]
        exp_cidrs = ['192.168.2.32/27', '192.168.2.64/27', '192.168.2.96/27']
        for exp_cidr in exp_cidrs:
            self.assertTrue(exp_cidr in cidrs)
        self.assertFalse('192.168.2.0/27' in cidrs)

    def test_validate_cidrs_split_all_in_use(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        in_use = [{'id': 1, 'cidr': '192.168.2.9/29'},
                  {'id': 2, 'cidr': '192.168.2.64/26'},
                  {'id': 3, 'cidr': '192.168.2.128/26'}]
        manager.db.network_get_all(ctxt).AndReturn(in_use)
        self.mox.ReplayAll()
        args = (None, 'fake', '192.168.2.0/24', False, 3, 64, None, None,
                None, None, None)
        # ValueError: Not enough subnets avail to satisfy requested num_
        #             networks - some subnets in requested range already
        #             in use
        self.assertRaises(ValueError, manager.create_networks, *args)

    def test_validate_cidrs_one_in_use(self):
        manager = fake_network.FakeNetworkManager()
        args = (None, 'fake', '192.168.0.0/24', False, 2, 256, None, None,
                None, None, None)
        # ValueError: network_size * num_networks exceeds cidr size
        self.assertRaises(ValueError, manager.create_networks, *args)

    def test_validate_cidrs_already_used(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        manager.db.network_get_all(ctxt).AndReturn([{'id': 1,
                                     'cidr': '192.168.0.0/24'}])
        self.mox.ReplayAll()
        # ValueError: cidr already in use
        args = (None, 'fake', '192.168.0.0/24', False, 1, 256, None, None,
                None, None, None)
        self.assertRaises(ValueError, manager.create_networks, *args)

    def test_validate_cidrs_too_many(self):
        manager = fake_network.FakeNetworkManager()
        args = (None, 'fake', '192.168.0.0/24', False, 200, 256, None, None,
                None, None, None)
        # ValueError: Not enough subnets avail to satisfy requested
        #             num_networks
        self.assertRaises(ValueError, manager.create_networks, *args)

    def test_validate_cidrs_split_partial(self):
        manager = fake_network.FakeNetworkManager()
        nets = manager.create_networks(None, 'fake', '192.168.0.0/16',
                                       False, 2, 256, None, None, None, None,
                                       None)
        returned_cidrs = [str(net['cidr']) for net in nets]
        self.assertTrue('192.168.0.0/24' in returned_cidrs)
        self.assertTrue('192.168.1.0/24' in returned_cidrs)

    def test_validate_cidrs_conflict_existing_supernet(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        fakecidr = [{'id': 1, 'cidr': '192.168.0.0/8'}]
        manager.db.network_get_all(ctxt).AndReturn(fakecidr)
        self.mox.ReplayAll()
        args = (None, 'fake', '192.168.0.0/24', False, 1, 256, None, None,
                None, None, None)
        # ValueError: requested cidr (192.168.0.0/24) conflicts
        #             with existing supernet
        self.assertRaises(ValueError, manager.create_networks, *args)

    def test_create_networks(self):
        cidr = '192.168.0.0/24'
        manager = fake_network.FakeNetworkManager()
        self.stubs.Set(manager, '_create_fixed_ips',
                                self.fake_create_fixed_ips)
        args = [None, 'foo', cidr, None, 1, 256, 'fd00::/48', None, None,
                None, None, None]
        self.assertTrue(manager.create_networks(*args))

    def test_create_networks_cidr_already_used(self):
        manager = fake_network.FakeNetworkManager()
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        ctxt = mox.IgnoreArg()
        fakecidr = [{'id': 1, 'cidr': '192.168.0.0/24'}]
        manager.db.network_get_all(ctxt).AndReturn(fakecidr)
        self.mox.ReplayAll()
        args = [None, 'foo', '192.168.0.0/24', None, 1, 256,
                 'fd00::/48', None, None, None, None, None]
        self.assertRaises(ValueError, manager.create_networks, *args)

    def test_create_networks_many(self):
        cidr = '192.168.0.0/16'
        manager = fake_network.FakeNetworkManager()
        self.stubs.Set(manager, '_create_fixed_ips',
                                self.fake_create_fixed_ips)
        args = [None, 'foo', cidr, None, 10, 256, 'fd00::/48', None, None,
                None, None, None]
        self.assertTrue(manager.create_networks(*args))

    def test_get_instance_uuids_by_ip_regex(self):
        manager = fake_network.FakeNetworkManager()
        _vifs = manager.db.virtual_interface_get_all(None)
        fake_context = context.RequestContext('user', 'project')

        # Greedy get eveything
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip': '.*'})
        self.assertEqual(len(res), len(_vifs))

        # Doesn't exist
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip': '10.0.0.1'})
        self.assertFalse(res)

        # Get instance 1
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip': '172.16.0.2'})
        self.assertTrue(res)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['instance_uuid'], _vifs[1]['instance_uuid'])

        # Get instance 2
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip': '173.16.0.2'})
        self.assertTrue(res)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['instance_uuid'], _vifs[2]['instance_uuid'])

        # Get instance 0 and 1
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip': '172.16.0.*'})
        self.assertTrue(res)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]['instance_uuid'], _vifs[0]['instance_uuid'])
        self.assertEqual(res[1]['instance_uuid'], _vifs[1]['instance_uuid'])

        # Get instance 1 and 2
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip': '17..16.0.2'})
        self.assertTrue(res)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]['instance_uuid'], _vifs[1]['instance_uuid'])
        self.assertEqual(res[1]['instance_uuid'], _vifs[2]['instance_uuid'])

    def test_get_instance_uuids_by_ipv6_regex(self):
        manager = fake_network.FakeNetworkManager()
        _vifs = manager.db.virtual_interface_get_all(None)
        fake_context = context.RequestContext('user', 'project')

        # Greedy get eveything
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip6': '.*'})
        self.assertEqual(len(res), len(_vifs))

        # Doesn't exist
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip6': '.*1034.*'})
        self.assertFalse(res)

        # Get instance 1
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip6': '2001:.*2'})
        self.assertTrue(res)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['instance_uuid'], _vifs[1]['instance_uuid'])

        # Get instance 2
        ip6 = '2001:db8:69:1f:dead:beff:feff:ef03'
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip6': ip6})
        self.assertTrue(res)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['instance_uuid'], _vifs[2]['instance_uuid'])

        # Get instance 0 and 1
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip6': '.*ef0[1,2]'})
        self.assertTrue(res)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]['instance_uuid'], _vifs[0]['instance_uuid'])
        self.assertEqual(res[1]['instance_uuid'], _vifs[1]['instance_uuid'])

        # Get instance 1 and 2
        ip6 = '2001:db8:69:1.:dead:beff:feff:ef0.'
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'ip6': ip6})
        self.assertTrue(res)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]['instance_uuid'], _vifs[1]['instance_uuid'])
        self.assertEqual(res[1]['instance_uuid'], _vifs[2]['instance_uuid'])

    def test_get_instance_uuids_by_ip(self):
        manager = fake_network.FakeNetworkManager()
        _vifs = manager.db.virtual_interface_get_all(None)
        fake_context = context.RequestContext('user', 'project')

        # No regex for you!
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'fixed_ip': '.*'})
        self.assertFalse(res)

        # Doesn't exist
        ip = '10.0.0.1'
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'fixed_ip': ip})
        self.assertFalse(res)

        # Get instance 1
        ip = '172.16.0.2'
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'fixed_ip': ip})
        self.assertTrue(res)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['instance_uuid'], _vifs[1]['instance_uuid'])

        # Get instance 2
        ip = '173.16.0.2'
        res = manager.get_instance_uuids_by_ip_filter(fake_context,
                                                      {'fixed_ip': ip})
        self.assertTrue(res)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['instance_uuid'], _vifs[2]['instance_uuid'])

    def test_get_network(self):
        manager = fake_network.FakeNetworkManager()
        fake_context = context.RequestContext('user', 'project')
        self.mox.StubOutWithMock(manager.db, 'network_get_by_uuid')
        manager.db.network_get_by_uuid(mox.IgnoreArg(),
                                       mox.IgnoreArg()).AndReturn(networks[0])
        self.mox.ReplayAll()
        uuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        network = manager.get_network(fake_context, uuid)
        self.assertEqual(network['uuid'], uuid)

    def test_get_network_not_found(self):
        manager = fake_network.FakeNetworkManager()
        fake_context = context.RequestContext('user', 'project')
        self.mox.StubOutWithMock(manager.db, 'network_get_by_uuid')
        manager.db.network_get_by_uuid(
                mox.IgnoreArg(),
                mox.IgnoreArg()).AndRaise(exception.NetworkNotFoundForUUID)
        self.mox.ReplayAll()
        uuid = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.assertRaises(exception.NetworkNotFound,
                          manager.get_network, fake_context, uuid)

    def test_get_all_networks(self):
        manager = fake_network.FakeNetworkManager()
        fake_context = context.RequestContext('user', 'project')
        self.mox.StubOutWithMock(manager.db, 'network_get_all')
        manager.db.network_get_all(mox.IgnoreArg()).AndReturn(networks)
        self.mox.ReplayAll()
        output = manager.get_all_networks(fake_context)
        self.assertEqual(len(networks), 2)
        self.assertEqual(output[0]['uuid'],
                         'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
        self.assertEqual(output[1]['uuid'],
                         'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')

    def test_disassociate_network(self):
        manager = fake_network.FakeNetworkManager()
        fake_context = context.RequestContext('user', 'project')
        self.mox.StubOutWithMock(manager.db, 'network_get_by_uuid')
        manager.db.network_get_by_uuid(mox.IgnoreArg(),
                                       mox.IgnoreArg()).AndReturn(networks[0])
        self.mox.ReplayAll()
        uuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        manager.disassociate_network(fake_context, uuid)

    def test_disassociate_network_not_found(self):
        manager = fake_network.FakeNetworkManager()
        fake_context = context.RequestContext('user', 'project')
        self.mox.StubOutWithMock(manager.db, 'network_get_by_uuid')
        manager.db.network_get_by_uuid(
                mox.IgnoreArg(),
                mox.IgnoreArg()).AndRaise(exception.NetworkNotFoundForUUID)
        self.mox.ReplayAll()
        uuid = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.assertRaises(exception.NetworkNotFound,
                          manager.disassociate_network, fake_context, uuid)


class TestRPCFixedManager(network_manager.RPCAllocateFixedIP,
        network_manager.NetworkManager):
    """Dummy manager that implements RPCAllocateFixedIP"""


class RPCAllocateTestCase(test.TestCase):
    """Tests nova.network.manager.RPCAllocateFixedIP"""
    def setUp(self):
        super(RPCAllocateTestCase, self).setUp()
        self.rpc_fixed = TestRPCFixedManager()
        self.context = context.RequestContext('fake', 'fake')

    def test_rpc_allocate(self):
        """Test to verify bug 855030 doesn't resurface.

        Mekes sure _rpc_allocate_fixed_ip returns a value so the call
        returns properly and the greenpool completes."""
        address = '10.10.10.10'

        def fake_allocate(*args, **kwargs):
            return address

        def fake_network_get(*args, **kwargs):
            return {}

        self.stubs.Set(self.rpc_fixed, 'allocate_fixed_ip', fake_allocate)
        self.stubs.Set(self.rpc_fixed.db, 'network_get', fake_network_get)
        rval = self.rpc_fixed._rpc_allocate_fixed_ip(self.context,
                                                     'fake_instance',
                                                     'fake_network')
        self.assertEqual(rval, address)


class TestFloatingIPManager(network_manager.FloatingIP,
        network_manager.NetworkManager):
    """Dummy manager that implements FloatingIP"""


class AllocateTestCase(test.TestCase):
    def test_allocate_for_instance(self):
        address = "10.10.10.10"
        self.flags(auto_assign_floating_ip=True)
        self.compute = self.start_service('compute')
        self.network = self.start_service('network')

        self.user_id = 'fake'
        self.project_id = 'fake'
        self.context = context.RequestContext(self.user_id,
                                              self.project_id,
                                              is_admin=True)

        db.floating_ip_create(self.context,
                              {'address': address,
                               'pool': 'nova'})
        inst = db.instance_create(self.context, {'host': self.compute.host,
                                                 'instance_type_id': 1})
        networks = db.network_get_all(self.context)
        for network in networks:
            db.network_update(self.context, network['id'],
                              {'host': self.network.host})
        project_id = self.context.project_id
        nw_info = self.network.allocate_for_instance(self.context,
            instance_id=inst['id'], instance_uuid=inst['uuid'],
            host=inst['host'], vpn=None, rxtx_factor=3,
            project_id=project_id)
        self.assertEquals(1, len(nw_info))
        fixed_ip = nw_info.fixed_ips()[0]['address']
        self.assertTrue(utils.is_valid_ipv4(fixed_ip))
        self.network.deallocate_for_instance(self.context,
                                             instance_id=inst['id'],
                                             fixed_ips=fixed_ip,
                                             host=self.network.host,
                                             project_id=project_id)


class FloatingIPTestCase(test.TestCase):
    """Tests nova.network.manager.FloatingIP"""
    def setUp(self):
        super(FloatingIPTestCase, self).setUp()
        self.tempdir = tempfile.mkdtemp()
        self.flags(logdir=self.tempdir)
        self.network = TestFloatingIPManager()
        temp = importutils.import_object('nova.network.minidns.MiniDNS')
        self.network.floating_dns_manager = temp
        self.network.db = db
        self.project_id = 'testproject'
        self.context = context.RequestContext('testuser', self.project_id,
            is_admin=False)

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super(FloatingIPTestCase, self).tearDown()

    def test_double_deallocation(self):
        instance_ref = db.api.instance_create(self.context,
                {"project_id": self.project_id})
        # Run it twice to make it fault if it does not handle
        # instances without fixed networks
        # If this fails in either, it does not handle having no addresses
        self.network.deallocate_for_instance(self.context,
                instance_id=instance_ref['id'])
        self.network.deallocate_for_instance(self.context,
                instance_id=instance_ref['id'])

    def test_deallocation_deleted_instance(self):
        self.stubs.Set(self.network, '_teardown_network_on_host',
                       lambda *args, **kwargs: None)
        instance = db.api.instance_create(self.context, {
                'project_id': self.project_id, 'deleted': True})
        network = db.api.network_create_safe(self.context.elevated(), {
                'project_id': self.project_id})
        addr = db.fixed_ip_create(self.context, {'allocated': True,
                'instance_uuid': instance['uuid'], 'address': '10.1.1.1',
                'network_id': network['id']})
        fixed = db.fixed_ip_get_by_address(
                self.context.elevated(read_deleted='yes'), addr)
        db.api.floating_ip_create(self.context, {
                'address': '10.10.10.10', 'instance_uuid': instance['uuid'],
                'fixed_ip_id': fixed['id'],
                'project_id': self.project_id})
        self.network.deallocate_for_instance(self.context,
                instance_id=instance['id'])

    def test_deallocation_duplicate_floating_ip(self):
        self.stubs.Set(self.network, '_teardown_network_on_host',
                       lambda *args, **kwargs: None)
        instance = db.api.instance_create(self.context, {
                'project_id': self.project_id})
        network = db.api.network_create_safe(self.context.elevated(), {
                'project_id': self.project_id})
        addr = db.fixed_ip_create(self.context, {'allocated': True,
                'instance_uuid': instance['uuid'], 'address': '10.1.1.1',
                'network_id': network['id']})
        fixed = db.fixed_ip_get_by_address(
                self.context.elevated(read_deleted='yes'), addr)
        db.api.floating_ip_create(self.context, {
                'address': '10.10.10.10',
                'deleted': True})
        db.api.floating_ip_create(self.context, {
                'address': '10.10.10.10', 'instance_uuid': instance['uuid'],
                'fixed_ip_id': fixed['id'],
                'project_id': self.project_id})
        self.network.deallocate_for_instance(self.context,
                instance_id=instance['id'])

    def test_floating_dns_create_conflict(self):
        zone = "example.org"
        address1 = "10.10.10.11"
        name1 = "foo"
        name2 = "bar"

        self.network.add_dns_entry(self.context, address1, name1, "A", zone)

        self.assertRaises(exception.FloatingIpDNSExists,
                          self.network.add_dns_entry, self.context,
                          address1, name1, "A", zone)

    def test_floating_create_and_get(self):
        zone = "example.org"
        address1 = "10.10.10.11"
        name1 = "foo"
        name2 = "bar"
        entries = self.network.get_dns_entries_by_address(self.context,
                                                          address1, zone)
        self.assertFalse(entries)

        self.network.add_dns_entry(self.context, address1, name1, "A", zone)
        self.network.add_dns_entry(self.context, address1, name2, "A", zone)
        entries = self.network.get_dns_entries_by_address(self.context,
                                                          address1, zone)
        self.assertEquals(len(entries), 2)
        self.assertEquals(entries[0], name1)
        self.assertEquals(entries[1], name2)

        entries = self.network.get_dns_entries_by_name(self.context,
                                                       name1, zone)
        self.assertEquals(len(entries), 1)
        self.assertEquals(entries[0], address1)

    def test_floating_dns_delete(self):
        zone = "example.org"
        address1 = "10.10.10.11"
        name1 = "foo"
        name2 = "bar"

        self.network.add_dns_entry(self.context, address1, name1, "A", zone)
        self.network.add_dns_entry(self.context, address1, name2, "A", zone)
        self.network.delete_dns_entry(self.context, name1, zone)

        entries = self.network.get_dns_entries_by_address(self.context,
                                                          address1, zone)
        self.assertEquals(len(entries), 1)
        self.assertEquals(entries[0], name2)

        self.assertRaises(exception.NotFound,
                          self.network.delete_dns_entry, self.context,
                          name1, zone)

    def test_floating_dns_domains_public(self):
        zone1 = "testzone"
        domain1 = "example.org"
        domain2 = "example.com"
        address1 = '10.10.10.10'
        entryname = 'testentry'

        context_admin = context.RequestContext('testuser', 'testproject',
                                               is_admin=True)

        self.assertRaises(exception.AdminRequired,
                          self.network.create_public_dns_domain, self.context,
                          domain1, zone1)
        self.network.create_public_dns_domain(context_admin, domain1,
                                              'testproject')
        self.network.create_public_dns_domain(context_admin, domain2,
                                              'fakeproject')

        domains = self.network.get_dns_domains(self.context)
        self.assertEquals(len(domains), 2)
        self.assertEquals(domains[0]['domain'], domain1)
        self.assertEquals(domains[1]['domain'], domain2)
        self.assertEquals(domains[0]['project'], 'testproject')
        self.assertEquals(domains[1]['project'], 'fakeproject')

        self.network.add_dns_entry(self.context, address1, entryname,
                                   'A', domain1)
        entries = self.network.get_dns_entries_by_name(self.context,
                                                       entryname, domain1)
        self.assertEquals(len(entries), 1)
        self.assertEquals(entries[0], address1)

        self.assertRaises(exception.AdminRequired,
                          self.network.delete_dns_domain, self.context,
                          domain1)
        self.network.delete_dns_domain(context_admin, domain1)
        self.network.delete_dns_domain(context_admin, domain2)

        # Verify that deleting the domain deleted the associated entry
        entries = self.network.get_dns_entries_by_name(self.context,
                                                       entryname, domain1)
        self.assertFalse(entries)

    def test_delete_all_by_ip(self):
        domain1 = "example.org"
        domain2 = "example.com"
        address = "10.10.10.10"
        name1 = "foo"
        name2 = "bar"

        def fake_domains(context):
            return [{'domain': 'example.org', 'scope': 'public'},
                    {'domain': 'example.com', 'scope': 'public'},
                    {'domain': 'test.example.org', 'scope': 'public'}]

        self.stubs.Set(self.network, 'get_dns_domains', fake_domains)

        context_admin = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

        self.network.create_public_dns_domain(context_admin, domain1,
                                              'testproject')
        self.network.create_public_dns_domain(context_admin, domain2,
                                              'fakeproject')

        domains = self.network.get_dns_domains(self.context)
        for domain in domains:
            self.network.add_dns_entry(self.context, address,
                                       name1, "A", domain['domain'])
            self.network.add_dns_entry(self.context, address,
                                       name2, "A", domain['domain'])
            entries = self.network.get_dns_entries_by_address(self.context,
                                                              address,
                                                              domain['domain'])
            self.assertEquals(len(entries), 2)

        self.network._delete_all_entries_for_ip(self.context, address)

        for domain in domains:
            entries = self.network.get_dns_entries_by_address(self.context,
                                                              address,
                                                              domain['domain'])
            self.assertFalse(entries)

        self.network.delete_dns_domain(context_admin, domain1)
        self.network.delete_dns_domain(context_admin, domain2)

    def test_mac_conflicts(self):
        """Make sure MAC collisions are retried"""
        self.flags(create_unique_mac_address_attempts=3)
        ctxt = context.RequestContext('testuser', 'testproject', is_admin=True)
        macs = ['bb:bb:bb:bb:bb:bb', 'aa:aa:aa:aa:aa:aa']

        # Create a VIF with aa:aa:aa:aa:aa:aa
        crash_test_dummy_vif = {
            'address': macs[1],
            'instance_uuid': 'fake_uuid',
            'network_id': 'fake_net',
            'uuid': 'fake_uuid',
            }
        self.network.db.virtual_interface_create(ctxt, crash_test_dummy_vif)

        # Hand out a collision first, then a legit MAC
        def fake_gen_mac():
            return macs.pop()
        self.stubs.Set(utils, 'generate_mac_address', fake_gen_mac)

        # SQLite doesn't seem to honor the uniqueness constraint on the
        # address column, so fake the collision-avoidance here
        def fake_vif_save(vif):
            if vif.address == crash_test_dummy_vif['address']:
                raise exception.DBError("If you're smart, you'll retry!")
        self.stubs.Set(models.VirtualInterface, 'save', fake_vif_save)

        # Attempt to add another and make sure that both MACs are consumed
        # by the retry loop
        self.network.add_virtual_interface(ctxt, 'fake_uuid', 'fake_net')
        self.assertEqual(macs, [])


class NetworkPolicyTestCase(test.TestCase):
    def setUp(self):
        super(NetworkPolicyTestCase, self).setUp()

        nova.policy.reset()
        nova.policy.init()

        self.context = context.get_admin_context()

    def tearDown(self):
        super(NetworkPolicyTestCase, self).tearDown()
        nova.policy.reset()

    def test_check_policy(self):
        self.mox.StubOutWithMock(nova.policy, 'enforce')
        target = {
            'project_id': self.context.project_id,
            'user_id': self.context.user_id,
        }
        nova.policy.enforce(self.context, 'network:get_all', target)
        self.mox.ReplayAll()
        network_manager.check_policy(self.context, 'get_all')


class InstanceDNSTestCase(test.TestCase):
    """Tests nova.network.manager instance DNS"""
    def setUp(self):
        super(InstanceDNSTestCase, self).setUp()
        self.tempdir = tempfile.mkdtemp()
        self.flags(logdir=self.tempdir)
        self.network = TestFloatingIPManager()
        temp = importutils.import_object('nova.network.minidns.MiniDNS')
        self.network.instance_dns_manager = temp
        temp = importutils.import_object('nova.network.dns_driver.DNSDriver')
        self.network.floating_dns_manager = temp
        self.network.db = db
        self.project_id = 'testproject'
        self.context = context.RequestContext('testuser', self.project_id,
            is_admin=False)

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super(InstanceDNSTestCase, self).tearDown()

    def test_dns_domains_private(self):
        zone1 = 'testzone'
        domain1 = 'example.org'

        context_admin = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

        self.assertRaises(exception.AdminRequired,
                          self.network.create_private_dns_domain, self.context,
                          domain1, zone1)

        self.network.create_private_dns_domain(context_admin, domain1, zone1)
        domains = self.network.get_dns_domains(self.context)
        self.assertEquals(len(domains), 1)
        self.assertEquals(domains[0]['domain'], domain1)
        self.assertEquals(domains[0]['availability_zone'], zone1)

        self.assertRaises(exception.AdminRequired,
                          self.network.delete_dns_domain, self.context,
                          domain1)
        self.network.delete_dns_domain(context_admin, domain1)


domain1 = "example.org"
domain2 = "example.com"


class LdapDNSTestCase(test.TestCase):
    """Tests nova.network.ldapdns.LdapDNS"""
    def setUp(self):
        super(LdapDNSTestCase, self).setUp()

        self.saved_ldap = sys.modules.get('ldap')
        import nova.auth.fakeldap
        sys.modules['ldap'] = nova.auth.fakeldap

        temp = importutils.import_object('nova.network.ldapdns.FakeLdapDNS')
        self.driver = temp
        self.driver.create_domain(domain1)
        self.driver.create_domain(domain2)

    def tearDown(self):
        self.driver.delete_domain(domain1)
        self.driver.delete_domain(domain2)
        sys.modules['ldap'] = self.saved_ldap
        super(LdapDNSTestCase, self).tearDown()

    def test_ldap_dns_domains(self):
        domains = self.driver.get_domains()
        self.assertEqual(len(domains), 2)
        self.assertIn(domain1, domains)
        self.assertIn(domain2, domains)

    def test_ldap_dns_create_conflict(self):
        address1 = "10.10.10.11"
        name1 = "foo"
        name2 = "bar"

        self.driver.create_entry(name1, address1, "A", domain1)

        self.assertRaises(exception.FloatingIpDNSExists,
                          self.driver.create_entry,
                          name1, address1, "A", domain1)

    def test_ldap_dns_create_and_get(self):
        address1 = "10.10.10.11"
        name1 = "foo"
        name2 = "bar"
        entries = self.driver.get_entries_by_address(address1, domain1)
        self.assertFalse(entries)

        self.driver.create_entry(name1, address1, "A", domain1)
        self.driver.create_entry(name2, address1, "A", domain1)
        entries = self.driver.get_entries_by_address(address1, domain1)
        self.assertEquals(len(entries), 2)
        self.assertEquals(entries[0], name1)
        self.assertEquals(entries[1], name2)

        entries = self.driver.get_entries_by_name(name1, domain1)
        self.assertEquals(len(entries), 1)
        self.assertEquals(entries[0], address1)

    def test_ldap_dns_delete(self):
        address1 = "10.10.10.11"
        name1 = "foo"
        name2 = "bar"

        self.driver.create_entry(name1, address1, "A", domain1)
        self.driver.create_entry(name2, address1, "A", domain1)
        entries = self.driver.get_entries_by_address(address1, domain1)
        self.assertEquals(len(entries), 2)

        self.driver.delete_entry(name1, domain1)
        entries = self.driver.get_entries_by_address(address1, domain1)
        LOG.debug("entries: %s" % entries)
        self.assertEquals(len(entries), 1)
        self.assertEquals(entries[0], name2)

        self.assertRaises(exception.NotFound,
                          self.driver.delete_entry,
                          name1, domain1)


class NetworkQoSTestCase(test.TestCase):
    def setUp(self):
        super(NetworkQoSTestCase, self).setUp()
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

    def tearDown(self):
        super(NetworkQoSTestCase, self).tearDown()

    def Fake_DB_instance_get():
            return lambda a, b: [dict(uuid='ignoreduuid')]

    def test_get_instance_qos_id_call(self):
        instance = {'id': '123', 'host': 'ignorehost'}

        def fake_call(context, topic, msg):
            return msg

        manager = network_manager.NetworkManager()

        ctxt = mox.IgnoreArg()

        self.stubs.Set(rpc, 'call', fake_call)

        self.mox.StubOutWithMock(rpc, 'queue_get_for')
        rpc.queue_get_for(ctxt, ctxt, ctxt).AndReturn('network_topic')

        self.mox.StubOutWithMock(manager.db, 'instance_get')
        manager.db.instance_get(ctxt, ctxt).AndReturn(instance)

        self.mox.ReplayAll()

        res = manager.get_instance_qos_id(self.context, instance['id'])

        if FLAGS.use_network_qos:
            self.assertEqual('_get_instance_qos_id', res['method'])

    def test_get_instance_qos_id(self):
        instance = {'uuid': 'fake_uuid'}
        context_admin = context.RequestContext('testuser', 'testproject',
                             is_admin=True)
        var = mox.IgnoreArg()
        self.mox.StubOutWithMock(linux_net.db, 'instance_get')
        linux_net.db.instance_get(var, var).\
                          AndReturn(instance)

        sys_metadata = {'network-tc-id': '123'}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(var, var).\
                          AndReturn(sys_metadata)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()
        manager = network_manager.NetworkManager()
        result = manager._get_instance_qos_id(context_admin, instance)
        self.assertEqual(result, 123)

    def test_get_instance_fw_mark(self):
        instance = {'uuid': 'fake_uuid'}
        var = mox.IgnoreArg()
        context_admin = context.RequestContext('testuser', 'testproject',
                is_admin=True)
        self.mox.StubOutWithMock(linux_net.db, 'instance_get')
        linux_net.db.instance_get(var, var).\
                          AndReturn(instance)

        sys_metadata = {'network-tc-id': '123'}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(var, var).\
                          AndReturn(sys_metadata)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()
        manager = network_manager.NetworkManager()
        result = manager._get_instance_fw_mark(context_admin, instance)
        self.assertEqual(result, '0x1000007b')

    def test_create_instance_network_qos_call(self):
        instance = {'id': '123', 'host': 'ignorehost'}
        spec_public = 'public'
        spec_private = 'private'

        def fake_call(context, topic, msg):
            return msg

        def fake_queue_get_for(context, topic, host):
            return 'network_topic'

        manager = network_manager.NetworkManager()
        ctxt = mox.IgnoreArg()
        self.stubs.Set(rpc, 'call', fake_call)
        self.stubs.Set(rpc, 'queue_get_for', fake_queue_get_for)

        self.mox.StubOutWithMock(manager.db, 'instance_get')
        manager.db.instance_get(ctxt, ctxt).AndReturn(instance)
        self.mox.ReplayAll()

        manager.create_instance_network_qos(
            self.context, instance['id'], spec_public, spec_private)

    def test_create_instance_network_qos_not_int(self):
        manager = network_manager.NetworkManager()

        instance = {'id': '123', 'host': 'ignorehost', 'uuid': FAKEUUID,
                      'instance_type_id': '1'}

        class fake_TcManager():
            pass

        fake_tc_manager = fake_TcManager()
        fake_tc_manager.config = Fake_Network_QoS_Config
        self.stubs.Set(linux_net, 'tc_manager', fake_tc_manager)

        metadata = {'network_qos_public_rate': 'pub_rate',
                    'network_qos_private_rate': 'pvt_rate'}
        var = mox.IgnoreArg()
        self.mox.StubOutWithMock(manager.db, 'instance_metadata_get')
        manager.db.instance_metadata_get(var, var).AndReturn(metadata)
        self.mox.ReplayAll()

        self.assertRaises(exception.InvalidTcParam,
                            manager._create_instance_network_qos,
                            self.context, instance, None, None)

    def test_create_instance_network_qos_error_param(self):
        instance = {'id': '123', 'host': 'ignorehost', 'uuid': FAKEUUID,
                     'instance_type_id': None}

        def Fake_metadata():
            return dict(network_qos_public_rate='invalidpara',
                               network_qos_private_rate='invalidpara')

        manager = network_manager.NetworkManager()

        class fake_TcManager():
            pass

        fake_tc_manager = fake_TcManager()
        fake_tc_manager.config = Fake_Network_QoS_Config
        self.stubs.Set(linux_net, 'tc_manager', fake_tc_manager)
        ctxt = mox.IgnoreArg()

        self.mox.StubOutWithMock(manager.db, 'instance_metadata_get')
        manager.db.instance_metadata_get(self.context, ctxt).\
                           AndReturn(Fake_metadata())

        self.mox.ReplayAll()

        self.assertRaises(exception.InvalidTcParam,
                           manager._create_instance_network_qos,
                           self.context, instance, None, None)

    def test_check_spec(self):
        manager = network_manager.NetworkManager()
        spec = dict(rate=5, ceil=100, burst=2)
        manager._check_spec(spec)

        spec = dict(ceil=100, burst=2)
        self.assertRaises(exception.InvalidTcParam,
                               manager._check_spec, spec)

        spec = dict(rate=5.2, ceil=100, burst=2)
        self.assertRaises(exception.InvalidTcParam,
                                manager._check_spec, spec)

        spec = dict(rate=5, ceil=100.1, burst=2)
        self.assertRaises(exception.InvalidTcParam,
                                manager._check_spec, spec)

        spec = dict(rate=5, ceil=100, burst=2.1)
        self.assertRaises(exception.InvalidTcParam,
                                manager._check_spec, spec)

        spec = dict(rate=-5, ceil=100, burst=2)
        self.assertRaises(exception.InvalidTcParam,
                                manager._check_spec, spec)

        spec = dict(rate=5, ceil=-100, burst=2)
        self.assertRaises(exception.InvalidTcParam,
                                manager._check_spec, spec)

        spec = dict(rate=5, ceil=100, burst=-2)
        self.assertRaises(exception.InvalidTcParam,
                                manager._check_spec, spec)

        spec = dict(rate=15, ceil=10, burst=20)
        self.assertRaises(exception.InvalidTcParam,
                                manager._check_spec, spec)

    def test_create_address_network_qos_call(self):
        instance = {'id': '123', 'host': 'ignorehost',
                      'address': '10.0.0.1'}
        qtype = 'public'
        atype = 'floating_ip'

        def fake_call(context, topic, msg):
            return msg

        def fake_queue_get_for(context, topic, host):
            return 'network_topic'

        manager = network_manager.NetworkManager()
        ctxt = mox.IgnoreArg()
        self.stubs.Set(rpc, 'call', fake_call)
        self.stubs.Set(rpc, 'queue_get_for', fake_queue_get_for)

        '''self.mox.StubOutWithMock(manager.db, 'instance_get')
        manager.db.instance_get(ctxt, ctxt).AndReturn(instance)
        self.mox.ReplayAll()'''

        manager.create_address_network_qos(
            self.context, instance, qtype, atype, instance['address'])

        #self.mox.VerifyAll()

    def test_create_address_network_qos(self):
        qtype = 'public'
        atype = 'floating_ip'
        address = '10.0.0.1'
        net_opt = network_qos_opt()
        expect = [('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                   'protocol', 'ip', 'parent', '10:', 'pref', '2', 'u32',
                  'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '10:10'),
                  ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                   'protocol', 'ip', 'parent', '10:', 'pref', '2', 'u32',
                   'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '10:10')]
        context_admin = context.RequestContext('testuser', 'testproject',
                is_admin=True)
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        instance = {'id': 123, 'host': 'ignorehost', 'uuid': FAKEUUID,
                      'instance_type_id': '1'}

        class fake_TcManager(test.TestCase):
            def __init__(self):
                pass

            def add_instance_filter(self, instance_id, qtype, node, address):
                dev = net_opt['phy_inf']
                node_id = '10'
                parent_id = '10'
                class_id = '10'
                type = 'htb'
                spec = {'rate': 10}
                tc = linux_net.TcClass(dev, node_id, parent_id,
                                       class_id, type, spec)

                node = 'ingress'
                protocol = 'ip'
                pref = 2
                tc_filt = tc.add_filter(protocol, pref, node, address)

        fake_tc_manager = fake_TcManager()
        fake_tc_manager.config = Fake_Network_QoS_Config
        self.stubs.Set(linux_net, 'tc_manager', fake_tc_manager)
        manager = network_manager.NetworkManager()
        manager._create_address_network_qos(context_admin, instance,
                                                qtype, atype, address)
        self.assertEqual(expect, self.executes)

    def test_delete_instance_network_qos_call(self):
        instance = {'id': '123', 'host': 'ignorehost',
                      'address': '10.0.0.1'}

        def fake_call(context, topic, msg):
            return msg

        def fake_queue_get_for(context, topic, host):
            return 'network_topic'

        manager = network_manager.NetworkManager()
        ctxt = mox.IgnoreArg()
        self.stubs.Set(rpc, 'call', fake_call)
        self.stubs.Set(rpc, 'queue_get_for', fake_queue_get_for)

        self.mox.StubOutWithMock(manager.db, 'instance_get')
        manager.db.instance_get(ctxt, ctxt).AndReturn(instance)
        self.mox.ReplayAll()

        manager.delete_instance_network_qos(
            self.context, instance['id'], instance['host'], False)

        self.mox.VerifyAll()

    def test_delete_address_network_qos(self):
        net_opt = network_qos_opt()
        qtype = 'public'
        instance_id = 40
        address = '10.0.0.1'
        instance = {'id': 40, 'host': 'ignorehost',
                        'address': '10.0.0.1', 'project_id': 'fake_project'}
        context_admin = context.RequestContext('testuser', 'testproject',
                                                is_admin=True)
        class_id = '40'
        spec = {'rate': 10}
        tc_mana = linux_net.TcManager()
        manager = network_manager.NetworkManager()
        expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'], 'root',
                   'handle', '9:', 'htb'),
                  ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                   '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                  ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                   '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                  ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                   'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                   'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40'),
                  ('tc', 'filter', 'del', 'dev', net_opt['phy_inf'],
                   'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                   'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        def fake_instance_tc_class_id(self, instance_id, qtype):
            return class_id

        self.stubs.Set(linux_net.TcManager, '_instance_tc_class_id',
                                          fake_instance_tc_class_id)

        tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
        tc_mana.egress.apply()
        tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', spec)
        c = tc_mana.e_pub_cls.add_class('40', spec)
        c.add_filter('ip', 1, 'egress', address)

        self.stubs.Set(linux_net.TcManager,
                                   'e_pub_cls', tc_mana.e_pub_cls)

        manager._delete_address_network_qos(context_admin, instance,
                                            qtype, address)
        self.assertEqual(expect, self.executes)

        self.mox.UnsetStubs()

    def test_modify_network_qos_no_rate(self):
        instance = {'id': '123', 'host': 'ignorehost',
                      'address': '10.0.0.1'}
        spec = dict(ceil=10, burst=10, cburst=10)
        qtype = 'public'
        manager = network_manager.NetworkManager()
        self.assertRaises(exception.InvalidTcParam,
                          manager._modify_network_qos,
                          self.context, instance, qtype, spec, None)

    def test_modify_network_qos(self):
        instance = {'id': 40, 'host': 'ignorehost',
                      'address': '10.0.0.1', 'uuid': 'fake_uuid'}
        spec = dict(rate=10, ceil=10, burst=10, cburst=10)
        qtype = 'public'
        class_id = '40'
        net_opt = network_qos_opt()
        expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'], 'root',
                   'handle', '9:', 'htb'),
       ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent', '9:',
        'classid', '9:40', 'htb', 'cburst', '10mbit', 'rate', '10mbit',
        'burst', '10mbit', 'ceil', '10mbit'),
       ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent', '9:40',
        'classid', '9:40', 'htb', 'cburst', '10mbit', 'rate', '10mbit',
        'burst', '10mbit', 'ceil', '10mbit'),
       ('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'], 'root', 'handle',
        '9:', 'htb'),
       ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent', '9:',
        'classid', '9:40', 'htb', 'cburst', '10mbit', 'rate', '10mbit',
        'burst', '10mbit', 'ceil', '10mbit'),
       ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent', '9:40',
        'classid', '9:40', 'htb', 'cburst', '10mbit', 'rate', '10mbit',
        'burst', '10mbit', 'ceil', '10mbit'),
       ('tc', 'class', 'change', 'dev', net_opt['phy_inf'], 'parent', '9:40',
        'classid', '9:40', 'htb', 'prio', '1', 'burst', '10mbit', 'ceil',
        '10mbit', 'rate', '10mbit', 'cburst', '10mbit'),
       ('tc', 'class', 'change', 'dev', net_opt['phy_inf'], 'parent', '9:40',
        'classid', '9:40', 'htb', 'prio', '1', 'burst', '10mbit', 'ceil',
        '10mbit', 'rate', '10mbit', 'cburst', '10mbit')]
        self.executes = []
        sys_metadata = {'network-qos':
                        '[{"prio":1, "type": "public", "rate": 5}]'}

        manager = network_manager.NetworkManager()

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        def fake_instance_system_metadata_get(context, instance_uuid):
            return sys_metadata
        self.stubs.Set(manager.db, 'instance_system_metadata_get',
                                   fake_instance_system_metadata_get)

        def fake_reserve(context, expire=None, project_id=None, **deltas):
            return 5
        self.stubs.Set(QUOTAS, 'reserve', fake_reserve)

        def fake_instance_system_metadata_update(context, instance_uuid,
                                                 metadata, delete):
            pass
        self.stubs.Set(manager.db, 'instance_system_metadata_update',
                                   fake_instance_system_metadata_update)

        instances = [{'uuid': 'fake_uuid'}]

        def fake_instance_get_all_by_host(context, host):
            return instances
        self.stubs.Set(manager.db, 'instance_get_all_by_host',
                                   fake_instance_get_all_by_host)

        metadata = {'network-qos':
                    '[{"type": "public", "rate": 5, "prio": 1}]'}

        tc_mana = linux_net.TcManager()

        def fake_instance_tc_class_id(self, instance_id, qtype):
            return class_id
        self.stubs.Set(linux_net.TcManager, '_instance_tc_class_id',
                       fake_instance_tc_class_id)

        tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
        tc_mana.egress.apply()
        tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', spec)
        c = tc_mana.e_pub_cls.add_class('40', spec)

        self.stubs.Set(linux_net.TcManager, 'e_pub_cls', tc_mana.e_pub_cls)

        tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
        tc_mana.ingress.apply()
        tc_mana.i_pub_cls = tc_mana.ingress.add_class('40', spec)
        c = tc_mana.i_pub_cls.add_class('40', spec)

        self.stubs.Set(linux_net.TcManager, 'i_pub_cls', tc_mana.i_pub_cls)

        manager._modify_network_qos(self.context, instance, qtype, spec)
        self.assertEqual(expect, self.executes)

        self.mox.UnsetStubs()
