# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 NTT
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

import os

import mox

from nova import context
from nova import db
from nova import exception
from nova import flags
from nova.network import linux_net
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova import test
from nova import utils


FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)


HOST = "testhost"

instances = {'00000000-0000-0000-0000-0000000000000000':
                 {'id': 0,
                  'uuid': '00000000-0000-0000-0000-0000000000000000',
                  'host': 'fake_instance00',
                  'created_at': 'fakedate',
                  'updated_at': 'fakedate',
                  'hostname': 'fake_instance00'},
             '00000000-0000-0000-0000-0000000000000001':
                 {'id': 1,
                  'uuid': '00000000-0000-0000-0000-0000000000000001',
                  'host': 'fake_instance01',
                  'created_at': 'fakedate',
                  'updated_at': 'fakedate',
                  'hostname': 'fake_instance01'}}


addresses = [{"address": "10.0.0.1"},
             {"address": "10.0.0.2"},
             {"address": "10.0.0.3"},
             {"address": "10.0.0.4"},
             {"address": "10.0.0.5"},
             {"address": "10.0.0.6"}]


networks = [{'id': 0,
             'uuid': "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
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
             'dhcp_server': '0.0.0.0',
             'dhcp_start': '192.168.100.1',
             'vlan': None,
             'host': None,
             'project_id': 'fake_project',
             'vpn_public_address': '192.168.0.2'},
            {'id': 1,
             'uuid': "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
             'label': 'test1',
             'injected': False,
             'multi_host': True,
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
             'dhcp_server': '0.0.0.0',
             'dhcp_start': '192.168.100.1',
             'vlan': None,
             'host': None,
             'project_id': 'fake_project',
             'vpn_public_address': '192.168.1.2'}]


fixed_ips = [{'id': 0,
              'network_id': 0,
              'address': '192.168.0.100',
              'instance_id': 0,
              'allocated': True,
              'virtual_interface_id': 0,
              'instance_uuid': '00000000-0000-0000-0000-0000000000000000',
              'floating_ips': []},
             {'id': 1,
              'network_id': 1,
              'address': '192.168.1.100',
              'instance_id': 0,
              'allocated': True,
              'virtual_interface_id': 1,
              'instance_uuid': '00000000-0000-0000-0000-0000000000000000',
              'floating_ips': []},
             {'id': 2,
              'network_id': 1,
              'address': '192.168.0.101',
              'instance_id': 1,
              'allocated': True,
              'virtual_interface_id': 2,
              'instance_uuid': '00000000-0000-0000-0000-0000000000000001',
              'floating_ips': []},
             {'id': 3,
              'network_id': 0,
              'address': '192.168.1.101',
              'instance_id': 1,
              'allocated': True,
              'virtual_interface_id': 3,
              'instance_uuid': '00000000-0000-0000-0000-0000000000000001',
              'floating_ips': []},
             {'id': 4,
              'network_id': 0,
              'address': '192.168.0.102',
              'instance_id': 0,
              'allocated': True,
              'virtual_interface_id': 4,
              'instance_uuid': '00000000-0000-0000-0000-0000000000000000',
              'floating_ips': []},
             {'id': 5,
              'network_id': 1,
              'address': '192.168.1.102',
              'instance_id': 1,
              'allocated': True,
              'virtual_interface_id': 5,
              'instance_uuid': '00000000-0000-0000-0000-0000000000000001',
              'floating_ips': []}]


vifs = [{'id': 0,
         'address': 'DE:AD:BE:EF:00:00',
         'uuid': '00000000-0000-0000-0000-0000000000000000',
         'network_id': 0,
         'instance_uuid': '00000000-0000-0000-0000-0000000000000000'},
        {'id': 1,
         'address': 'DE:AD:BE:EF:00:01',
         'uuid': '00000000-0000-0000-0000-0000000000000001',
         'network_id': 1,
         'instance_uuid': '00000000-0000-0000-0000-0000000000000000'},
        {'id': 2,
         'address': 'DE:AD:BE:EF:00:02',
         'uuid': '00000000-0000-0000-0000-0000000000000002',
         'network_id': 1,
         'instance_uuid': '00000000-0000-0000-0000-0000000000000001'},
        {'id': 3,
         'address': 'DE:AD:BE:EF:00:03',
         'uuid': '00000000-0000-0000-0000-0000000000000003',
         'network_id': 0,
         'instance_uuid': '00000000-0000-0000-0000-0000000000000001'},
        {'id': 4,
         'address': 'DE:AD:BE:EF:00:04',
         'uuid': '00000000-0000-0000-0000-0000000000000004',
         'network_id': 0,
         'instance_uuid': '00000000-0000-0000-0000-0000000000000000'},
        {'id': 5,
         'address': 'DE:AD:BE:EF:00:05',
         'uuid': '00000000-0000-0000-0000-0000000000000005',
         'network_id': 1,
         'instance_uuid': '00000000-0000-0000-0000-0000000000000001'}]


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


def get_associated(context, network_id, host=None):
    result = []
    for datum in fixed_ips:
        if (datum['network_id'] == network_id and datum['allocated']
            and datum['instance_uuid'] is not None
            and datum['virtual_interface_id'] is not None):
            instance = instances[datum['instance_uuid']]
            if host and host != instance['host']:
                continue
            cleaned = {}
            cleaned['address'] = datum['address']
            cleaned['instance_uuid'] = datum['instance_uuid']
            cleaned['network_id'] = datum['network_id']
            cleaned['vif_id'] = datum['virtual_interface_id']
            vif = vifs[datum['virtual_interface_id']]
            cleaned['vif_address'] = vif['address']
            cleaned['instance_hostname'] = instance['hostname']
            cleaned['instance_updated'] = instance['updated_at']
            cleaned['instance_created'] = instance['created_at']
            result.append(cleaned)
    return result


class LinuxNetworkTestCase(test.TestCase):

    def setUp(self):
        super(LinuxNetworkTestCase, self).setUp()
        network_driver = FLAGS.network_driver
        self.driver = importutils.import_module(network_driver)
        self.driver.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

        def get_vifs(_context, instance_uuid):
            return [vif for vif in vifs
                    if vif['instance_uuid'] == instance_uuid]

        def get_instance(_context, instance_id):
            return instances[instance_id]

        self.stubs.Set(db, 'virtual_interface_get_by_instance', get_vifs)
        self.stubs.Set(db, 'instance_get', get_instance)
        self.stubs.Set(db, 'network_get_associated_fixed_ips', get_associated)

    def test_update_dhcp_for_nw00(self):
        self.flags(use_single_default_gateway=True)

        self.mox.StubOutWithMock(self.driver, 'write_to_file')
        self.mox.StubOutWithMock(utils, 'ensure_tree')
        self.mox.StubOutWithMock(os, 'chmod')

        self.driver.write_to_file(mox.IgnoreArg(), mox.IgnoreArg())
        self.driver.write_to_file(mox.IgnoreArg(), mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        os.chmod(mox.IgnoreArg(), mox.IgnoreArg())
        os.chmod(mox.IgnoreArg(), mox.IgnoreArg())

        self.mox.ReplayAll()

        self.driver.update_dhcp(self.context, "eth0", networks[0])

    def test_update_dhcp_for_nw01(self):
        self.flags(use_single_default_gateway=True)

        self.mox.StubOutWithMock(self.driver, 'write_to_file')
        self.mox.StubOutWithMock(utils, 'ensure_tree')
        self.mox.StubOutWithMock(os, 'chmod')

        self.driver.write_to_file(mox.IgnoreArg(), mox.IgnoreArg())
        self.driver.write_to_file(mox.IgnoreArg(), mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        utils.ensure_tree(mox.IgnoreArg())
        os.chmod(mox.IgnoreArg(), mox.IgnoreArg())
        os.chmod(mox.IgnoreArg(), mox.IgnoreArg())

        self.mox.ReplayAll()

        self.driver.update_dhcp(self.context, "eth0", networks[0])

    def test_get_dhcp_hosts_for_nw00(self):
        self.flags(use_single_default_gateway=True)

        expected = (
                "DE:AD:BE:EF:00:00,fake_instance00.novalocal,"
                "192.168.0.100,net:NW-0\n"
                "DE:AD:BE:EF:00:03,fake_instance01.novalocal,"
                "192.168.1.101,net:NW-3\n"
                "DE:AD:BE:EF:00:04,fake_instance00.novalocal,"
                "192.168.0.102,net:NW-4"
        )
        actual_hosts = self.driver.get_dhcp_hosts(self.context, networks[0])

        self.assertEquals(actual_hosts, expected)

    def test_get_dhcp_hosts_for_nw01(self):
        self.flags(use_single_default_gateway=True)
        self.flags(host='fake_instance01')

        expected = (
                "DE:AD:BE:EF:00:02,fake_instance01.novalocal,"
                "192.168.0.101,net:NW-2\n"
                "DE:AD:BE:EF:00:05,fake_instance01.novalocal,"
                "192.168.1.102,net:NW-5"
        )
        actual_hosts = self.driver.get_dhcp_hosts(self.context, networks[1])

        self.assertEquals(actual_hosts, expected)

    def test_get_dhcp_opts_for_nw00(self):
        expected_opts = 'NW-0,3\nNW-3,3\nNW-4,3'
        actual_opts = self.driver.get_dhcp_opts(self.context, networks[0])

        self.assertEquals(actual_opts, expected_opts)

    def test_get_dhcp_opts_for_nw01(self):
        self.flags(host='fake_instance01')
        expected_opts = "NW-5,3"
        actual_opts = self.driver.get_dhcp_opts(self.context, networks[1])

        self.assertEquals(actual_opts, expected_opts)

    def test_dhcp_opts_not_default_gateway_network(self):
        expected = "NW-0,3"
        data = get_associated(self.context, 0)[0]
        actual = self.driver._host_dhcp_opts(data)
        self.assertEquals(actual, expected)

    def test_host_dhcp_without_default_gateway_network(self):
        expected = ','.join(['DE:AD:BE:EF:00:00',
                             'fake_instance00.novalocal',
                             '192.168.0.100'])
        data = get_associated(self.context, 0)[0]
        actual = self.driver._host_dhcp(data)
        self.assertEquals(actual, expected)

    def test_linux_bridge_driver_plug(self):
        """Makes sure plug doesn't drop FORWARD by default.

        Ensures bug 890195 doesn't reappear."""

        def fake_execute(*args, **kwargs):
            return "", ""
        self.stubs.Set(utils, 'execute', fake_execute)

        def verify_add_rule(chain, rule):
            self.assertEqual(chain, 'FORWARD')
            self.assertIn('ACCEPT', rule)
        self.stubs.Set(linux_net.iptables_manager.ipv4['filter'],
                       'add_rule', verify_add_rule)
        driver = linux_net.LinuxBridgeInterfaceDriver()
        driver.plug({"bridge": "br100", "bridge_interface": "eth0"},
                    "fakemac")

    def test_vlan_override(self):
        """Makes sure vlan_interface flag overrides network bridge_interface.

        Allows heterogeneous networks a la bug 833426"""

        driver = linux_net.LinuxBridgeInterfaceDriver()

        info = {}

        @classmethod
        def test_ensure(_self, vlan, bridge, interface, network, mac_address):
            info['passed_interface'] = interface

        self.stubs.Set(linux_net.LinuxBridgeInterfaceDriver,
                       'ensure_vlan_bridge', test_ensure)

        network = {
                "bridge": "br100",
                "bridge_interface": "base_interface",
                "vlan": "fake"
        }
        self.flags(vlan_interface="")
        driver.plug(network, "fakemac")
        self.assertEqual(info['passed_interface'], "base_interface")
        self.flags(vlan_interface="override_interface")
        driver.plug(network, "fakemac")
        self.assertEqual(info['passed_interface'], "override_interface")
        driver.plug(network, "fakemac")

    def test_flat_override(self):
        """Makes sure flat_interface flag overrides network bridge_interface.

        Allows heterogeneous networks a la bug 833426"""

        driver = linux_net.LinuxBridgeInterfaceDriver()

        info = {}

        @classmethod
        def test_ensure(_self, bridge, interface, network, gateway):
            info['passed_interface'] = interface

        self.stubs.Set(linux_net.LinuxBridgeInterfaceDriver,
                       'ensure_bridge', test_ensure)

        network = {
                "bridge": "br100",
                "bridge_interface": "base_interface",
        }
        driver.plug(network, "fakemac")
        self.assertEqual(info['passed_interface'], "base_interface")
        self.flags(flat_interface="override_interface")
        driver.plug(network, "fakemac")
        self.assertEqual(info['passed_interface'], "override_interface")

    def _test_initialize_gateway(self, existing, expected, routes=''):
        self.flags(fake_network=False)
        executes = []

        def fake_execute(*args, **kwargs):
            executes.append(args)
            if args[0] == 'ip' and args[1] == 'addr' and args[2] == 'show':
                return existing, ""
            if args[0] == 'ip' and args[1] == 'route' and args[2] == 'show':
                return routes, ""
        self.stubs.Set(utils, 'execute', fake_execute)
        network = {'dhcp_server': '192.168.1.1',
                   'cidr': '192.168.1.0/24',
                   'broadcast': '192.168.1.255',
                   'cidr_v6': '2001:db8::/64'}
        self.driver.initialize_gateway_device('eth0', network)
        self.assertEqual(executes, expected)

    def test_initialize_gateway_moves_wrong_ip(self):
        existing = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "    mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000\n"
            "    link/ether de:ad:be:ef:be:ef brd ff:ff:ff:ff:ff:ff\n"
            "    inet 192.168.0.1/24 brd 192.168.0.255 scope global eth0\n"
            "    inet6 dead::beef:dead:beef:dead/64 scope link\n"
            "    valid_lft forever preferred_lft forever\n")
        expected = [
            ('sysctl', '-w', 'net.ipv4.ip_forward=1'),
            ('ip', 'addr', 'show', 'dev', 'eth0', 'scope', 'global'),
            ('ip', 'route', 'show', 'dev', 'eth0'),
            ('ip', 'addr', 'del', '192.168.0.1/24',
             'brd', '192.168.0.255', 'scope', 'global', 'dev', 'eth0'),
            ('ip', 'addr', 'add', '192.168.1.1/24',
             'brd', '192.168.1.255', 'dev', 'eth0'),
            ('ip', 'addr', 'add', '192.168.0.1/24',
             'brd', '192.168.0.255', 'scope', 'global', 'dev', 'eth0'),
            ('ip', '-f', 'inet6', 'addr', 'change',
             '2001:db8::/64', 'dev', 'eth0'),
        ]
        self._test_initialize_gateway(existing, expected)

    def test_initialize_gateway_resets_route(self):
        routes = ("default via 192.168.0.1 dev eth0\n"
                  "192.168.100.0/24 via 192.168.0.254 dev eth0 proto static\n")
        existing = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "    mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000\n"
            "    link/ether de:ad:be:ef:be:ef brd ff:ff:ff:ff:ff:ff\n"
            "    inet 192.168.0.1/24 brd 192.168.0.255 scope global eth0\n"
            "    inet6 dead::beef:dead:beef:dead/64 scope link\n"
            "    valid_lft forever preferred_lft forever\n")
        expected = [
            ('sysctl', '-w', 'net.ipv4.ip_forward=1'),
            ('ip', 'addr', 'show', 'dev', 'eth0', 'scope', 'global'),
            ('ip', 'route', 'show', 'dev', 'eth0'),
            ('ip', 'route', 'del', 'default', 'dev', 'eth0'),
            ('ip', 'route', 'del', '192.168.100.0/24', 'dev', 'eth0'),
            ('ip', 'addr', 'del', '192.168.0.1/24',
             'brd', '192.168.0.255', 'scope', 'global', 'dev', 'eth0'),
            ('ip', 'addr', 'add', '192.168.1.1/24',
             'brd', '192.168.1.255', 'dev', 'eth0'),
            ('ip', 'addr', 'add', '192.168.0.1/24',
             'brd', '192.168.0.255', 'scope', 'global', 'dev', 'eth0'),
            ('ip', 'route', 'add', 'default', 'via', '192.168.0.1',
             'dev', 'eth0'),
            ('ip', 'route', 'add', '192.168.100.0/24', 'via', '192.168.0.254',
             'dev', 'eth0', 'proto', 'static'),
            ('ip', '-f', 'inet6', 'addr', 'change',
             '2001:db8::/64', 'dev', 'eth0'),
        ]
        self._test_initialize_gateway(existing, expected, routes)

    def test_initialize_gateway_no_move_right_ip(self):
        existing = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "    mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000\n"
            "    link/ether de:ad:be:ef:be:ef brd ff:ff:ff:ff:ff:ff\n"
            "    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth0\n"
            "    inet 192.168.0.1/24 brd 192.168.0.255 scope global eth0\n"
            "    inet6 dead::beef:dead:beef:dead/64 scope link\n"
            "    valid_lft forever preferred_lft forever\n")
        expected = [
            ('sysctl', '-w', 'net.ipv4.ip_forward=1'),
            ('ip', 'addr', 'show', 'dev', 'eth0', 'scope', 'global'),
            ('ip', '-f', 'inet6', 'addr', 'change',
             '2001:db8::/64', 'dev', 'eth0'),
        ]
        self._test_initialize_gateway(existing, expected)

    def test_initialize_gateway_add_if_blank(self):
        existing = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "    mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000\n"
            "    link/ether de:ad:be:ef:be:ef brd ff:ff:ff:ff:ff:ff\n"
            "    inet6 dead::beef:dead:beef:dead/64 scope link\n"
            "    valid_lft forever preferred_lft forever\n")
        expected = [
            ('sysctl', '-w', 'net.ipv4.ip_forward=1'),
            ('ip', 'addr', 'show', 'dev', 'eth0', 'scope', 'global'),
            ('ip', 'route', 'show', 'dev', 'eth0'),
            ('ip', 'addr', 'add', '192.168.1.1/24',
             'brd', '192.168.1.255', 'dev', 'eth0'),
            ('ip', '-f', 'inet6', 'addr', 'change',
             '2001:db8::/64', 'dev', 'eth0'),
        ]
        self._test_initialize_gateway(existing, expected)

    def test_apply_ran(self):
        manager = linux_net.IptablesManager()
        manager.iptables_apply_deferred = False
        self.mox.StubOutWithMock(manager, '_apply')
        manager._apply()
        self.mox.ReplayAll()
        empty_ret = manager.apply()
        self.assertEqual(empty_ret, None)

    def test_apply_not_run(self):
        manager = linux_net.IptablesManager()
        manager.iptables_apply_deferred = True
        self.mox.StubOutWithMock(manager, '_apply')
        self.mox.ReplayAll()
        manager.apply()

    def test_deferred_unset_apply_ran(self):
        manager = linux_net.IptablesManager()
        manager.iptables_apply_deferred = True
        self.mox.StubOutWithMock(manager, '_apply')
        manager._apply()
        self.mox.ReplayAll()
        manager.defer_apply_off()
        self.assertFalse(manager.iptables_apply_deferred)

    def test_ipsets_manager_create(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        ipsets_manager = linux_net.IpsetsManager()
        ipsets_manager.create('test_ipset', 'bitmap:ip', '10.0.233.0/24')
        expected = [('ipset', 'create', 'test_ipset', 'bitmap:ip', 'range',
                     '10.0.233.0/24')]
        self.assertEqual(self.executes, expected)

        self.executes = []
        ipsets_manager.create('test_ipset_2', 'hash:net')
        expected = [('ipset', 'create', 'test_ipset_2', 'hash:net')]
        self.assertEqual(self.executes, expected)

    def test_ipsets_manager_destroy(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        ipsets_manager = linux_net.IpsetsManager()
        ipsets_manager.destroy('test_ipset')
        expected = [('ipset', 'destroy', 'test_ipset')]
        self.assertEqual(self.executes, expected)

    def test_ipsets_manager_add(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        ipsets_manager = linux_net.IpsetsManager()
        ipsets_manager.add('test_ipset', '10.0.233.10')
        expected = [('ipset', 'add', 'test_ipset', '10.0.233.10')]
        self.assertEqual(self.executes, expected)

    def test_ipsets_manager_delete(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        ipsets_manager = linux_net.IpsetsManager()
        ipsets_manager.delete('test_ipset', '10.0.233.10')
        expected = [('ipset', 'del', 'test_ipset', '10.0.233.10')]
        self.assertEqual(self.executes, expected)

    def test_ipsets_manager_list(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            fake_ipset_list = 'test1\ntest2\ntest3\n'
            return fake_ipset_list, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        ipsets_manager = linux_net.IpsetsManager()
        ret = ipsets_manager.list()
        expected_cmd = [('ipset', '-L', '-name')]
        expected_result = ['test1', 'test2', 'test3']
        self.assertEqual(self.executes, expected_cmd)
        self.assertEqual(ret, expected_result)

    def test_ipsets_manager_members(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            fake_ipset_save = '''
create private-floating-ip-dst hash:net family inet hashsize 1024 maxelem 65536
add private-floating-ip-dst 192.168.1.0/24
add private-floating-ip-dst 172.17.0.0/20
create 68e01370fa704bafa86c6b0efc71b23 bitmap:ip range 10.0.0.0-10.0.255.255
add 68e01370fa704bafa86c6b0efc71b23 10.0.1.10
add 68e01370fa704bafa86c6b0efc71b23 10.0.1.11
add 68e01370fa704bafa86c6b0efc71b23 10.0.10.100
create 1ba988069d304fccb436e73991385c bitmap:ip range 10.120.40.0-10.120.43.255
add 1ba988069d304fccb436e73991385c 10.120.40.68
add 1ba988069d304fccb436e73991385c 10.120.41.72
add 1ba988069d304fccb436e73991385c 10.120.42.54
'''
            return fake_ipset_save, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        ipsets_manager = linux_net.IpsetsManager()
        ret = ipsets_manager.members('68e01370fa704bafa86c6b0efc71b23')
        expected_cmd = [('ipset', 'save')]
        expected_result = ['10.0.1.10', '10.0.1.11', '10.0.10.100']
        self.assertEqual(self.executes, expected_cmd)
        self.assertEqual(ret, expected_result)

        self.executes = []
        ret = ipsets_manager.members('private-floating-ip-dst')
        expected_cmd = [('ipset', 'save')]
        expected_result = ['192.168.1.0/24', '172.17.0.0/20']
        self.assertEqual(self.executes, expected_cmd)
        self.assertEqual(ret, expected_result)

    def test_is_ipset_existed(self):

        def fake_ipsets_manager_list():
            return ['test1', 'test2', 'test3',
                    'b46995d5d4234fecb9f125ffb750751']

        self.stubs.Set(linux_net.ipsets_manager, 'list',
                        fake_ipsets_manager_list)

        case_1 = linux_net.is_ipset_existed('test1')
        case_2 = linux_net.is_ipset_existed('test2')
        case_3 = linux_net.is_ipset_existed('test3')
        case_4 = linux_net.is_ipset_existed('test4')
        case_5 = linux_net.is_ipset_existed('b46995d5d4234fecb9f125ffb750751b')

        self.assertTrue(case_1)
        self.assertTrue(case_2)
        self.assertTrue(case_3)
        self.assertFalse(case_4)
        self.assertTrue(case_5)

    def test_create_tenant_ipset(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        def fake_list(*args, **kwargs):
            return ['test', 'test2']

        def fake_members(*args, **kwargs):
            return ['10.0.233.1']

        def fake_instance_get_all_by_project(*args, **kwargs):
            instances = [{'id': 0,
                          'uuid': '1111',
                          'host': 'fake_instance00',
                          'created_at': 'fakedate',
                          'updated_at': 'fakedate',
                          'hostname': 'fake_instance00'}]
            return instances

        def fake_fixed_ip_get_by_instance(*args, **kwargs):
            fixed_ips = [{'id': 0,
                          'network_id': 0,
                          'address': '10.0.233.100',
                          'instance_uuid': '1111',
                          'allocated': True,
                          'virtual_interface_id': 0,
                          'instance_id': 0,
                          'floating_ips': []}]
            return fixed_ips

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.IpsetsManager, 'list', fake_list)
        self.stubs.Set(linux_net.IpsetsManager, 'members', fake_members)
        self.stubs.Set(db, 'instance_get_all_by_project',
                            fake_instance_get_all_by_project)
        self.stubs.Set(db, 'fixed_ip_get_by_instance',
                            fake_fixed_ip_get_by_instance)

        linux_net.create_tenant_ipset('b46995d5d4234fecb9f125ffb750751b',
                                        '10.0.233.0/24')
        expected = [('ipset', 'create', 'b46995d5d4234fecb9f125ffb750751',
                     'bitmap:ip', 'range', '10.0.233.0/24'),
                    ('ipset', 'add', 'b46995d5d4234fecb9f125ffb750751',
                                        '10.0.233.100',)]
        self.assertEqual(self.executes, expected)

    def test_add_address_to_ipset(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        def fake_members(*args, **kwargs):
            return ['10.0.10.1']

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.IpsetsManager, 'members', fake_members)

        linux_net.add_address_to_ipset('10.0.233.10', 'test_ipset')
        expected = [('ipset', 'add', 'test_ipset', '10.0.233.10')]
        self.assertEqual(self.executes, expected)

        self.executes = []
        linux_net.add_address_to_ipset('10.0.233.11',
                                        'b46995d5d4234fecb9f125ffb750751b')
        expected = [('ipset', 'add', 'b46995d5d4234fecb9f125ffb750751',
                                        '10.0.233.11')]
        self.assertEqual(self.executes, expected)

        self.executes = []
        linux_net.add_address_to_ipset('10.0.10.1', 'test_ipset')
        expected = []
        self.assertEqual(self.executes, expected)

    def test_delete_address_from_ipset(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        def fake_members(*args, **kwargs):
            return ['10.0.233.10', '10.0.233.11']

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.IpsetsManager, 'members', fake_members)

        linux_net.delete_address_from_ipset('10.0.233.10', 'test_ipset')
        expected = [('ipset', 'del', 'test_ipset', '10.0.233.10')]
        self.assertEqual(self.executes, expected)

        self.executes = []
        linux_net.delete_address_from_ipset('10.0.233.11',
                                            'b46995d5d4234fecb9f125ffb750751b')
        expected = [('ipset', 'del', 'b46995d5d4234fecb9f125ffb750751',
                        '10.0.233.11')]
        self.assertEqual(self.executes, expected)


class  TcManagerTestCase(test.TestCase):

    def setUp(self):
        super(TcManagerTestCase, self).setUp()
        network_driver = FLAGS.network_driver
        self.driver = importutils.import_module(network_driver)
        self.driver.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

    def test_init_network_qos_device(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return 'ifb0, ifb1', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        self.executes = []

        def fake_get_network_qos_config(self):
            return Fake_Network_QoS_Config

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.TcManager, 'get_network_qos_config',
                                      fake_get_network_qos_config)

        tc_mana = linux_net.TcManager()
        tc_mana._init_network_qos_device()

    def test_init_network_qos_device_nodev(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        def fake_get_network_qos_config(self):
            return Fake_Network_QoS_Config

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.TcManager, 'get_network_qos_config',
                                      fake_get_network_qos_config)

        tc_mana = linux_net.TcManager()
        self.assertRaises(exception.TcDeviceNotFound,
                                 tc_mana._init_network_qos_device)

    def test_init_network_qos_device_errordev(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return 'ifb2,ifb3', None

        def fake_get_network_qos_config(self):
            return Fake_Network_QoS_Config

        self.stubs.Set(linux_net, '_execute', fake_execute)
        self.stubs.Set(linux_net.TcManager, 'get_network_qos_config',
                                      fake_get_network_qos_config)

        tc_mana = linux_net.TcManager()
        self.assertRaises(exception.InvalidTcDevice,
                         tc_mana._init_network_qos_device)

    def test_register_no_tc(self):
        instance_id = '123'
        var = mox.IgnoreArg()
        instances = [{'uuid': 'fake_uuid', 'id': 'fake_id'}]
        self.mox.StubOutWithMock(linux_net.db, 'instance_get_all_by_host')
        linux_net.db.instance_get_all_by_host(var, var).\
                          AndReturn(instances)

        smd = {'network-tc-id': '1000'}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(var, var).\
                          AndReturn(smd)

        self.mox.ReplayAll()
        tc_mana = linux_net.TcManager()
        self.assertRaises(exception.TcNotFound,
                                 tc_mana._register,
                                 instance_id)
        self.mox.VerifyAll()

    def test_register(self):
        instance_id = '123'
        var = mox.IgnoreArg()
        instances = [{'uuid': '1000', 'id': 123}]
        self.mox.StubOutWithMock(linux_net.db, 'instance_get_all_by_host')
        linux_net.db.instance_get_all_by_host(var, var).\
                          AndReturn(instances)

        smd = {'network-tc-id': '123'}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(var, var).\
                          AndReturn(smd)

        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()
        result = tc_mana._register(instance_id)
        self.assertEqual(result, 123)

    def test_get_instance_qos_id(self):
        instance = {'uuid': 'fake_uuid'}
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
        result = tc_mana._get_instance_qos_id(instance)
        self.assertEqual(result, 123)

    def test_get_instance_qos_id_no_ins(self):
        instance_id = '123'
        ctxt = mox.IgnoreArg()
        self.mox.StubOutWithMock(linux_net.db, 'instance_get')
        linux_net.db.instance_get(ctxt, ctxt).\
                          AndRaise(exception.InstanceNotFound)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()
        self.assertRaises(exception.InvalidTcInstanceId,
                                  tc_mana._get_instance_qos_id,
                                  instance_id)

    def test_get_instance_qos_id_invalid_id(self):
        instance_id = '123'
        instance = {'uuid': 'fake_uuid'}
        ctxt = mox.IgnoreArg()
        self.mox.StubOutWithMock(linux_net.db, 'instance_get')
        linux_net.db.instance_get(ctxt, ctxt).\
                          AndReturn(instance)

        sys_metadata = {'network-tc-id': None}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(ctxt, ctxt).\
                          AndReturn(sys_metadata)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()
        self.assertRaises(exception.InvalidTcInstanceId,
                                  tc_mana._get_instance_qos_id,
                                  instance_id)

    def test_instance_fw_mark(self):
        instance_id = '123'
        instance = {'uuid': 'fake_uuid'}
        ctxt = mox.IgnoreArg()
        self.mox.StubOutWithMock(linux_net.db, 'instance_get')
        linux_net.db.instance_get(ctxt, ctxt).\
                          AndReturn(instance)

        sys_metadata = {'network-tc-id': '1'}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(ctxt, ctxt).\
                          AndReturn(sys_metadata)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()

        result = tc_mana._instance_fw_mark(instance_id)
        self.assertEqual(result, hex(int(tc_mana.fw_mask, 16) + 1))

    def test_instance_tc_class_id(self):
        instance_id = '123'
        qtype = 'public'
        instance = {'uuid': 'fake_uuid'}
        ctxt = mox.IgnoreArg()

        self.mox.StubOutWithMock(linux_net.db, 'instance_get')
        linux_net.db.instance_get(ctxt, ctxt).\
                          AndReturn(instance)

        sys_metadata = {'network-tc-id': '1'}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(ctxt, ctxt).\
                          AndReturn(sys_metadata)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()

        result = tc_mana._instance_tc_class_id(instance_id, qtype)
        self.assertEqual(result, hex(int(tc_mana.tc_class_pub_mask, 16) + 1))

    def test_instance_tc_filter_pref(self):
        instance_id = '123'
        qtype = 'public'
        instance = {'uuid': 'fake_uuid'}
        ctxt = mox.IgnoreArg()

        self.mox.StubOutWithMock(linux_net.db, 'instance_get')
        linux_net.db.instance_get(ctxt, ctxt).\
                          AndReturn(instance)

        sys_metadata = {'network-tc-id': '1'}
        self.mox.StubOutWithMock(linux_net.db, 'instance_system_metadata_get')
        linux_net.db.instance_system_metadata_get(ctxt, ctxt).\
                          AndReturn(sys_metadata)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()

        result = tc_mana._instance_tc_filter_pref(instance_id, qtype)
        self.assertEqual(result, tc_mana.tc_filter_pub_mask + 1)

    def test_add_instance_class(self):
        instance_id = 123
        qtype = ['public', 'private']
        node = ['ingress', 'egress']
        spec = {'rate': 100}
        class_id = '40'
        spec = {'rate': 10}

        tc_mana = linux_net.TcManager()

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        for i in node:
            for j in qtype:
                if i == 'egress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:', 'classid', '9:40',
                               'htb', 'rate', '10mbit'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:40', 'classid', '9:40',
                               'htb', 'rate', '10mbit')]
                    self.executes = []

                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                             AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pub_cls', tc_mana.e_pub_cls)

                    tc_mana.add_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'egress' and j == 'private':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:', 'classid', '9:40',
                               'htb', 'rate', '10mbit'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:40', 'classid', '9:40',
                               'htb', 'rate', '10mbit')]
                    self.executes = []

                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pvt_cls = tc_mana.egress.add_class(
                                                '40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pvt_cls', tc_mana.e_pvt_cls)

                    tc_mana.add_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'ingress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:', 'classid', '9:40',
                               'htb', 'rate', '10mbit'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:40', 'classid', '9:40',
                               'htb', 'rate', '10mbit')]
                    self.executes = []

                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pub_cls = tc_mana.ingress.add_class(
                                                '40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                    'i_pub_cls', tc_mana.i_pub_cls)

                    tc_mana.add_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                else:
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:', 'classid', '9:40',
                               'htb', 'rate', '10mbit'),
                              ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                               'parent', '9:40', 'classid', '9:40',
                               'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pvt_cls = tc_mana.ingress.add_class(
                                                '40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                   'i_pvt_cls', tc_mana.i_pvt_cls)

                    tc_mana.add_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

    def test_add_instance_filter_noClass(self):
        net_opt = network_qos_opt()
        instance_id = 123
        qtype = 'public'
        node = 'ingress'
        spec = {'rate': 100}
        public_bandwidth = int(
                                FLAGS.network_qos_host_public_bandwidth *
                                FLAGS.network_qos_public_allocation_ratio -
                                FLAGS.reserved_host_network_public_bandwidth)
        public_spec = {
                       'rate': public_bandwidth,
                      }

        self.mox.StubOutWithMock(linux_net.TcManager,
                                 '_instance_tc_class_id')
        linux_net.TcManager._instance_tc_class_id(instance_id, qtype).\
                                  AndReturn(40)

        self.mox.StubOutWithMock(linux_net.TcManager,
                                 '_instance_tc_filter_pref')
        linux_net.TcManager._instance_tc_filter_pref(instance_id, qtype).\
                                  AndReturn(30000)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()
        tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
        tc_mana.ingress.apply()
        tc_mana.i_pub_cls = tc_mana.ingress.add_class(
                                                '40', public_spec)

        self.stubs.Set(linux_net.TcManager, 'i_pub_cls', tc_mana.i_pub_cls)

        self.assertRaises(exception.TcClassNotFound,
                                 tc_mana.add_instance_filter,
                                 instance_id, qtype, node, spec)

    def test_add_instance_filter(self):
        net_opt = network_qos_opt()
        expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                   'root', 'handle', '9:', 'htb'),
                  ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                   '9:', 'classid', '9:40', 'htb', 'rate', '90mbit'),
                  ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                   '9:40', 'classid', '9:40', 'htb', 'rate', '90mbit'),
                 ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'], 'protocol',
                  'ip', 'parent', '9:', 'pref', '30000', 'u32', 'match', 'ip',
                   'dst', '10.0.0.1/32', 'classid', '9:40')]

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        instance_id = 40
        qtype = 'public'
        node = 'ingress'
        address = '10.0.0.1'

        public_bandwidth = int(
                                FLAGS.network_qos_host_public_bandwidth *
                                FLAGS.network_qos_public_allocation_ratio -
                                FLAGS.reserved_host_network_public_bandwidth)
        public_spec = {
                       'rate': public_bandwidth,
                      }

        self.mox.StubOutWithMock(linux_net.TcManager, '_instance_tc_class_id')
        linux_net.TcManager._instance_tc_class_id(instance_id, qtype).\
                      AndReturn('40')

        self.mox.StubOutWithMock(linux_net.TcManager,
                                 '_instance_tc_filter_pref')
        linux_net.TcManager._instance_tc_filter_pref(instance_id, qtype).\
                                 AndReturn(30000)

        tc_mana = linux_net.TcManager()
        tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
        tc_mana.ingress.apply()
        tc_mana.i_pub_cls = tc_mana.ingress.add_class(
                                                '40', public_spec)
        tc_mana.i_pub_cls.add_class('40', public_spec)

        self.stubs.Set(linux_net.TcManager, 'i_pub_cls', tc_mana.i_pub_cls)
        self.mox.ReplayAll()

        tc_mana.add_instance_filter(instance_id, qtype, node, address)
        self.assertEqual(expect, self.executes)

    def test_add_snat_egress_filter_no_class(self):
        instance_id = 40

        public_bandwidth = int(
                                FLAGS.network_qos_host_public_bandwidth *
                                FLAGS.network_qos_public_allocation_ratio -
                                FLAGS.reserved_host_network_public_bandwidth)
        public_spec = {
                       'rate': public_bandwidth,
                      }

        fwmark = '0x10000000'
        self.mox.StubOutWithMock(linux_net.TcManager, '_instance_fw_mark')
        linux_net.TcManager._instance_fw_mark(instance_id).\
                      AndReturn(fwmark)

        class_id = '40'
        self.mox.StubOutWithMock(linux_net.TcManager, '_instance_tc_class_id')
        linux_net.TcManager._instance_tc_class_id(instance_id, 'public').\
                      AndReturn(class_id)

        pref = 30000
        self.mox.StubOutWithMock(linux_net.TcManager,
                                 '_instance_tc_filter_pref')
        linux_net.TcManager._instance_tc_filter_pref(instance_id, 'snat').\
                                 AndReturn(pref)

        tc_mana = linux_net.TcManager()
        tc_mana.egress = linux_net.TcQdisc(dev='40',
                                  node='root', handle='9', type='htb')
        tc_mana.egress.apply()
        tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', public_spec)

        self.stubs.Set(linux_net.TcManager, 'e_pub_cls', tc_mana.e_pub_cls)
        self.mox.ReplayAll()

        self.assertRaises(exception.TcClassNotFound,
                                 tc_mana.add_snat_egress_filter,
                                 instance_id)

    def test_add_snat_egress_filter(self):
        net_opt = network_qos_opt()
        self.executes = []
        expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                   'root', 'handle', '9:', 'htb'),
                  ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                   'parent', '9:', 'classid', '9:40',
                   'htb', 'rate', '90mbit'),
                  ('tc', 'class', 'add', 'dev', net_opt['phy_inf'],
                   'parent', '9:40', 'classid', '9:40',
                   'htb', 'rate', '90mbit'),
                  ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                   'protocol', 'ip', 'parent', '9:', 'pref', '30000',
                   'handle', net_opt['tc_mark'], 'fw', 'classid', '9:40')]

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        instance_id = 40
        public_bandwidth = int(
                                FLAGS.network_qos_host_public_bandwidth *
                                FLAGS.network_qos_public_allocation_ratio -
                                FLAGS.reserved_host_network_public_bandwidth)
        public_spec = {
                       'rate': public_bandwidth,
                      }

        fwmark = net_opt['tc_mark']
        self.mox.StubOutWithMock(linux_net.TcManager, '_instance_fw_mark')
        linux_net.TcManager._instance_fw_mark(instance_id).\
                      AndReturn(fwmark)

        class_id = '40'
        self.mox.StubOutWithMock(linux_net.TcManager, '_instance_tc_class_id')
        linux_net.TcManager._instance_tc_class_id(instance_id, 'public').\
                      AndReturn(class_id)

        pref = 30000
        self.mox.StubOutWithMock(linux_net.TcManager,
                                 '_instance_tc_filter_pref')
        linux_net.TcManager._instance_tc_filter_pref(instance_id, 'snat').\
                      AndReturn(pref)

        tc_mana = linux_net.TcManager()
        tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
        tc_mana.egress.apply()
        tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', public_spec)
        tc_mana.e_pub_cls.add_class('40', public_spec)

        self.stubs.Set(linux_net.TcManager, 'e_pub_cls', tc_mana.e_pub_cls)
        self.mox.ReplayAll()

        tc_mana.add_snat_egress_filter(instance_id)
        self.assertEqual(expect, self.executes)

    def test_del_instance_class(self):
        expect = []

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        instance_id = 40
        node = ['egress', 'ingress']
        qtype = ['public', 'private']
        spec = {'rate': 10}
        class_id = '40'

        tc_mana = linux_net.TcManager()

        for i in node:
            for j in qtype:
                if i == 'egress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                            '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                             AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', spec)
                    tc_mana.e_pub_cls.add_class('40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pub_cls', tc_mana.e_pub_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'egress' and j == 'private':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pvt_cls = tc_mana.egress.add_class(
                                                '40', spec)
                    tc_mana.e_pvt_cls.add_class('40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pvt_cls', tc_mana.e_pvt_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'ingress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pub_cls = tc_mana.ingress.add_class(
                                                '40', spec)
                    tc_mana.i_pub_cls.add_class('40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                   'i_pub_cls', tc_mana.i_pub_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                else:
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                  AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pvt_cls = tc_mana.ingress.add_class(
                                                '40', spec)
                    tc_mana.i_pvt_cls.add_class('40', spec)

                    self.stubs.Set(linux_net.TcManager,
                                   'i_pvt_cls', tc_mana.i_pvt_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(self.executes, expect)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

    def test_del_instance_filter(self):
        instance_id = 40
        node = ['egress', 'ingress']
        qtype = ['public', 'private']
        spec = {'rate': 10}
        class_id = '40'
        address = '10.0.0.1'

        tc_mana = linux_net.TcManager()
        expect = []
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        for i in node:
            for j in qtype:
                if i == 'egress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'filter', 'del', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', spec)
                    c = tc_mana.e_pub_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pub_cls', tc_mana.e_pub_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'egress' and j == 'private':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'filter', 'del', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pvt_cls = tc_mana.egress.add_class(
                                                '40', spec)
                    c = tc_mana.e_pvt_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pvt_cls', tc_mana.e_pvt_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(self.executes, expect)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'ingress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'filter', 'del', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                              '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                               AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pub_cls = tc_mana.ingress.add_class(
                                                '40', spec)
                    c = tc_mana.i_pub_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'i_pub_cls', tc_mana.i_pub_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(self.executes, expect)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                else:
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'filter', 'del', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'del', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                  AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pvt_cls = tc_mana.ingress.add_class(
                                                '40', spec)
                    c = tc_mana.i_pvt_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'i_pvt_cls', tc_mana.i_pvt_cls)

                    tc_mana.del_instance_class(instance_id, j, i)
                    self.assertEqual(self.executes, expect)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

    def test_mod_instance_class_noClass(self):
        instance_id = 40
        node = 'egress'
        qtype = 'public'
        spec = {'rate': 10}
        class_id = '400'

        self.mox.StubOutWithMock(linux_net.TcManager, '_instance_tc_class_id')
        linux_net.TcManager._instance_tc_class_id(instance_id, qtype).\
                       AndReturn(class_id)
        self.mox.ReplayAll()

        tc_mana = linux_net.TcManager()
        tc_mana.egress = linux_net.TcQdisc(dev='40',
                                  node='root', handle='9', type='htb')
        tc_mana.egress.apply()
        tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', spec)
        tc_mana.e_pub_cls.add_class('40', spec)

        self.stubs.Set(linux_net.TcManager, 'e_pub_cls', tc_mana.e_pub_cls)

        self.assertRaises(exception.TcClassNotFound,
                                 tc_mana.mod_instance_class,
                                 instance_id, qtype, node, spec)

    def test_mod_instance_class(self):
        instance_id = 40
        node = ['egress', 'ingress']
        qtype = ['public', 'private']
        spec = {'rate': 10}
        class_id = '40'
        address = '10.0.0.1'

        tc_mana = linux_net.TcManager()
        expect = []
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        for i in node:
            for j in qtype:
                if i == 'egress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'change', 'dev', net_opt['phy_inf'],
                     'parent', '9:40', 'classid', '9:40', 'htb', 'rate',
                     '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                             AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pub_cls = tc_mana.egress.add_class(
                                                '40', spec)
                    c = tc_mana.e_pub_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pub_cls', tc_mana.e_pub_cls)

                    tc_mana.mod_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'egress' and j == 'private':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'src', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'change', 'dev', net_opt['phy_inf'],
                     'parent', '9:40', 'classid', '9:40', 'htb', 'rate',
                     '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                  AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.egress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.egress.apply()
                    tc_mana.e_pvt_cls = tc_mana.egress.add_class(
                                                '40', spec)
                    c = tc_mana.e_pvt_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'e_pvt_cls', tc_mana.e_pvt_cls)

                    tc_mana.mod_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                elif i == 'ingress' and j == 'public':
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'change', 'dev', net_opt['phy_inf'],
                     'parent', '9:40', 'classid', '9:40', 'htb', 'rate',
                     '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pub_cls = tc_mana.ingress.add_class(
                                                '40', spec)
                    c = tc_mana.i_pub_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'i_pub_cls', tc_mana.i_pub_cls)

                    tc_mana.mod_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()

                else:
                    net_opt = network_qos_opt()
                    expect = [('tc', 'qdisc', 'add', 'dev', net_opt['phy_inf'],
                               'root', 'handle', '9:', 'htb'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'class', 'add', 'dev', net_opt['phy_inf'], 'parent',
                     '9:40', 'classid', '9:40', 'htb', 'rate', '10mbit'),
                    ('tc', 'filter', 'add', 'dev', net_opt['phy_inf'],
                     'protocol', 'ip', 'parent', '9:', 'pref', '1', 'u32',
                     'match', 'ip', 'dst', '10.0.0.1/32', 'classid', '9:40'),
                    ('tc', 'class', 'change', 'dev', net_opt['phy_inf'],
                     'parent', '9:40', 'classid', '9:40', 'htb', 'rate',
                     '10mbit')]
                    self.executes = []
                    self.mox.StubOutWithMock(linux_net.TcManager,
                                             '_instance_tc_class_id')
                    linux_net.TcManager._instance_tc_class_id(instance_id, j).\
                                              AndReturn(class_id)
                    self.mox.ReplayAll()

                    tc_mana.ingress = linux_net.TcQdisc(dev=net_opt['phy_inf'],
                                  node='root', handle='9', type='htb')
                    tc_mana.ingress.apply()
                    tc_mana.i_pvt_cls = tc_mana.ingress.add_class(
                                                '40', spec)
                    c = tc_mana.i_pvt_cls.add_class('40', spec)
                    c.add_filter('ip', 1, i, address)

                    self.stubs.Set(linux_net.TcManager,
                                   'i_pvt_cls', tc_mana.i_pvt_cls)

                    tc_mana.mod_instance_class(instance_id, j, i, spec)
                    self.assertEqual(expect, self.executes)

                    self.mox.UnsetStubs()
                    self.mox.VerifyAll()


class  TcQdiscTestCase(test.TestCase):
    def setUp(self):
        super(TcQdiscTestCase, self).setUp()
        network_driver = FLAGS.network_driver
        self.driver = importutils.import_module(network_driver)
        self.driver.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

        def get_vifs(_context, instance_uuid):
            return [vif for vif in vifs
                    if vif['instance_uuid'] == instance_uuid]

        def get_instance(_context, instance_id):
            return instances[instance_id]

        self.stubs.Set(db, 'virtual_interface_get_by_instance', get_vifs)
        self.stubs.Set(db, 'instance_get', get_instance)
        self.stubs.Set(db, 'network_get_associated_fixed_ips', get_associated)

    def test__str__(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                               handle='100', type='htb')
        result = tq.__str__()
        expect_result = 'dev eth0 root handle 100: htb'
        self.assertEqual(result, expect_result)

    def test_apply_ran(self):
        expect = [('tc', 'qdisc', 'add', 'dev', 'eth0', 'root', 'handle',
                   '100:', 'htb')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        tq = linux_net.TcQdisc(dev='eth0', node='root',
                               handle='100', type='htb')
        tq.apply()
        self.assertEqual(expect, self.executes)

    def test_to_list(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                handle='100', type='htb')
        result = tq.to_list()
        expect = ['dev', 'eth0', 'root', 'handle', '100:', 'htb']
        self.assertEqual(result, expect)

    def test_apply(self):
        expect = [('tc', 'qdisc', 'fake_action', 'dev', 'eth0', 'root',
                   'handle', '100:', 'htb')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)
        action = 'fake_action'
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                               handle='100', type='htb')
        tq._apply(action)
        self.assertEqual(expect, self.executes)

    def test_delete(self):
        expect = [('tc', 'qdisc', 'del', 'dev', 'eth0', 'root',
                   'handle', '100:', 'htb')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        tq.delete()
        self.assertEqual(expect, self.executes)

    def test_add_class(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                               handle='100', type='htb')
        class_id = '100'
        result = tq.add_class(class_id, spec={'fake_spec': ''})
        self.assertEqual(tq.cls[class_id], result)

    def test_add_filter(self):
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        protocol = 'ip'
        pref = 1
        filter_type = 'u32'
        filter_params = 'match u32 0 0'
        action = 'mirred egress redirect dev eth0'
        result = tq.add_filter(protocol, pref, filter_type,
                               filter_params, None, action)
        self.assertEqual(tq.filt[pref], result)

    def test_del_class(self):
        expect = [('tc', 'class', 'add', 'dev', 'eth0', 'parent', '100:',
                   'classid', '100:100', 'htb', 'fake_spec', ''),
                  ('tc', 'class', 'del', 'dev', 'eth0', 'parent', '100:',
                   'classid', '100:100', 'htb', 'fake_spec', '')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        class_id = '100'
        result = tq.add_class(class_id, spec={'fake_spec': ''})
        self.assertEqual(tq.cls[class_id], result)
        tq.del_class(class_id)
        self.assertEqual(expect, self.executes)

    def test_del_filter(self):
        expect = [('tc', 'filter', 'add', 'dev', 'eth0', 'protocol', 'ip',
          'parent', '100:', 'pref', '1', 'u32', 'match', 'u32', '0', '0',
          'action', 'mirred', 'egress', 'redirect', 'dev', 'eth0'),
         ('tc', 'filter', 'del', 'dev', 'eth0', 'protocol', 'ip', 'parent',
          '100:', 'pref', '1', 'u32', 'match', 'u32', '0', '0', 'action',
          'mirred', 'egress', 'redirect', 'dev', 'eth0')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        protocol = 'ip'
        pref = 1
        filter_type = 'u32'
        filter_params = 'match u32 0 0'
        action = 'mirred egress redirect dev eth0'

        tq.add_filter(protocol, pref, filter_type,
                   filter_params, None, action)
        tq.del_filter(pref)
        self.assertEqual(expect, self.executes)

    def test_get_class(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        class_id = '100'
        tc_cls = tq.add_class(class_id, spec={'fake_spec': ''})
        result = tq.get_class(class_id)
        self.assertEqual(result, tc_cls)

    def test_get_filter(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        pref = 1
        protocol = 'ip'
        filter_type = 'u32'
        filter_params = 'match u32 0 0'
        action = 'mirred egress redirect dev eth0'

        tc_filt = tq.add_filter(protocol, pref, filter_type,
                   filter_params, None, action)
        result = tq.get_filter(pref)
        self.assertEqual(result, tc_filt)

    def test_get_valid_class_id(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        class_id = '100'
        tq.add_class(class_id, spec={'fake_spec': ''})
        result = tq.get_valid_class_id()
        expect = [class_id]
        self.assertEqual(result, expect)

        class_id2 = '101'
        result = tq.add_class(class_id2, spec={'fake_spec': ''})
        result = tq.get_valid_class_id()
        expect = [class_id, class_id2]
        self.assertEqual(result, expect)

        tq.del_class(class_id)
        result = tq.get_valid_class_id()
        expect = [class_id2]
        self.assertEqual(result, expect)

    def test_get_valid_class(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        class_id = '100'
        tc_cls = tq.add_class(class_id, spec={'fake_spec': ''})
        result = tq.get_valid_class()
        expect = [tc_cls]
        self.assertEqual(result, expect)

        class_id2 = '101'
        tc_cls2 = tq.add_class(class_id2, spec={'fake_spec': ''})
        result = tq.get_valid_class()
        expect = [tc_cls, tc_cls2]
        self.assertEqual(result, expect)

        tq.del_class(class_id)
        result = tq.get_valid_class()
        expect = [tc_cls2]
        self.assertEqual(result, expect)

    def test_get_all_class(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        class_id = '100'
        tc_cls = tq.add_class(class_id, spec={'fake_spec': ''})
        result = tq.get_all_class()
        expect = {class_id: tc_cls}
        self.assertEqual(result, expect)

        class_id2 = '101'
        tc_cls2 = tq.add_class(class_id2, spec={'fake_spec': ''})
        result = tq.get_all_class()
        expect = {class_id: tc_cls, class_id2: tc_cls2}
        self.assertEqual(result, expect)

        tq.del_class(class_id)
        result = tq.get_all_class()
        expect = {class_id: tc_cls, class_id2: tc_cls2}
        self.assertEqual(result, expect)

    def test_get_valid_filter_pref(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        protocol = 'ip'
        pref = 1
        filter_type = 'u32'
        filter_params = 'match u32 0 0'
        action = 'mirred egress redirect dev eth0'

        result = tq.add_filter(protocol, pref, filter_type,
                                       filter_params, None, action)

        result = tq.get_valid_filter_pref()
        expect = [pref]
        self.assertEqual(result, expect)

        pref2 = 2
        tq.add_filter(protocol, pref2, filter_type,
                                       filter_params, None, action)
        result = tq.get_valid_filter_pref()
        expect = [pref, pref2]
        self.assertEqual(result, expect)

        tq.del_filter(pref)
        result = tq.get_valid_filter_pref()
        expect = [pref2]
        self.assertEqual(result, expect)

    def test_get_valid_filter(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        protocol = 'ip'
        pref = 1
        filter_type = 'u32'
        filter_params = 'match u32 0 0'
        action = 'mirred egress redirect dev eth0'

        tc_filt = tq.add_filter(protocol, pref, filter_type,
                                       filter_params, None, action)
        result = tq.get_valid_filter()
        expect = [tc_filt]
        self.assertEqual(result, expect)

        pref2 = 2
        tc_filt2 = tq.add_filter(protocol, pref2, filter_type,
                                       filter_params, None, action)
        result = tq.get_valid_filter()
        expect = [tc_filt, tc_filt2]
        self.assertEqual(result, expect)

        tq.del_filter(pref)
        result = tq.get_valid_filter()
        expect = [tc_filt2]
        self.assertEqual(result, expect)

    def test_get_all_filter(self):
        tq = linux_net.TcQdisc(dev='eth0', node='root',
                                          handle='100', type='htb')
        protocol = 'ip'
        pref = 1
        filter_type = 'u32'
        filter_params = 'match u32 0 0'
        action = 'mirred egress redirect dev eth0'

        tc_filt = tq.add_filter(protocol, pref, filter_type,
                                       filter_params, None, action)
        result = tq.get_all_filter()
        expect = {1: tc_filt}
        self.assertEqual(result, expect)

        pref2 = 2
        tc_filt2 = tq.add_filter(protocol, pref2, filter_type,
                                       filter_params, None, action)
        result = tq.get_all_filter()
        expect = {1: tc_filt, 2: tc_filt2}
        self.assertEqual(result, expect)

        tq.del_filter(pref)
        result = tq.get_all_filter()
        expect = {1: tc_filt, 2: tc_filt2}
        self.assertEqual(result, expect)


class  TcClassTestCase(test.TestCase):

    def setUp(self):
        super(TcClassTestCase, self).setUp()
        network_driver = FLAGS.network_driver
        self.driver = importutils.import_module(network_driver)
        self.driver.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

    def test__str__(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}

        tc = linux_net.TcClass(dev, node_id, parent_id,
                           class_id, type, spec)

        result = tc.__str__()
        expect_result = 'dev eth0 parent 10:10 classid 10:10 htb rate 10mbit'
        self.assertEqual(result, expect_result)

    def test_apply_ran(self):
        expect = []

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                           class_id, type, spec)
        self.mox.StubOutWithMock(tc, '_apply')
        tc._apply(mox.IgnoreArg())
        self.mox.ReplayAll()
        tc.apply()

        self.assertEqual(self.executes, expect)

    def test_to_list(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                           class_id, type, spec)

        result = tc.to_list()
        expect = ['dev', 'eth0', 'parent', '10:10', 'classid',\
                     '10:10', 'htb', 'rate', '10mbit']
        self.assertEqual(result, expect)

    def test_apply(self):
        expect = [('tc', 'class', 'fake_action', 'dev', 'eth0', 'parent',
                   '10:10', 'classid', '10:10', 'htb', 'rate', '10mbit')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        action = 'fake_action'
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        tc._apply(action)
        self.assertEqual(expect, self.executes)

    def test_delete(self):
        expect = [('tc', 'class', 'del', 'dev', 'eth0', 'parent',
                   '10:10', 'classid', '10:10', 'htb', 'rate', '10mbit')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        tc.delete()
        self.assertEqual(expect, self.executes)

    def test_change(self):
        expect = [('tc', 'class', 'change', 'dev', 'eth0', 'parent',
                   '10:10', 'classid', '10:10', 'htb', 'rate', '10mbit')]

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = []
        self.assertRaises(exception.InvalidTcParam,
                                 linux_net.TcClass, dev,
                                 node_id, parent_id, class_id, type, spec)
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        tc.change(spec)
        self.assertEqual(expect, self.executes)

    def test_add_class(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        result = tc.add_class(class_id, spec)
        self.assertEqual(tc.cls[class_id], result)

    def test_mod_class(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        class_id2 = '11'
        tc.add_class(class_id2, spec)
        new_spec = {'rate': 11}

        tc_cls = tc.mod_class(class_id2, new_spec)

        tc.mod_class(class_id2, new_spec)
        self.assertEqual(new_spec, tc_cls.spec)

    def test_del_class(self):
        expect = []

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        tc.del_class(class_id)
        self.assertEqual(expect, self.executes)

    def test_add_filter(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        address = 'source_ip'
        node = 'ingress'
        protocol = 'ip'
        pref = 2
        tc_filt = tc.add_filter(protocol, pref, node, address)

        self.assertEqual(tc.filt[address], tc_filt)

    def test_add_snat_egress_filter(self):
        expect = [('tc', 'filter', 'add', 'dev', 'eth0', 'protocol',
                   'ip', 'parent', '10:', 'pref', '2', 'handle',
                   '0x1000', 'fw', 'classid', '10:10')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}

        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        protocol = 'ip'
        pref = 2
        fwmark = '0x1000'
        tc.add_snat_egress_filter(protocol, pref, fwmark)
        self.assertEqual(expect, self.executes)

    def test_del_filter(self):
        expect = [('tc', 'filter', 'add', 'dev', 'eth0', 'protocol',
                   'ip', 'parent', '10:', 'pref', '2', 'u32', 'match',
                   'ip', 'dst', 'source_ip/32', 'classid', '10:10'),
                  ('tc', 'filter', 'del', 'dev', 'eth0', 'protocol',
                   'ip', 'parent', '10:', 'pref', '2', 'u32', 'match',
                   'ip', 'dst', 'source_ip/32', 'classid', '10:10')]

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        address = 'source_ip'
        node = 'ingress'
        protocol = 'ip'
        pref = 2
        tc_filt = tc.add_filter(protocol, pref, node, address)
        self.assertEqual(tc.filt[address], tc_filt)

        tc.del_filter(address)
        self.assertEqual(expect, self.executes)

    def test_get_class(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        tc_cls = tc.add_class(class_id, spec)
        result = tc.get_class(class_id)
        self.assertEqual(result, tc_cls)

    def test_get_filter(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        address = 'source_ip'
        node = 'ingress'
        protocol = 'ip'
        pref = 2
        tc_filt = tc.add_filter(protocol, pref, node, address)

        result = tc.get_filter(address)
        self.assertEqual(result, tc_filt)

    def test_get_valid_class_id(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        tc.add_class(class_id, spec)
        result = tc.get_valid_class_id()
        self.assertEqual(result, [class_id])

        class_id2 = '11'
        tc.add_class(class_id2, spec)
        result = tc.get_valid_class_id()
        self.assertEqual(result, [class_id2, class_id])

        tc.del_class(class_id2)
        result = tc.get_valid_class_id()
        self.assertEqual(result, [class_id])

    def test_get_valid_class(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        tc_cls = tc.add_class(class_id, spec)
        result = tc.get_valid_class()
        self.assertEqual(result, [tc_cls])

        class_id2 = '11'
        tc_cls2 = tc.add_class(class_id2, spec)
        result = tc.get_valid_class()
        self.assertEqual(result, [tc_cls2, tc_cls])

        tc.del_class(class_id2)
        result = tc.get_valid_class()
        self.assertEqual(result, [tc_cls])

    def test_get_all_class(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)
        tc_cls = tc.add_class(class_id, spec)
        result = tc.get_all_class()
        self.assertEqual(result, {class_id: tc_cls})

        class_id2 = '11'
        tc_cls2 = tc.add_class(class_id2, spec)
        result = tc.get_all_class()
        self.assertEqual(result, {class_id2: tc_cls2, class_id: tc_cls})

        tc.del_class(class_id2)
        result = tc.get_all_class()
        self.assertEqual(result, {class_id2: tc_cls2, class_id: tc_cls})

    def test_get_valid_filter_addr(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        address = 'source_ip'
        node = 'ingress'
        protocol = 'ip'
        pref = 2
        tc.add_filter(protocol, pref, node, address)
        result = tc.get_valid_filter_addr()
        self.assertEqual(result, [address])

        address2 = 'source_ip2'
        tc.add_filter(protocol, pref, node, address2)
        result = tc.get_valid_filter_addr()
        self.assertEqual(result, [address, address2])

        tc.del_filter(address)
        result = tc.get_valid_filter_addr()
        self.assertEqual(result, [address2])

    def test_get_valid_filter(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        address = 'source_ip'
        node = 'ingress'
        protocol = 'ip'
        pref = 2
        tc_filt = tc.add_filter(protocol, pref, node, address)
        result = tc.get_valid_filter()
        self.assertEqual(result, [tc_filt])

        address2 = 'source_ip2'
        tc_filt2 = tc.add_filter(protocol, pref, node, address2)
        result = tc.get_valid_filter()
        self.assertEqual(result, [tc_filt, tc_filt2])

        tc.del_filter(address)
        result = tc.get_valid_filter()
        self.assertEqual(result, [tc_filt2])

    def test_get_all_filter(self):
        dev = 'eth0'
        node_id = '10'
        parent_id = '10'
        class_id = '10'
        type = 'htb'
        spec = {'rate': 10}
        tc = linux_net.TcClass(dev, node_id, parent_id,
                                        class_id, type, spec)

        address = 'source_ip'
        node = 'ingress'
        protocol = 'ip'
        pref = 2
        tc_filt = tc.add_filter(protocol, pref, node, address)
        result = tc.get_all_filter()
        self.assertEqual(result, {address: tc_filt})

        address2 = 'source_ip2'
        tc_filt2 = tc.add_filter(protocol, pref, node, address2)
        result = tc.get_all_filter()
        self.assertEqual(result, {address: tc_filt, address2: tc_filt2})

        tc.del_filter(address)
        result = tc.get_all_filter()
        self.assertEqual(result, {address: tc_filt, address2: tc_filt2})


class  TcFilterTestCase(test.TestCase):

    def setUp(self):
        super(TcFilterTestCase, self).setUp()
        network_driver = FLAGS.network_driver
        self.driver = importutils.import_module(network_driver)
        self.driver.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

    def test__str__(self):
        dev = 'eth0'
        tf = linux_net.TcFilter(dev, protocol='ip', filter_type='u32',
             filter_params='match u32 0 0')

        result = tf.__str__()
        expect = 'dev eth0 protocol ip u32 match u32 0 0'
        self.assertEqual(result, expect)

    def test_apply(self):
        expect = [('tc', 'filter', 'fake_action', 'dev', 'eth0',
                   'protocol', 'ip', 'u32', 'match', 'u32', '0', '0')]
        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return None, None

        self.stubs.Set(linux_net, '_execute', fake_execute)

        action = 'fake_action'
        dev = 'eth0'
        tf = linux_net.TcFilter(dev, protocol='ip', filter_type='u32',
              filter_params='match u32 0 0')
        tf._apply(action)
        self.assertEqual(expect, self.executes)

    def test_to_list(self):
        tf = linux_net.TcFilter(dev='eth0', protocol='ip',
                           filter_type='u32', filter_params='match u32 0 0')
        result = tf.to_list()
        expect = ['dev', 'eth0', 'protocol', 'ip',
                   'u32', 'match', 'u32', '0', '0']
        self.assertEqual(result, expect)

    def test_apply_ran(self):
        expect = [('tc', 'filter', 'add', 'dev', 'eth0', 'protocol',
                     'ip', 'u32', 'match', 'u32', '0', '0')]

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)
        tf = linux_net.TcFilter(dev='eth0', protocol='ip',
                           filter_type='u32', filter_params='match u32 0 0')
        tf.apply()
        self.assertEqual(expect, self.executes)

    def test_delete(self):
        expect = [('tc', 'filter', 'del', 'dev', 'eth0', 'protocol',
                   'ip', 'u32', 'match', 'u32', '0', '0')]

        self.executes = []

        def fake_execute(*args, **kwargs):
            self.executes.append(args)
            return '', None

        self.stubs.Set(linux_net, '_execute', fake_execute)
        tf = linux_net.TcFilter(dev='eth0', protocol='ip',
                           filter_type='u32', filter_params='match u32 0 0')
        tf.delete()
        self.assertEqual(expect, self.executes)
