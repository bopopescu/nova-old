# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
from lxml import etree
import webob

from nova.api.openstack.compute.contrib import quotas_usage as usages
from nova.api.openstack import wsgi
from nova import db
from nova.db.sqlalchemy import models
from nova import exception
from nova import test
from nova.tests.api.openstack import fakes


def quotas_usage():
    return {
            'memory_mb': {
                'memory_mb': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'memory_mb': 1L,
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6'
                    }
                ],
                'capacity': 4031L
            },
            'vcpus': {
                'vcpus': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'vcpus': 1L
                    }
                ]
            },
            'local_gb': {
                'local_gb': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'local_gb': 1L
                    }
                        ],
                'capacity': 35L
            },
            'ecus': {
                'ecus': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'ecus': 4
                    }
                ],
                'capacity': 8
            },
            'network_qos': {
                'private_capacity': 1500,
                'network_qos': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'type': 'private',
                        'rate': 123
                    },
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'type': 'public',
                        'rate': 10
                    }
                ],
                'public_capacity': 1100
            },
            'floating_ips': [
                {
                    'instance_uuid': None,
                    'host_id': None,
                    'ip': u'10.120.240.225',
                    'fixed_ip_id': None,
                    'project_id': None,
                    'id': 1L,
                    'pool': u'nova'
                }
            ],
            'servers': {
                'servers': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6'
                    }
                ]
            }
        }


def quotas_usage_with_no_floating_ips():
    return {
            'memory_mb': {
                'memory_mb': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'memory_mb': 1L,
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6'
                    }
                ],
                'capacity': 4031L
            },
            'vcpus': {
                'vcpus': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'vcpus': 1L
                    }
                ]
            },
            'local_gb': {
                'local_gb': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'local_gb': 1L
                    }
                        ],
                'capacity': 35L
            },
            'ecus': {
                'ecus': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'ecus': 4
                    }
                ],
                'capacity': 8
            },
            'network_qos': {
                'private_capacity': 1500,
                'network_qos': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'type': 'private',
                        'rate': 123
                    },
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
                        'type': 'public',
                        'rate': 10
                    }
                ],
                'public_capacity': 1100
            },
            'floating_ips': [
            ],
            'servers': {
                'servers': [
                    {
                        'instance_id': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
                        'host': '10-120-240-46',
                        'project_id': 'dc32392af0ae4a098fb7235760077fa6'
                    }
                ]
            }
        }


def fake_db_compute_node_get_all(context):
    node = {'deleted_at': None,
            'vcpus_used': 1L,
            'deleted': False,
            'hypervisor_type': u'QEMU',
            'created_at': datetime.datetime(2012, 12, 15, 7, 28, 15),
            'local_gb_used': 1L,
            'updated_at': datetime.datetime(2012, 12, 15, 7, 45, 42),
            'hypervisor_hostname': u'10-120-240-46',
            'id': 1L, 'memory_mb': 4031L,
            'current_workload': 0L, 'vcpus': 1L,
            'free_ram_mb': 3518L, 'running_vms': 1L,
            'free_disk_gb': 34L, 'service_id': 2L,
            'hypervisor_version': 1000000L, 'disk_available_least': 25L,
            'local_gb': 35L,
            'cpu_info': u'{"ecus": 8, "ecus_used": 1}',
            'memory_mb_used': 513L,
            'private_network_mbps_used': 40,
            'public_network_mbps_used': 4,
            'total_private_network_mbps': 1500,
            'total_public_network_mbps': 1100}
    return [models.ComputeNode(**node)]


def fake_db_instance_type_get_all(context):
    return [{
            "flavorid": 6L,
            "vcpus": 1,
            "extra_specs": {"ecus_per_vcpu:": 4}
            }]


def fake_db_instance_get_all_by_filters(context, filters,
                                        sort_key=None, sort_dir=None):
    instance_dict = {
        'vm_state': 'active',
        'availability_zone': None,
        'terminated_at': None,
        'ramdisk_id': '',
        'instance_type_id': 6L,
        'updated_at': datetime.datetime(2012, 12, 15, 7, 44, 40),
        'vm_mode': None,
        'deleted_at': None,
        'reservation_id': 'r-s0mbn8kg',
        'id': 2L,
        'disable_terminate': False,
        'user_id': 'f2665c1140c54a03a98110cb86262ec3',
        'uuid': '82fbc5f8-e60f-440a-a9a6-a5ab32cd2f68',
        'server_name': None,
        'default_swap_device': None,
        'hostname': 'test',
        'launched_on': '10-120-240-46',
        'display_description': 'test',
        'key_data': None,
        'deleted': False,
        'power_state': 1L,
        'default_ephemeral_device': None,
        'progress': 0L,
        'project_id': 'dc32392af0ae4a098fb7235760077fa6',
        'launched_at': datetime.datetime(2012, 12, 15, 7, 44, 40),
        'scheduled_at': datetime.datetime(2012, 12, 15, 7, 43, 48),
        'ephemeral_gb': 0L,
        'access_ip_v6': None,
        'access_ip_v4': None,
        'kernel_id': '',
        'key_name': None,
        'user_data': None,
        'host': '10-120-240-46',
        'display_name': 'test',
        'task_state': None,
        'shutdown_terminate': False,
        'architecture': None,
        'root_gb': 1L,
        'locked': False,
        'created_at': datetime.datetime(2012, 12, 15, 7, 43, 47),
        'launch_index': 0L,
        'memory_mb': 1L,
        'vcpus': 1L,
        'image_ref': '75c8bf1d-4c2a-4835-acde-94992c5e50e1',
        'root_device_name': '/dev/vda',
        'auto_disk_config': None,
        'os_type': None,
        'config_drive': ''
    }
    instance = models.Instance(**instance_dict)
    extra_specs = {"key": "ecus_per_vcpu:",
                   "value": 4}
    instance_type_extra_specs = models.InstanceTypeExtraSpecs(**extra_specs)
    instance_type = {"flavorid": 6L, "vcpus": 1}
    instance.instance_type = models.InstanceTypes(**instance_type)
    instance.instance_type.extra_specs = [instance_type_extra_specs]
    return [instance]


def fake_db_floating_ip_get_all(context):
    ip = {
            'deleted_at': None,
            'deleted': False,
            'fixed_ip_id': None,
            'created_at': datetime.datetime(2012, 12, 15, 7, 27, 49),
            'updated_at': None,
            'id': 1L,
            'host': None,
            'address': u'10.120.240.225',
            'interface': u'eth0',
            'project_id': None,
            'auto_assigned': False,
            'pool': u'nova'
        }
    return [models.FloatingIp(**ip)]


def fake_db_floating_ip_get_all_with_no_floating_ips(context):
    raise exception.NoFloatingIpsDefined()


def fake_db_fixed_ip_get(context, ip_id):
    ip = {
            'instance_uuid': None,
            'reserved': True,
            'deleted': False,
            'created_at': datetime.datetime(2012, 12, 15, 7, 26, 58),
            'virtual_interface_id': None,
            'leased': False,
            'updated_at': None,
            'network_id': 1L,
            'host': None,
            'address': u'10.0.0.0',
            'allocated': False,
            'deleted_at': None,
            'id': 1L
        }
    return models.FixedIp(**ip)


def fake_db_instance_system_metadata_get(context, instance_id):
    return {'network-qos': '[{"type": "private", "rate":123},' \
                                + '{"type": "public", "rate":10}]'}


class QuotasUsageTest(test.TestCase):

    def setUp(self):
        super(QuotasUsageTest, self).setUp()
        self.controller = usages.QuotasUsageController()
        self.stubs.Set(db, 'fixed_ip_get', fake_db_fixed_ip_get)
        self.stubs.Set(db, 'floating_ip_get_all', fake_db_floating_ip_get_all)
        self.stubs.Set(db, 'instance_get_all_by_filters',
                       fake_db_instance_get_all_by_filters)
        self.stubs.Set(db, 'compute_node_get_all',
                       fake_db_compute_node_get_all)
        self.stubs.Set(db, 'instance_system_metadata_get',
                       fake_db_instance_system_metadata_get)
        self.stubs.Set(db, 'instance_type_get_all',
                       fake_db_instance_type_get_all)

    def test_index(self):
        uri = '/v2/fake_tenant/os-quotas-usage'
        req = fakes.HTTPRequest.blank(uri, use_admin_context=True)
        context = req.environ['nova.context']
        context.roles = ['admin']
        result = self.controller.index(req)
        self.assertEqual(result, quotas_usage())

    def test_index_with_no_floating_ips(self):
        uri = '/v2/fake_tenant/os-quotas-usage'
        self.stubs.Set(db, 'floating_ip_get_all',
                       fake_db_floating_ip_get_all_with_no_floating_ips)
        req = fakes.HTTPRequest.blank(uri, use_admin_context=True)
        context = req.environ['nova.context']
        context.roles = ['admin']
        result = self.controller.index(req)
        self.assertEqual(result, quotas_usage_with_no_floating_ips())

    def test_not_admin(self):
        uri = '/v2/fake_tenant/os-quotas-usage'
        req = fakes.HTTPRequest.blank(uri)
        self.assertRaises(exception.PolicyNotAuthorized,
                            self.controller.index, req)

    def test_hosts(self):
        expected = {u'10-120-240-46': {'disk_gb': 35,
                                        'ecus': 8,
                                        'ecus_used': 1,
                                        'local_gb_used': 1,
                                        'memory_mb': 4031,
                                        'memory_mb_used': 513,
                                        'private_network_qos_mbps': 1500,
                                        'private_qos_used': 40,
                                        'public_network_qos_mbps': 1100,
                                        'public_qos_used': 4,
                                        'servers_used': 1,
                                        'vcpus_used': 1}}
        uri = '/v2/fake_tenant/os-quotas-usage/hosts'
        req = fakes.HTTPRequest.blank(uri, use_admin_context=True)
        context = req.environ['nova.context']
        context.roles = ['admin']
        result = self.controller.hosts(req)
        self.assertEquals(expected, result)
