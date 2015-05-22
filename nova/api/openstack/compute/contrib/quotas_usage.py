#
# Created on Dec 13, 2012
#
# @author: hzzhoushaoyu
#
# If more quota should return in index,
# add a method named _get_xxx and add dict object
# in usage.such as {'ecus': {'ecus': [], 'capacity': 20}}
# No capacity will also be OK.
#

import json

from nova.api.openstack.compute.views import servers as servers_view
from nova.api.openstack import extensions
from nova.api.openstack import xmlutil
from nova import db
from nova import exception
from nova.openstack.common import log as logging
from nova import utils

LOG = logging.getLogger(__name__)

authorize = extensions.extension_authorizer('compute', 'quotas_usage')


def make_usage(elem):
    elem.set('ecus')
    elem.set('floating_ips')
    elem.set('local_gb')
    elem.set('memory_mb')
    elem.set('network_qos')
    elem.set('servers')
    elem.set('vcpus')


class QuotasUsageTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('quota_usage', selector='quota_usage')
        make_usage(root)
        return xmlutil.MasterTemplate(root, 1)


def wrap_key_error(fn):
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeyError:
            LOG.exception(_("Quotas usage key ERROR."))
            return None
    return wrapper


class QuotasUsageController(object):

    def _get_instance_base_info(self, instance):
        '''
          {
           "project_id": "xx1",
           "instance_id": "uuid1",
           "host": "host1"
           }
        '''
        return dict(project_id=instance.project_id,
                    instance_id=instance.uuid,
                    host=instance.host)

    def _get_host_ecu(self, req, compute_node):
        '''
        return host ecu capacity and ecu_used num.
        '''
        capacity = 0
        ecus_used = 0
        try:
            cpu_info = json.loads(compute_node.cpu_info)
            capacity = cpu_info['ecus']
            ecus_used = cpu_info['ecus_used']
        except (KeyError, ValueError, TypeError):
            LOG.warn(_("Host ecu capacity get error, %s") %
                    compute_node.cpu_info)

        return {'capacity': capacity, 'ecus_used': ecus_used}

    @wrap_key_error
    def _get_ecus(self, req, instance):
        '''
        {
           "project_id": "xx1",
           "instance_id": "uuid1",
           "host": "host1",
           "ecus": 10
        }
        '''
        inst_type_id = instance.instance_type.flavorid
        inst_type = {}
        for flavor in self.flavors:
            if flavor['flavorid'] == inst_type_id:
                inst_type = flavor
        for ext_spec in inst_type["extra_specs"]:
            if ext_spec == "ecus_per_vcpu:":
                ecu = inst_type["vcpus"] * int(
                                    inst_type["extra_specs"][ext_spec])
                result = self._get_instance_base_info(instance)
                result.update(ecus=ecu)
                return result

    def _get_servers(self, req, instance):
        '''
        {
         "project_id": "xx1",
         "instance_id": "uuid1",
         "host": "host1",
         }
        '''
        return self._get_instance_base_info(instance)

    def _get_vcpus(self, req, instance):
        '''
        {
         "project_id": "xx1",
         "instance_id": "uuid1",
         "host": "host1",
         "vcpus": 1
         }
        '''
        result = self._get_instance_base_info(instance)
        result.update(vcpus=instance.vcpus)
        return result

    def _get_memory_mb(self, req, instance):
        '''
        {
         "project_id": "xx1",
         "instance_id": "uuid1",
         "host": "host1",
         "memory_mb": 1
         }
        '''
        result = self._get_instance_base_info(instance)
        result.update(memory_mb=instance.memory_mb)
        return result

    def _get_local_gb(self, req, instance):
        '''
        {
         "project_id": "xx1",
         "instance_id": "uuid1",
         "host": "host1",
         "local_gb": 40
         }
        '''
        result = self._get_instance_base_info(instance)
        result.update(local_gb=instance.root_gb + instance.ephemeral_gb)
        return result

    def _set_floating_ip_metadata(self, context, floating_ip):
        fixed_ip = floating_ip.get('fixed_ip', None)
        instance_uuid = None
        if fixed_ip:
            floating_ip['fixed_ip'] = fixed_ip.address
            instance_uuid = fixed_ip.instance_uuid

        if instance_uuid:
            floating_ip['instance_uuid'] = instance_uuid
        else:
            floating_ip['instance_uuid'] = None

    def _make_floating_ip(self, floating_ip_ref):
        ip_type = utils._recog_floating_ip_type(floating_ip_ref.address)

        ip = dict(fixed_ip_id=floating_ip_ref.fixed_ip_id,
                    id=floating_ip_ref.id,
                    ip=floating_ip_ref.address,
                    pool=floating_ip_ref.pool,
                    host_id=floating_ip_ref.host,
                    project_id=floating_ip_ref.project_id)
        if ip_type is not None:
            ip.update(type=ip_type)
        return ip

    def _get_floating_ips(self, context):
        '''
        [
        {
            "fixed_ip": "10.0.0.0",
            "id": 2,
            "instance_id": "xxx",
            "ip": "10.120.32.162",
            "pool": "nova",
            "host": "host1",
            "type": "public",
            "project_id": "xxx"
        }]
        '''
        ips = []
        try:
            floating_ips_refs = db.floating_ip_get_all(context)
        except exception.NoFloatingIpsDefined:
            return ips

        for floating_ip in floating_ips_refs:
            ip = self._make_floating_ip(floating_ip)
            self._set_floating_ip_metadata(context, ip)
            ips.append(ip)
        return ips

    def _get_network_qos(self, req, instance):
        public_qos, private_qos = servers_view.get_network_qos(req, instance)
        result = self._get_instance_base_info(instance)
        private_qos.update(type='private')
        private_qos.update(result)
        public_qos.update(type='public')
        public_qos.update(result)
        return [private_qos, public_qos]

    def index(self, req):
        '''
        return all quotas usage in platform.
        '''
        context = req.environ['nova.context']
        authorize(context)

        hosts = db.compute_node_get_all(context)
        memory_mb_capacity = 0
        local_gb_capacity = 0
        ecu_capacity = 0
        private_network_qos_capacity = 0
        public_network_qos_capacity = 0
        for host in hosts:
            memory_mb_capacity += host.memory_mb
            local_gb_capacity += host.local_gb
            ecu_capacity += self._get_host_ecu(req, host).get('capacity') or 0
            total_private_network_mbps = host.\
                                    get('total_private_network_mbps')
            if total_private_network_mbps is not None:
                private_network_qos_capacity += total_private_network_mbps
            total_public_network_mbps = host.\
                                    get('total_public_network_mbps')
            if total_private_network_mbps is not None:
                public_network_qos_capacity += total_public_network_mbps
        filters = {"deleted": False}
        instances = db.instance_get_all_by_filters(context, filters,
                                                   "created_at", "desc")
        self.flavors = db.instance_type_get_all(context)
        usages = dict(
                      ecus={"capacity": ecu_capacity,
                            "ecus": []},
                      servers={"servers": []},
                      vcpus={"vcpus": []},
                      local_gb={"capacity": local_gb_capacity,
                                "local_gb": []},
                      memory_mb={"capacity": memory_mb_capacity,
                                 "memory_mb": []},
                      network_qos={
                       "network_qos": [],
                       "private_capacity": private_network_qos_capacity,
                       "public_capacity": public_network_qos_capacity
                       }
                      )
        for instance in instances:
            for key in usages:
                # Note(hzzhoushaoyu) key in usages should be the same as
                # list key in each item. 'key' in second parameter is not the
                # same hierarchy as 'key' in first parameter in usage.
                self._make_items(req, usages[key], key, instance)
        # update floating IPs
        usages.update(floating_ips=self._get_floating_ips(context))
        return usages

    def _make_items(self, req, dict_obj, key, instance):
        '''
        call method self._get_xxx to get specify item usage for instance
        and then add them in usage list
        '''
        item = self.__getattribute__("_get_%s" % key)(req, instance)
        if item is None:
            pass
        elif isinstance(item, list):
            dict_obj[key].extend(item)
        else:
            dict_obj[key].append(item)

    def hosts(self, req):
        context = req.environ['nova.context']
        authorize(context)
        nodes = db.compute_node_get_all(context)
        result = {}
        for node in nodes:
            pri_network_mbps = node.get('total_private_network_mbps', 0)
            pub_network_mbps = node.get('total_public_network_mbps', 0)
            pri_network_mbps_used = node.get('private_network_mbps_used', 0)
            pub_network_mbps_used = node.get('public_network_mbps_used', 0)
            result.update({node.hypervisor_hostname: {
                "ecus": self._get_host_ecu(req, node).get('capacity'),
                "ecus_used": self._get_host_ecu(req, node).get('ecus_used'),
                "disk_gb": node.local_gb,
                "local_gb_used": node.local_gb_used,
                "memory_mb": node.memory_mb,
                "memory_mb_used": node.memory_mb_used,
                "public_network_qos_mbps": pub_network_mbps,
                "private_network_qos_mbps": pri_network_mbps,
                "public_qos_used": pub_network_mbps_used,
                "private_qos_used": pri_network_mbps_used,
                "servers_used": node.running_vms,
                "vcpus_used": node.vcpus_used
                }})
        return result


class Quotas_usage(extensions.ExtensionDescriptor):
    """Quotas Usage management support"""

    name = "QuotasUsage"
    alias = "os-quotas-usage"
    namespace = "http://docs.openstack.org/compute/ext/quotas-usage/api/v1.1"
    updated = "2012-12-13T00:00:00+00:00"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension('os-quotas-usage',
                                        QuotasUsageController(),
                                        collection_actions={"hosts": "GET"})
        resources.append(res)

        return resources
