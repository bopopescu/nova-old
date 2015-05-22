#
# Created on Dec 13, 2012
#
# @author: hzzhoushaoyu
#

import netaddr

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import compute
from nova.db import api as db_api
from nova import exception
from nova import flags
from nova import network
from nova.network import linux_net
from nova.openstack.common import log as logging


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)
authorize = extensions.extension_authorizer('compute', 'floating_ips:search')


def make_float_ip(elem):
    elem.set('id')
    elem.set('ip')
    elem.set('pool')
    elem.set('fixed_ip')
    elem.set('instance_id')


class FloatingIPsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('floating_ips')
        elem = xmlutil.SubTemplateElement(root, 'floating_ip',
                                          selector='floating_ips')
        make_float_ip(elem)
        return xmlutil.MasterTemplate(root, 1)


def _recog_floating_ip_type(floating_ip):
    if FLAGS.use_private_floating_ip:
        private_ip_range = FLAGS.private_floating_ip_range
        private_network = netaddr.IPNetwork(private_ip_range)
        ip = netaddr.IPAddress(floating_ip['address'])
        if ip in private_network:
            return 'private'
        else:
            return 'public'


def _translate_floating_ip_view(floating_ip):
    result = {
        'id': floating_ip['id'],
        'ip': floating_ip['address'],
        'pool': floating_ip['pool'],
    }
    try:
        result['fixed_ip'] = floating_ip['fixed_ip']['address']
    except (TypeError, KeyError):
        result['fixed_ip'] = None
    try:
        result['instance_id'] = floating_ip['instance']['uuid']
    except (TypeError, KeyError):
        result['instance_id'] = None
    try:
        result['instance_name'] = floating_ip['instance']['hostname']
    except (TypeError, KeyError):
        result['instance_name'] = None
    try:
        result['project_id'] = floating_ip['project_id']
    except (TypeError, KeyError):
        result['propject_id'] = None
    if FLAGS.use_private_floating_ip:
        result['type'] = _recog_floating_ip_type(floating_ip)
    return {'floating_ip': result}


def _translate_floating_ips_view(floating_ips):
    return {'floating_ips': [_translate_floating_ip_view(ip)['floating_ip']
                             for ip in floating_ips]}


class FloatingIPSearchController(object):
    """The Floating IPs API controller for the OpenStack API."""

    def __init__(self):
        self.compute_api = compute.API()
        self.network_api = network.API()
        super(FloatingIPSearchController, self).__init__()

    def _get_fixed_ip(self, context, fixed_ip_id, fixed_ips=None):
        if fixed_ip_id is None:
            return None
        if fixed_ips is None:
            try:
                return self.network_api.get_fixed_ip(context, fixed_ip_id)
            except exception.FixedIpNotFound:
                return None
        for ip in fixed_ips:
            if ip.get('id') == fixed_ip_id:
                return ip

    def _get_instance(self, context, instance_id, instances=None):
        if instances is None:
            return self.compute_api.get(context, instance_id)
        for instance in instances:
            if instance.get('uuid') == instance_id:
                return instance

    def _set_metadata(self, context, floating_ip, fixed_ips=None,
                      instances=None):
        fixed_ip_id = floating_ip['fixed_ip_id']
        floating_ip['fixed_ip'] = self._get_fixed_ip(context,
                                                     fixed_ip_id,
                                                     fixed_ips)
        instance_uuid = None
        if floating_ip['fixed_ip']:
            instance_uuid = floating_ip['fixed_ip']['instance_uuid']

        if instance_uuid:
            floating_ip['instance'] = self._get_instance(context,
                                                         instance_uuid,
                                                         instances)
        else:
            floating_ip['instance'] = None

    def _set_floating_ips_pools(self, context, search_opts, result):
        get_pools = search_opts.get("get_pools", False)
        if not get_pools:
            return
        usages = db_api.floating_ip_get_pools_usage(context)
        capacities = db_api.floating_ip_get_pools_capacity(context)
        pools = []
        for pool in capacities:
            item = dict(name=pool,
                        count=capacities.get(pool, 0),
                        in_use=usages.get(pool, 0))
            pools.append(item)
        result.update(pools=pools)

    @wsgi.serializers(xml=FloatingIPsTemplate)
    def index(self, req):
        """Return a list of floating ips."""
        context = req.environ['nova.context']
        authorize(context)

        search_opts = {}
        search_opts.update(req.GET)

        fixed_ips = self.network_api.get_allocated_fixed_ips(context)
        instances = self.compute_api.get_all(context, {'deleted': 0})
        floating_ips = self.network_api.get_floating_ips(context, search_opts)
        for floating_ip in floating_ips:
            self._set_metadata(context, floating_ip, fixed_ips, instances)

        result = _translate_floating_ips_view(floating_ips)
        self._set_floating_ips_pools(context, search_opts, result)
        return result


class Floating_ips_search(extensions.ExtensionDescriptor):
    """Floating IPs support"""

    name = "FloatingIpsSearch"
    alias = "os-floating-ips-search"
    namespace = "http://docs.openstack.org/compute/ext/floating_ips/api/v1.1"
    updated = "2011-06-16T00:00:00+00:00"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension('os-floating-ips-search',
                         FloatingIPSearchController(),
                         collection_actions={})
        resources.append(res)

        return resources
