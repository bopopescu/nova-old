# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2011 Grid Dynamics
# Copyright 2011 Eldar Nugaev, Kirill Shileev, Ilya Alekseyev
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
#    under the License

import netaddr
import webob

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import compute
from nova.compute import api as compute_api
from nova.compute import task_states
from nova.compute import utils as compute_utils
from nova.compute import vm_states
from nova import exception
from nova import flags
from nova import network
from nova.network import linux_net
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova import utils


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)
authorize = extensions.extension_authorizer('compute', 'floating_ips')


def make_float_ip(elem):
    elem.set('id')
    elem.set('ip')
    elem.set('pool')
    elem.set('fixed_ip')
    elem.set('instance_id')


class FloatingIPTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('floating_ip',
                                       selector='floating_ip')
        make_float_ip(root)
        return xmlutil.MasterTemplate(root, 1)


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
    if FLAGS.use_private_floating_ip:
        result['type'] = _recog_floating_ip_type(floating_ip)
    return {'floating_ip': result}


def _translate_floating_ips_view(floating_ips):
    return {'floating_ips': [_translate_floating_ip_view(ip)['floating_ip']
                             for ip in floating_ips]}


def get_instance_by_floating_ip_addr(self, context, address):
    snagiibfa = self.network_api.get_instance_id_by_floating_address
    instance_id = snagiibfa(context, address)
    if instance_id:
        return self.compute_api.get(context, instance_id)


def get_instance_by_floating_ip(self, context, address, floating_ip):
    if floating_ip['fixed_ip_id'] is None:
            return None

    db_driver = FLAGS.db_driver
    db = importutils.import_module(db_driver)

    fixed_ip = db.fixed_ip_get(context, floating_ip['fixed_ip_id'])

    # NOTE(tr3buchet): this can be None
    # NOTE(mikal): we need to return the instance id here because its used
    # by ec2 (and possibly others)
    uuid = fixed_ip['instance_uuid']

    instance = db.instance_get_by_uuid(context, uuid)

    compute_api.check_policy(context, 'get', instance)
    inst = dict(instance.iteritems())
    inst['name'] = instance['name']
    return inst


def disassociate_floating_ip(self, context, instance, address):
    try:
        self.network_api.disassociate_floating_ip(context, instance, address)
    except exception.NotAuthorized:
        raise webob.exc.HTTPUnauthorized()


class FloatingIPController(object):
    """The Floating IPs API controller for the OpenStack API."""

    def __init__(self):
        self.compute_api = compute.API()
        self.network_api = network.API()
        super(FloatingIPController, self).__init__()

    def _normalize_ip(self, floating_ip):
        # NOTE(vish): translate expects instance to be in the floating_ip
        #             dict but it is returned in the fixed_ip dict by
        #             nova-network
        fixed_ip = floating_ip.get('fixed_ip')
        if 'instance' not in floating_ip:
            if fixed_ip:
                floating_ip['instance'] = fixed_ip['instance']
            else:
                floating_ip['instance'] = None
        else:
            floating_ip['instance'] = None

    @wsgi.serializers(xml=FloatingIPTemplate)
    def show(self, req, id):
        """Return data about the given floating ip."""
        context = req.environ['nova.context']
        authorize(context)

        try:
            floating_ip = self.network_api.get_floating_ip(context, id)
        except exception.NotFound:
            raise webob.exc.HTTPNotFound()

        self._normalize_ip(floating_ip)

        return _translate_floating_ip_view(floating_ip)

    @wsgi.serializers(xml=FloatingIPsTemplate)
    def index(self, req):
        """Return a list of floating ips allocated to a project."""
        context = req.environ['nova.context']
        authorize(context)

        floating_ips = self.network_api.get_floating_ips_by_project(context)

        for floating_ip in floating_ips:
            self._normalize_ip(floating_ip)

        return _translate_floating_ips_view(floating_ips)

    @wsgi.serializers(xml=FloatingIPTemplate)
    def create(self, req, body=None):
        context = req.environ['nova.context']
        authorize(context)

        pool = None
        assign_address = None
        if body and 'pool' in body:
            pool = body['pool']
        if body and 'address' in body:
            assign_address = body['address']
        try:
            address = self.network_api.allocate_floating_ip(context,
                                                       pool, assign_address)
            ip = self.network_api.get_floating_ip_by_address(context, address)
        except exception.NoMoreFloatingIps, nmfi:
            if pool:
                nmfi.message = _("No more floating ips in pool %s.") % pool
            else:
                nmfi.message = _("No more floating ips available.")
            raise webob.exc.HTTPNotFound(explanation=nmfi.message)
        except exception.FloatingIpLimitExceeded, nmfi:
            raise webob.exc.HTTPRequestEntityTooLarge(headers=nmfi.headers,
                                                      explanation=nmfi.message)

        return _translate_floating_ip_view(ip)

    def delete(self, req, id):
        context = req.environ['nova.context']
        authorize(context)

        # get the floating ip object
        floating_ip = self.network_api.get_floating_ip(context, id)
        address = floating_ip['address']

        # get the associated instance object (if any)
        instance = get_instance_by_floating_ip_addr(self, context, address)

        # disassociate if associated
        if floating_ip.get('fixed_ip_id'):
            try:
                disassociate_floating_ip(self, context, instance, address)
            except exception.FloatingIpNotAssociated:
                LOG.info(_("Floating ip %s has been disassociated") % address)

        # release ip from project
        self.network_api.release_floating_ip(context, address)
        return webob.Response(status_int=202)

    def _get_ip_by_id(self, context, value):
        """Checks that value is id and then returns its address."""
        return self.network_api.get_floating_ip(context, value)['address']


class FloatingIPActionController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(FloatingIPActionController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API()
        self.network_api = network.API()
        db_driver = FLAGS.db_driver
        self.db = importutils.import_module(db_driver)

    def _check_instance_state(self, func_name, instance,
                              vm_state=None, task_state=(None,)):
        """
        Check VM and/or task state before some action (such as
                                                       associate_floating_ip)
        If the instance is in the wrong state, an exception will be raised.
        """

        if vm_state is not None and not isinstance(vm_state, set):
            vm_state = set(vm_state)
        if task_state is not None and not isinstance(task_state, set):
            task_state = set(task_state)

        instance_uuid = instance.get('uuid')
        instance_vm_state = instance.get('vm_state')
        instance_task_state = instance.get('task_state')

        if instance_vm_state is None:
            # this is useful for Unit Test. In reality it won't happen.
            LOG.warning(_("Watch out, vm state of instance %s is None!")
                        % instance_vm_state)
            return

        if vm_state is not None and instance_vm_state not in vm_state:
            raise exception.InstanceInvalidState(
                attr='vm_state',
                instance_uuid=instance_uuid,
                state=instance_vm_state,
                method=func_name)

        if (task_state is not None and
            instance_task_state not in task_state):
            raise exception.InstanceInvalidState(
                attr='task_state',
                instance_uuid=instance_uuid,
                state=instance_task_state,
                method=func_name)

    @wsgi.action('addFloatingIp')
    def _add_floating_ip(self, req, id, body):
        """Associate floating_ip to an instance."""
        context = req.environ['nova.context']
        authorize(context)

        try:
            address = body['addFloatingIp']['address']
        except TypeError:
            msg = _("Missing parameter dict")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        except KeyError:
            msg = _("Address not specified")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        instance = self.compute_api.get(context, id)
        try:
            self._check_instance_state('addFloatingIp', instance,
                              [vm_states.ACTIVE, vm_states.STOPPED], [None])
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                                                            'add floating ip')

        cached_nwinfo = compute_utils.get_nw_info_for_instance(instance)
        if not cached_nwinfo:
            msg = _('No nw_info cache associated with instance')
            raise webob.exc.HTTPBadRequest(explanation=msg)

        fixed_ips = cached_nwinfo.fixed_ips()
        if not fixed_ips:
            msg = _('No fixed ips associated to instance')
            raise webob.exc.HTTPBadRequest(explanation=msg)

        # TODO(tr3buchet): this will associate the floating IP with the
        # first fixed_ip an instance has. This should be
        # changed to support specifying a particular fixed_ip if
        # multiple exist.
        if len(fixed_ips) > 1:
            msg = _('multiple fixed_ips exist, using the first: %s')
            LOG.warning(msg, fixed_ips[0]['address'])

        try:
            self.network_api.associate_floating_ip(context, instance,
                                  floating_address=address,
                                  fixed_address=fixed_ips[0]['address'])
        except exception.FloatingIpAssociated:
            msg = _('floating ip is already associated')
            raise webob.exc.HTTPBadRequest(explanation=msg)
        except exception.NoFloatingIpInterface:
            msg = _('l3driver call to add floating ip failed')
            raise webob.exc.HTTPBadRequest(explanation=msg)
        except Exception:
            msg = _('Error. Unable to associate floating ip')
            LOG.exception(msg)
            raise webob.exc.HTTPBadRequest(explanation=msg)

        return webob.Response(status_int=202)

    @wsgi.action('removeFloatingIp')
    def _remove_floating_ip(self, req, id, body):
        """Dissociate floating_ip from an instance."""
        context = req.environ['nova.context']
        authorize(context)

        try:
            address = body['removeFloatingIp']['address']
        except TypeError:
            msg = _("Missing parameter dict")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        except KeyError:
            msg = _("Address not specified")

        # get the floating ip from db directly, not via rpc
        floating_ip = dict(self.db.floating_ip_get_by_address(context,
                                                        address).iteritems())

        instance = get_instance_by_floating_ip(self, context, address,
                                                       floating_ip)

        # disassociate if associated
        if (instance and
            floating_ip.get('fixed_ip_id') and
            (utils.is_uuid_like(id) and
             [instance['uuid'] == id] or
             [instance['id'] == id])[0]):
            try:
                disassociate_floating_ip(self, context, instance, address)
            except exception.FloatingIpNotAssociated:
                msg = _('Floating ip is not associated')
                raise webob.exc.HTTPBadRequest(explanation=msg)
            return webob.Response(status_int=202)
        else:
            msg = _("Floating ip %(address)s is not associated with instance "
                    "%(id)s.") % locals()
            raise webob.exc.HTTPUnprocessableEntity(explanation=msg)


class Floating_ips(extensions.ExtensionDescriptor):
    """Floating IPs support"""

    name = "FloatingIps"
    alias = "os-floating-ips"
    namespace = "http://docs.openstack.org/compute/ext/floating_ips/api/v1.1"
    updated = "2011-06-16T00:00:00+00:00"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension('os-floating-ips',
                         FloatingIPController(),
                         member_actions={})
        resources.append(res)

        return resources

    def get_controller_extensions(self):
        controller = FloatingIPActionController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
