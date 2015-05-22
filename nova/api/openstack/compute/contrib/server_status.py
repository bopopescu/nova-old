# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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

from webob import exc

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova import exception
from nova import flags
from nova.openstack.common import log as logging


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)
authorize = extensions.extension_authorizer('compute', 'server_status')


class ServerStatusController(object):
    def __init__(self):
        self.compute_api = compute.API()

    def show(self, req, id):
        context = req.environ['nova.context']
        authorize(context)
        LOG.debug(_("Listing server status"), context=context,
                    instance_uuid=id)

        try:
            instance = self.compute_api.get(context, id)
            result = self.compute_api.instance_os_boot_ready(context,
                                            instance['uuid'],
                                            FLAGS.server_heartbeat_period)
            return result
        except exception.MemCacheClientNotFound:
            explanation = _("Memory cache client is not found.")
            raise exc.HTTPServerError(explanation=explanation)
        except exception.NotFound:
            explanation = _("Instance %s not found.") % id
            raise exc.HTTPNotFound(explanation=explanation)


class ExtendedServerStatusController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ExtendedServerStatusController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API()

    def _extend_server(self, context, server, instance):
        try:
            result = self.compute_api.instance_os_boot_ready(context,
                            instance['uuid'], FLAGS.server_heartbeat_period)
        except Exception, e:
            LOG.error(("_Extend Server OS status failed: %s"), e,
                      instance=instance)
            result = {}

        server[Server_status.alias] = result.get('status', 'unknown')

    @wsgi.extends
    def show(self, req, resp_obj, id):
        context = req.environ['nova.context']
        authorize(context)
        server = resp_obj.obj['server']
        db_instance = req.get_db_instance(server['id'])
        self._extend_server(context, server, db_instance)

    @wsgi.extends
    def detail(self, req, resp_obj):
        context = req.environ['nova.context']
        authorize(context)
        servers = list(resp_obj.obj['servers'])
        for server in servers:
            db_instance = req.get_db_instance(server['id'])
            self._extend_server(context, server, db_instance)


class Server_status(extensions.ExtensionDescriptor):
    """Add server_status to the Create Server v1.1 API"""

    name = "ServerStatus"
    alias = "os-server-status"
    namespace = ("http://docs.openstack.org/compute/ext/"
                 "os-server-status/api/v1.1")
    updated = "2012-10-31T00:00:00+00:00"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension('os-server-status',
                                           ServerStatusController())
        resources.append(res)
        return resources

    def get_controller_extensions(self):
        controller = ExtendedServerStatusController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
