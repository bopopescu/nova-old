#   Copyright 2011 OpenStack, LLC.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

"""The Extended Availability Zone API extension."""

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import db
from nova import flags
from nova.openstack.common import log as logging


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)
authorize = extensions.soft_extension_authorizer('compute',
                                                 'extended_availability_zone')


class ExtendedAvailabilityZoneController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ExtendedAvailabilityZoneController,
              self).__init__(*args, **kwargs)

    @wsgi.extends
    def show(self, req, resp_obj, id):
        context = req.environ['nova.context']
        if authorize(context):
            server = resp_obj.obj['server']
            admin_context = context.elevated()
            host = self._get_host(req, server)
            services = db.service_get_all_by_host(admin_context, host)
            self._extend_server(context, host, server, services)

    @wsgi.extends
    def detail(self, req, resp_obj):
        context = req.environ['nova.context']
        if authorize(context):
            servers = list(resp_obj.obj['servers'])
            admin_context = context.elevated()
            services = db.service_get_all(admin_context)
            for server in servers:
                host = self._get_host(req, server)
                self._extend_server(context, host, server, services)

    def _get_host(self, req, server):
        host = server.get('OS-EXT-SRV-ATTR:host')
        if host is None:
            instance = req.get_db_instance(server['id'])
            # server['id'] is guaranteed to be in the cache due to
            # the core API adding it in its 'show' method.
            host = instance.get('host')
        return host

    def _extend_server(self, context, host, server, services):
        key = 'availability_zone'
        availability_zone = None

        try:
            for service in services:
                if service['host'] == host:
                    availability_zone = service.get('availability_zone')
                    break
        except (KeyError, TypeError):
            server[key] = None
        else:
            server[key] = availability_zone


class Extended_availability_zone(extensions.ExtensionDescriptor):
    """Extended Availability Zone support"""

    name = "ExtendedAvailabilityZone"
    alias = "OS-EXT-AZ"
    namespace = ("not yet")
    updated = "2012-11-20T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = ExtendedAvailabilityZoneController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
