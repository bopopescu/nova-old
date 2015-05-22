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

import traceback
import webob
from webob import exc

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova.compute import vm_states
from nova import exception
from nova import flags
from nova.openstack.common import log as logging
from nova.openstack.common.notifier import api as notifier_api


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)


class FailoverActionController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(FailoverActionController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API()

    @wsgi.action('failover')
    def _failover(self, req, id, body):
        """ failover a server """
        context = req.environ['nova.context']

        try:
            method = body["failover"]
        except (TypeError, KeyError):
            method = None

        if method is not None and method not in ('reboot', 'rebuild', 'move'):
            msg = _("Method must be in (reboot, rebuild, move)")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            server = dict(self.compute_api.get(context, id))
            if method:
                server['method'] = method
            publisher_id = 'nova-api'
            event_type = 'user.vm.down'
            priority = 'INFO'
            notifier_api.notify(context, publisher_id, event_type, priority,
                                server)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_("Compute.api::failover %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)


class Action_failover(extensions.ExtensionDescriptor):
    """ Action failover. Send notifications to HA module """

    name = "ActionFailover"
    alias = "os-action-failover"
    namespace = ("http://docs.openstack.org/compute/ext/"
                 "action-failover/api/v1.1")
    updated = "2011-09-20T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = FailoverActionController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
