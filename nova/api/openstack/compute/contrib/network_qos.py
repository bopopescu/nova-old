# Copyright 2011 Justin Santa Barbara
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

"""The network-qos extension.

The URL mapping is shown below.

GET /v2/{tenant_id}/servers/{server-id}/network-qos => index

PUT /v2/{tenant_id}/servers/{server-id}/network-qos/public => update
PUT /v2/{tenant_id}/servers/{server-id}/network-qos/private => update
"""

import re
import webob
from webob import exc

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import compute
from nova import db
from nova import exception
from nova import flags
from nova import network
from nova.openstack.common import log as logging
from nova.openstack.common.rpc import common as rpc_common


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS
authorize = extensions.extension_authorizer('compute', 'network-qos')


class NetworkQosController(wsgi.Controller):
    """The network qos API controller for the OpenStack API.

    A child resource of the server.
    """

    def __init__(self):
        self.compute_api = compute.API()
        self.network_api = network.API()
        super(NetworkQosController, self).__init__()

    def _check_qos_format(self, body):
        """ Check format of specified qos. and return spec object"""
        rate = body.get('rate', None)
        ceil = body.get('ceil', None)
        burst = body.get('burst', None)

        if not rate:
            msg = _("'rate' must be specified.")
            raise exc.HTTPBadRequest(explanation=msg)

        if rate and not isinstance(rate, int):
            msg = _("'rate' must be int.")
            raise exc.HTTPBadRequest(explanation=msg)

        if ceil and not isinstance(ceil, int):
            msg = _("'ceil' must be int.")
            raise exc.HTTPBadRequest(explanation=msg)

        if burst and not isinstance(burst, int):
            msg = _("'burst' must be int.")
            raise exc.HTTPBadRequest(explanation=msg)

        if rate and rate <= 0:
            msg = _("'rate' must great than 0.")
            raise exc.HTTPBadRequest(explanation=msg)

        if ceil and ceil <= 0:
            msg = _("'ceil' must great than 0.")
            raise exc.HTTPBadRequest(explanation=msg)

        if burst and burst <= 0:
            msg = _("'burst' must great than 0.")
            raise exc.HTTPBadRequest(explanation=msg)

        if ceil and ceil < rate:
            msg = _("'ceil' must greate than rate.")
            raise exc.HTTPBadRequest(explanation=msg)

        res = {}
        if rate:
            res['rate'] = rate
        if ceil:
            res['ceil'] = ceil
        if burst:
            res['burst'] = burst

        return res

    def index(self, req, server_id):
        """Returns the list of network qos information for a given instance.

        GET /v2/{tenant_id}/servers/{server-id}/network-qos
        """
        context = req.environ['nova.context']
        authorize(context, action='index')

        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        try:
            net_qos = self.network_api.get_network_qos(context, instance['id'])
        except exception.NotFound:
            raise exc.HTTPNotFound()

        private_qos = net_qos['private']
        private_qos['type'] = 'private'

        public_qos = net_qos['public']
        public_qos['type'] = 'public'

        network_qos = [private_qos, public_qos]

        return {'network-qos': network_qos}

    def show(self, req, server_id, id):
        """Return data about the given network qos."""
        context = req.environ['nova.context']
        authorize(context, action='show')

        qos_type = id
        if qos_type not in ('private', 'public'):
            raise exc.HTTPNotFound()

        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        try:
            net_qos = self.network_api.get_network_qos(context, instance['id'])
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return net_qos[qos_type]

    def update(self, req, server_id, id, body=None):
        """Update a network qos.

        PUT /v2/{tenant_id}/servers/{server-id}/network-qos/public
        PUT /v2/{tenant_id}/servers/{server-id}/network-qos/private
        """
        context = req.environ['nova.context']
        authorize(context, action='update')

        qos_type = id
        if qos_type not in ('private', 'public'):
            raise exc.HTTPNotFound()

        # only admin could modify private network qos settings
        if qos_type == 'private':
            if not context.is_admin:
                raise webob.exc.HTTPForbidden()

        if not body:
            raise exc.HTTPUnprocessableEntity()

        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        spec = self._check_qos_format(body)

        flavor_id = body.get('flavor_id', None)
        if flavor_id:
            try:
                db.instance_type_get_by_flavor_id(context, flavor_id)
            except exception.FlavorNotFound:
                msg = _("flavor %s not found") % flavor_id
                raise exc.HTTPBadRequest(explanation=msg)

        try:
            self.network_api.modify_network_qos(context, instance['id'],
                                                qos_type, spec, flavor_id)
        except exception.TcInvalid, e:
            msg = e.kwargs.get('err')
            raise exc.HTTPBadRequest(explanation=str(msg))
        except exception.TcNotFound, e:
            msg = e.kwargs.get('err')
            raise exc.HTTPBadRequest(explanation=str(msg))
        except exception.OverQuota:
            msg = _("Quota exceeded for resources: public_bandwidth")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.CannotResizeToSameFlavor:
            msg = _("Cannot resize to same flavor")
            raise exc.HTTPBadRequest(explanation=msg)
        except rpc_common.RemoteError, e:
            # NOTE(stanzgy): RemoteError raised here due to exception
            #                deserialization error, truncate the traceback
            #                messages here
            m = str(e.value.encode('utf-8'))
            res = re.search("(.*\n)Traceback \(most recent call last\).*", m)

            try:
                msg = res.groups()[0]
            except Exception:
                # NOTE(stanzgy): traceback messages not matched, return
                #                original exception message
                msg = m

            raise exc.HTTPBadRequest(explanation=msg)
        except Exception, e:
            msg = str(e)
            raise exc.HTTPBadRequest(explanation=msg)

        return webob.Response(status_int=202)


class Network_qos(extensions.ExtensionDescriptor):
    """Network QoS support"""

    name = "NetworkQoS"
    alias = "os-network-qos"
    namespace = "http://docs.openstack.org/compute/ext/network_qos/api/v1.1"
    updated = "2012-12-27T00:00:00+00:00"

    def get_resources(self):
        res = extensions.ResourceExtension(
            'network-qos',
            NetworkQosController(),
            parent=dict(
                member_name='server',
                collection_name='servers'))
        return [res]
