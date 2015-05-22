# Copyright (c) 2011 OpenStack, LLC.
# Copyright (c) 2012 Cloudscaling
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

from nova import context
from nova import db
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.scheduler import filters

LOG = logging.getLogger(__name__)

FLAGS = flags.FLAGS


class NetworkFilter(filters.BaseHostFilter):
    """Network Filter based on available network bandwith"""

    def host_passes(self, host_state, filter_properties):
        """Return hosts with sufficient available both private and
        public network bandwith, or with network qos disable """

        if not FLAGS.use_network_qos:
            return True

        requested_private_bandwith =\
                filter_properties.get('private_network_bandwith')
        requested_public_bandwith =\
                filter_properties.get('public_network_bandwith')

        private_network_mbps_used = host_state.private_network_mbps_used
        public_network_mbps_used = host_state.public_network_mbps_used

        private_bandwith_limit = host_state.total_private_network_mbps
        public_bandwith_limit = host_state.total_public_network_mbps

        usable_private_bandwith = (private_bandwith_limit -
                                   private_network_mbps_used)
        usable_public_bandwith = (public_bandwith_limit -
                                  public_network_mbps_used)

        if not usable_private_bandwith >= requested_private_bandwith:
            LOG.debug(_("%(host_state)s does not have"
                        "%(requested_private_bandwith)s MB/s"
                        "private network bandwith, it only has"
                        "%(usable_private_bandwith)s MB usable private"
                        "network bandwith."), locals())
            return False

        elif not usable_public_bandwith >= requested_public_bandwith:
            LOG.debug(_("%(host_state)s does not have"
                        "%(requested_public_bandwith)s MB/s"
                        "public network bandwith, it only has"
                        "%(usable_public_bandwith)s MB usable public"
                        "network bandwith."), locals())
            return False

        else:
            return True
