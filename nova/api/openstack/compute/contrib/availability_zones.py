#
# Created on 2012-7-31
#
# @author: Para
#
# for availability_zones REST API
#
#

from nova.api.openstack import extensions
from nova import compute
from nova.openstack.common import log as logging


LOG = logging.getLogger(__name__)
authorize = extensions.extension_authorizer('compute', 'availability_zones')


class AvailabilityZonesController(object):

    def index(self, req):
        context = req.environ['nova.context']
        authorize(context)
        LOG.debug(_("Listing all availability zones"))
        compute_api = compute.API()
        available_zones = compute_api.describe_availability_zones(context)
        return available_zones


class Availability_zones(extensions.ExtensionDescriptor):
    """Admin-only Availability-zones Management Extension"""

    name = "AvailabilityZones"
    alias = "availability-zones"
    namespace = "not yet"
    updated = "2012-07-31T00:00:00+00:00"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension('availability-zones',
                                           AvailabilityZonesController())
        resources.append(res)
        return resources
