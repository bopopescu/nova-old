# author: hzwangpan@corp.netease.com
# A scheduler filter for checking whether a compute node has enough ecus
# to run current instance.

from nova.openstack.common import log as logging
from nova.scheduler import filters

LOG = logging.getLogger(__name__)


class EcuFilter(filters.BaseHostFilter):
    """EcuFilter filters based on available ECU."""

    def host_passes(self, host_state, filter_properties):
        """Return True if host has sufficient ECUs."""
        instance_type = filter_properties.get("instance_type")
        if host_state.topic != "compute" or not instance_type:
            return True

        # NOTE(wangpan): use ecu_ratio to determine cpu qos of this host is
        #                enable or not, because it is only reported when
        #                cpu qos is enabled on the host.
        if not host_state.ecu_ratio:
            # Fail safe
            LOG.info(_("Ecu info of host %s is not reported, let it pass")
                    % host_state.host)
            return True

        ecus_per_vcpu = int(instance_type["extra_specs"]["ecus_per_vcpu:"])
        ecus_total = instance_type["vcpus"] * ecus_per_vcpu

        return (host_state.free_ecus >= ecus_total and
                host_state.ecu_ratio >= ecus_per_vcpu)
