"""
Aggregate weigher. The higher costs the more metadata a aggregate contains.

We want to save advance host AMAP. when instance boot with flavor which dont
need any extra_specs, but a host actually has aggregate metadata. We see the
instance need more costs.
"""
from nova import db
from nova import flags
from nova.openstack.common import cfg

weight_config = cfg.FloatOpt('compute_aggregate_metadata_cost_more_fn_weight',
                      default=10.0,
                      help='The cost of metadata in aggregate. The more '
                             'metadata the more costs.')
FLAGS = flags.FLAGS
FLAGS.register_opt(weight_config)


def compute_aggregate_metadata_cost_more_fn(host_state, weighing_properties):
    """More metadata in aggregate more costs."""
    instance_type = weighing_properties.get('instance_type', {})
    extra_specs = instance_type.get('extra_specs', {})
    extra_specs_keys = set(extra_specs.keys())

    context = weighing_properties['context'].elevated()
    metadata = db.aggregate_metadata_get_by_host(context, host_state.host)
    metadata_keys = set(metadata.keys())

    # Get the count of difference from metadata to extra_specs
    # If no metadata return 0.
    # If metadata has (nbs), extra_specs has nothing, return 1.
    # if metadata has nothing, extra_specs has (nbs), return 0.
    return len(metadata_keys.difference(extra_specs_keys))
