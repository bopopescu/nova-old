#!/usr/bin/env python
"""
The script print all flavors in the environment.

HOWTO extend items:
Append new items name in `headers`, then add your `get_{item}` method below.
Read `get_nbs` for example. If no `get_{item}`, I will just get item from
flavor dict.
"""
from nova.compute import instance_types
from nova import flags
flags.parse_args([])


headers = ['name', 'id', 'memory_mb', 'vcpus', 'swap', 'vcpu_weight',
           'flavorid', 'rxtx_factor', 'root_gb', 'ephemeral_gb', 'disable',
           'is_public', 'ecus_per_cpu', 'nbs']
print ','.join(headers)


def get_ecus_per_cpu(body):
    return body['extra_specs'].get('ecus_per_vcpu:')


def get_nbs(body):
    nbs = body['extra_specs'].get('nbs', '').lower()
    return 1 if nbs == 'true' else 0


def get_vcpu_weight(body):
    return 'null'


def get_disable(body):
    return 1 if body['disabled'] else 0


def get_is_public(body):
    return 1 if body['is_public'] else 0


def main():
    for name, body in instance_types.get_all_flavors().iteritems():
        line_item = []
        for value in headers:
            func = globals().get('get_%s' % value)
            if func:
                line_item.append(str(func(body)))
            else:
                line_item.append(str(body.get(value)))
        print ','.join(line_item)

if __name__ == '__main__':
    main()
