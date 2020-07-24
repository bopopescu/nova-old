# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Implements vlans, bridges, and iptables rules using linux utilities."""

import calendar
import functools
import inspect
import json
import netaddr
import os
import re
import types

from nova import context
from nova import db
from nova import exception
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova import utils


LOG = logging.getLogger(__name__)


linux_net_opts = [
    cfg.StrOpt('dhcpbridge_flagfile',
               default='/etc/nova/nova-dhcpbridge.conf',
               help='location of flagfile for dhcpbridge'),
    cfg.StrOpt('networks_path',
               default='$state_path/networks',
               help='Location to keep network config files'),
    cfg.StrOpt('public_interface',
               default='eth0',
               help='Interface for public IP addresses'),
    cfg.StrOpt('network_device_mtu',
               default=None,
               help='MTU setting for vlan'),
    cfg.StrOpt('dhcpbridge',
               default='$bindir/nova-dhcpbridge',
               help='location of nova-dhcpbridge'),
    cfg.StrOpt('routing_source_ip',
               default='$my_ip',
               help='Public IP of network host'),
    cfg.IntOpt('dhcp_lease_time',
               default=120,
               help='Lifetime of a DHCP lease in seconds'),
    cfg.StrOpt('dns_server',
               default=None,
               help='if set, uses specific dns server for dnsmasq'),
    cfg.ListOpt('dmz_cidr',
               default=[],
               help='A list of dmz range that should be accepted'),
    cfg.StrOpt('dnsmasq_config_file',
               default='',
               help='Override the default dnsmasq settings with this file'),
    cfg.StrOpt('linuxnet_interface_driver',
               default='nova.network.linux_net.LinuxBridgeInterfaceDriver',
               help='Driver used to create ethernet devices.'),
    cfg.StrOpt('linuxnet_ovs_integration_bridge',
               default='br-int',
               help='Name of Open vSwitch bridge used with linuxnet'),
    cfg.BoolOpt('send_arp_for_ha',
                default=False,
                help='send gratuitous ARPs for HA setup'),
    cfg.IntOpt('send_arp_for_ha_count',
               default=3,
               help='send this many gratuitous ARPs for HA setup'),
    cfg.BoolOpt('use_single_default_gateway',
                default=False,
                help='Use single default gateway. Only first nic of vm will '
                     'get default gateway from dhcp server'),
    cfg.StrOpt('ipset_range',
                default='10.0.0.0/22',
                help='ipset range cidr, in most cases should be'
                     'same as fixed_range. one ipset can store up'
                     'to 65535 entries'),
    cfg.BoolOpt('use_private_floating_ip',
                default=False,
                help='whether to use private floating ip'),
    cfg.StrOpt('private_floating_ip_range',
               default='10.120.144.0/22',
               help='The private floating ip range'),
    cfg.ListOpt('private_floating_ip_dst',
               default=['172.17.0.0/20'],
               help='The private floating ip destination network list'),
    cfg.StrOpt('private_floating_ip_dst_setname',
               default='nova-private-floating-ip-dst',
               help='The private floating ip destination ipset name'),
    cfg.BoolOpt('enable_fill_dhcp_checksum',
                default=False,
                help='whether to add fill dhcp checksum iptable rule'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(linux_net_opts)


# NOTE(vish): Iptables supports chain names of up to 28 characters,  and we
#             add up to 12 characters to binary_name which is used as a prefix,
#             so we limit it to 16 characters.
#             (max_chain_name_length - len('-POSTROUTING') == 16)
def get_binary_name():
    """Grab the name of the binary we're running in."""
    return os.path.basename(inspect.stack()[-1][1])[:16]

binary_name = get_binary_name()


class IptablesRule(object):
    """An iptables rule.

    You shouldn't need to use this class directly, it's only used by
    IptablesManager.

    """

    def __init__(self, chain, rule, wrap=True, top=False):
        self.chain = chain
        self.rule = rule
        self.wrap = wrap
        self.top = top

    def __eq__(self, other):
        return ((self.chain == other.chain) and
                (self.rule == other.rule) and
                (self.top == other.top) and
                (self.wrap == other.wrap))

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        if self.wrap:
            chain = '%s-%s' % (binary_name, self.chain)
        else:
            chain = self.chain
        # new rules should have a zero [packet: byte] count
        return '[0:0] -A %s %s' % (chain, self.rule)


class IptablesTable(object):
    """An iptables table."""

    def __init__(self):
        self.rules = []
        self.remove_rules = []
        self.chains = set()
        self.unwrapped_chains = set()
        self.remove_chains = set()

    def add_chain(self, name, wrap=True):
        """Adds a named chain to the table.

        The chain name is wrapped to be unique for the component creating
        it, so different components of Nova can safely create identically
        named chains without interfering with one another.

        At the moment, its wrapped name is <binary name>-<chain name>,
        so if nova-compute creates a chain named 'OUTPUT', it'll actually
        end up named 'nova-compute-OUTPUT'.

        """
        if wrap:
            self.chains.add(name)
        else:
            self.unwrapped_chains.add(name)

    def remove_chain(self, name, wrap=True):
        """Remove named chain.

        This removal "cascades". All rule in the chain are removed, as are
        all rules in other chains that jump to it.

        If the chain is not found, this is merely logged.

        """
        if wrap:
            chain_set = self.chains
        else:
            chain_set = self.unwrapped_chains

        if name not in chain_set:
            LOG.warn(_('Attempted to remove chain %s which does not exist'),
                     name)
            return

        # non-wrapped chains and rules need to be dealt with specially,
        # so we keep a list of them to be iterated over in apply()
        if not wrap:
            self.remove_chains.add(name)
        chain_set.remove(name)
        if not wrap:
            self.remove_rules += filter(lambda r: r.chain == name, self.rules)
        self.rules = filter(lambda r: r.chain != name, self.rules)

        if wrap:
            jump_snippet = '-j %s-%s' % (binary_name, name)
        else:
            jump_snippet = '-j %s' % (name,)

        if not wrap:
            self.remove_rules += filter(lambda r: jump_snippet in r.rule,
                                        self.rules)
        self.rules = filter(lambda r: jump_snippet not in r.rule, self.rules)

    def add_rule(self, chain, rule, wrap=True, top=False):
        """Add a rule to the table.

        This is just like what you'd feed to iptables, just without
        the '-A <chain name>' bit at the start.

        However, if you need to jump to one of your wrapped chains,
        prepend its name with a '$' which will ensure the wrapping
        is applied correctly.

        """
        if wrap and chain not in self.chains:
            raise ValueError(_('Unknown chain: %r') % chain)

        if '$' in rule:
            rule = ' '.join(map(self._wrap_target_chain, rule.split(' ')))

        self.rules.append(IptablesRule(chain, rule, wrap, top))

    def _wrap_target_chain(self, s):
        if s.startswith('$'):
            return '%s-%s' % (binary_name, s[1:])
        return s

    def remove_rule(self, chain, rule, wrap=True, top=False):
        """Remove a rule from a chain.

        Note: The rule must be exactly identical to the one that was added.
        You cannot switch arguments around like you can with the iptables
        CLI tool.

        """
        try:
            self.rules.remove(IptablesRule(chain, rule, wrap, top))
            if not wrap:
                self.remove_rules.append(IptablesRule(chain, rule, wrap, top))
        except ValueError:
            LOG.warn(_('Tried to remove rule that was not there:'
                       ' %(chain)r %(rule)r %(wrap)r %(top)r'),
                     {'chain': chain, 'rule': rule,
                      'top': top, 'wrap': wrap})

    def empty_chain(self, chain, wrap=True):
        """Remove all rules from a chain."""
        chained_rules = [rule for rule in self.rules
                              if rule.chain == chain and rule.wrap == wrap]
        for rule in chained_rules:
            self.rules.remove(rule)


class IptablesManager(object):
    """Wrapper for iptables.

    See IptablesTable for some usage docs

    A number of chains are set up to begin with.

    First, nova-filter-top. It's added at the top of FORWARD and OUTPUT. Its
    name is not wrapped, so it's shared between the various nova workers. It's
    intended for rules that need to live at the top of the FORWARD and OUTPUT
    chains. It's in both the ipv4 and ipv6 set of tables.

    For ipv4 and ipv6, the built-in INPUT, OUTPUT, and FORWARD filter chains
    are wrapped, meaning that the "real" INPUT chain has a rule that jumps to
    the wrapped INPUT chain, etc. Additionally, there's a wrapped chain named
    "local" which is jumped to from nova-filter-top.

    For ipv4, the built-in PREROUTING, OUTPUT, and POSTROUTING nat chains are
    wrapped in the same was as the built-in filter chains. Additionally,
    there's a snat chain that is applied after the POSTROUTING chain.

    """

    def __init__(self, execute=None):
        if not execute:
            self.execute = _execute
        else:
            self.execute = execute

        self.ipv4 = {'filter': IptablesTable(),
                     'nat': IptablesTable()}
        self.ipv6 = {'filter': IptablesTable()}

        if FLAGS.use_network_qos or FLAGS.enable_fill_dhcp_checksum:
            self.ipv4['mangle'] = IptablesTable()
            self.ipv6['mangle'] = IptablesTable()

        self.iptables_apply_deferred = False

        # Add a nova-filter-top chain. It's intended to be shared
        # among the various nova components. It sits at the very top
        # of FORWARD and OUTPUT.
        for tables in [self.ipv4, self.ipv6]:
            tables['filter'].add_chain('nova-filter-top', wrap=False)
            tables['filter'].add_rule('FORWARD', '-j nova-filter-top',
                                      wrap=False, top=True)
            tables['filter'].add_rule('OUTPUT', '-j nova-filter-top',
                                      wrap=False, top=True)

            tables['filter'].add_chain('local')
            tables['filter'].add_rule('nova-filter-top', '-j $local',
                                      wrap=False)

            # Note(stanzgy): add fw mark to instance if network qos is in use
            if FLAGS.use_network_qos:
                tables['mangle'].add_chain('nova-mangle-top', wrap=False)
                tables['mangle'].add_rule('FORWARD', '-j nova-mangle-top',
                                          wrap=False, top=True)
                tables['mangle'].add_rule('OUTPUT', '-j nova-mangle-top',
                                          wrap=False, top=True)

                tables['mangle'].add_chain('tc')

                if not FLAGS.allow_private_to_public:
                    rule = ('-m mark --mark %s -j ACCEPT' %
                            FLAGS.tc_private_to_public_fwmark)
                    tables['mangle'].add_rule('nova-mangle-top', rule,
                                              wrap=False, top=True)

                tables['mangle'].add_rule('nova-mangle-top', '-j $tc',
                                          wrap=False)

        # Wrap the built-in chains
        builtin_chains = {4: {'filter': ['INPUT', 'OUTPUT', 'FORWARD'],
                              'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING']},
                          6: {'filter': ['INPUT', 'OUTPUT', 'FORWARD']}}

        if FLAGS.use_network_qos or FLAGS.enable_fill_dhcp_checksum:
            builtin_chains[4]['mangle'] = ['PREROUTING', 'INPUT', 'FORWARD',
                                           'OUTPUT', 'POSTROUTING']
            builtin_chains[6]['mangle'] = ['INPUT', 'FORWARD', 'OUTPUT']

        for ip_version in builtin_chains:
            if ip_version == 4:
                tables = self.ipv4
            elif ip_version == 6:
                tables = self.ipv6

            for table, chains in builtin_chains[ip_version].iteritems():
                for chain in chains:
                    tables[table].add_chain(chain)
                    tables[table].add_rule(chain, '-j $%s' % (chain,),
                                           wrap=False)

        # Add a nova-postrouting-bottom chain. It's intended to be shared
        # among the various nova components. We set it as the last chain
        # of POSTROUTING chain.
        self.ipv4['nat'].add_chain('nova-postrouting-bottom', wrap=False)
        self.ipv4['nat'].add_rule('POSTROUTING', '-j nova-postrouting-bottom',
                                  wrap=False)

        # We add a snat chain to the shared nova-postrouting-bottom chain
        # so that it's applied last.
        self.ipv4['nat'].add_chain('snat')
        self.ipv4['nat'].add_rule('nova-postrouting-bottom', '-j $snat',
                                  wrap=False)

        # And then we add a float-snat chain and jump to first thing in
        # the snat chain.
        self.ipv4['nat'].add_chain('float-snat')
        self.ipv4['nat'].add_rule('snat', '-j $float-snat')

    def defer_apply_on(self):
        self.iptables_apply_deferred = True

    def defer_apply_off(self):
        self.iptables_apply_deferred = False
        self._apply()

    def apply(self):
        if self.iptables_apply_deferred:
            return

        self._apply()

    @utils.synchronized('iptables', external=True)
    def _apply(self):
        """Apply the current in-memory set of iptables rules.

        This will blow away any rules left over from previous runs of the
        same component of Nova, and replace them with our current set of
        rules. This happens atomically, thanks to iptables-restore.

        """
        s = [('iptables', self.ipv4)]
        if FLAGS.use_ipv6:
            s += [('ip6tables', self.ipv6)]

        for cmd, tables in s:
            for table in tables:
                current_table, _err = self.execute('%s-save' % (cmd,), '-c',
                                                   '-t', '%s' % (table,),
                                                   run_as_root=True,
                                                   attempts=5)
                current_lines = current_table.split('\n')
                new_filter = self._modify_rules(current_lines,
                                                tables[table])
                self.execute('%s-restore' % (cmd,), '-c', run_as_root=True,
                             process_input='\n'.join(new_filter),
                             attempts=5)
        LOG.debug(_("IPTablesManager.apply completed with success"))

    def _modify_rules(self, current_lines, table, binary=None):
        unwrapped_chains = table.unwrapped_chains
        chains = table.chains
        remove_chains = table.remove_chains
        rules = table.rules
        remove_rules = table.remove_rules

        # Remove any trace of our rules
        new_filter = filter(lambda line: binary_name not in line,
                            current_lines)

        seen_chains = False
        rules_index = 0
        for rules_index, rule in enumerate(new_filter):
            if not seen_chains:
                if rule.startswith(':'):
                    seen_chains = True
            else:
                if not rule.startswith(':'):
                    break

        our_rules = []
        bot_rules = []
        for rule in rules:
            rule_str = str(rule)
            if rule.top:
                # rule.top == True means we want this rule to be at the top.
                # Further down, we weed out duplicates from the bottom of the
                # list, so here we remove the dupes ahead of time.

                # We don't want to remove an entry if it has non-zero
                # [packet:byte] counts and replace it with [0:0], so let's
                # go look for a duplicate, and over-ride our table rule if
                # found.

                # ignore [packet:byte] counts at beginning of line
                if rule_str.startswith('['):
                    rule_str = rule_str.split(']', 1)[1]
                dup_filter = filter(lambda s: rule_str.strip() in s.strip(),
                                    new_filter)

                new_filter = filter(lambda s:
                                    rule_str.strip() not in s.strip(),
                                    new_filter)
                # if no duplicates, use original rule
                if dup_filter:
                    # grab the last entry, if there is one
                    dup = dup_filter[-1]
                    rule_str = str(dup)
                else:
                    rule_str = str(rule)
                rule_str.strip()

                our_rules += [rule_str]
            else:
                bot_rules += [rule_str]

        our_rules += bot_rules

        new_filter[rules_index:rules_index] = our_rules

        new_filter[rules_index:rules_index] = [':%s - [0:0]' % (name,)
                                               for name in unwrapped_chains]
        new_filter[rules_index:rules_index] = [':%s-%s - [0:0]' %
                                               (binary_name, name,)
                                               for name in chains]

        seen_lines = set()

        def _weed_out_duplicates(line):
            # ignore [packet:byte] counts at beginning of lines
            if line.startswith('['):
                line = line.split(']', 1)[1]
            line = line.strip()
            if line in seen_lines:
                return False
            else:
                seen_lines.add(line)
                return True

        def _weed_out_removes(line):
            # We need to find exact matches here
            if line.startswith(':'):
                # it's a chain, for example, ":nova-billing - [0:0]"
                # strip off everything except the chain name
                line = line.split(':')[1]
                line = line.split('- [')[0]
                line = line.strip()
                for chain in remove_chains:
                    if chain == line:
                        remove_chains.remove(chain)
                        return False
            elif line.startswith('['):
                # it's a rule
                # ignore [packet:byte] counts at beginning of lines
                line = line.split(']', 1)[1]
                line = line.strip()
                for rule in remove_rules:
                    # ignore [packet:byte] counts at beginning of rules
                    rule_str = str(rule)
                    rule_str = rule_str.split(' ', 1)[1]
                    rule_str = rule_str.strip()
                    if rule_str == line:
                        remove_rules.remove(rule)
                        return False

            # Leave it alone
            return True

        # We filter duplicates, letting the *last* occurrence take
        # precendence.  We also filter out anything in the "remove"
        # lists.
        new_filter.reverse()
        new_filter = filter(_weed_out_duplicates, new_filter)
        new_filter = filter(_weed_out_removes, new_filter)
        new_filter.reverse()

        # flush lists, just in case we didn't find something
        remove_chains.clear()
        for rule in remove_rules:
            remove_rules.remove(rule)

        return new_filter


class IpsetsManager(object):
    """Wrapper for ipset."""

    def __init__(self):
        pass

    def create(self, setname, settype, setrange=''):
        if setrange:
            _execute('ipset', 'create', setname, settype, 'range', setrange,
                     run_as_root=True, check_exit_code=[0])
        else:
            _execute('ipset', 'create', setname, settype,
                     run_as_root=True, check_exit_code=[0])

    def destroy(self, setname):
        _execute('ipset', 'destroy', setname,
                 run_as_root=True, check_exit_code=[0])

    def rename(self, name_old, name_new):
        _execute('ipset', 'rename', name_old, name_new,
                 run_as_root=True, check_exit_code=[0])

    def swap(self, name_from, name_to):
        _execute('ipset', 'swap', name_from, name_to,
                 run_as_root=True, check_exit_code=[0])

    def flush(self, setname):
        _execute('ipset', 'flush', setname,
                 run_as_root=True, check_exit_code=[0])

    def add(self, setname, address):
        _execute('ipset', 'add', setname, address,
                 run_as_root=True, check_exit_code=[0])

    def delete(self, setname, address):
        _execute('ipset', 'del', setname, address,
                 run_as_root=True, check_exit_code=[0])

    def list(self):
        ret = []
        out, err = _execute('ipset', '-L', '-name',
                            run_as_root=True, check_exit_code=[0])
        if out:
            out = out.strip()
            ret = [i for i in out.split('\n') if i != '']

        return ret

    def members(self, setname):
        members = []
        out, err = _execute('ipset', 'save', run_as_root=True,
                            check_exit_code=[0])

        if out:
            out = out.strip()
            out = [i for i in out.split('\n') if i != '']

            for line in out:
                if line.find('add ') == 0:
                    line = [i for i in line.replace('\n', '').split(' ')]
                    if line[1] == setname:
                        members.append(line[2])
        return members


# NOTE(stanzgy): ipset could only create set with setname of 31 characters
#                at max, but tenant uuid in keystone is 32 characters long,
#                so truncate the tenant uuid last char
@utils.synchronized('ipsets', external=True)
def init_ipset(context):
    """Build all related ipsets"""

    # build tenant ipsets
    local_instances = db.instance_get_all_by_host(context, FLAGS.host)
    current_ipset_list = ipsets_manager.list()
    target_tenant_list = list(set([i['project_id']
                            for i in local_instances if i['project_id']]))

    for t in target_tenant_list:
        tenant_instances = db.instance_get_all_by_project(context, t)
        tmp_setname = 'tmp-' + t[0:27]
        setname = t[0:31]
        if tmp_setname not in current_ipset_list:
            ipsets_manager.create(tmp_setname, 'bitmap:ip', FLAGS.ipset_range)
        else:
            ipsets_manager.flush(tmp_setname)
        for i in tenant_instances:
            fixed_ip = None
            try:
                fixed_ip = _validate_fixed_ip(
                            db.fixed_ip_get_by_instance(context, i['uuid']))
            except exception.FixedIpNotFoundForInstance:
                LOG.warn(_('Instance %s fixed ip not found') % i['uuid'])

            if fixed_ip:
                ipsets_manager.add(tmp_setname, fixed_ip)
            else:
                LOG.warn(
                    _('Cannot find fixed ip for instance %s on ipset init')
                                % i['uuid'])
        # replace old ipset
        if setname not in current_ipset_list:
            ipsets_manager.rename(tmp_setname, setname)
        else:
            ipsets_manager.swap(tmp_setname, setname)
            ipsets_manager.destroy(tmp_setname)


@utils.synchronized('ipsets', external=True)
def init_private_floating():
    # build private floating ip ipset
    dst_setname = FLAGS.private_floating_ip_dst_setname
    if dst_setname in ipsets_manager.list():
        ipsets_manager.flush(dst_setname)
    else:
        ipsets_manager.create(dst_setname, "hash:net")

    for dst in FLAGS.private_floating_ip_dst:
        ipsets_manager.add(dst_setname, dst)


@utils.synchronized('ipsets', external=True)
def init_private_to_public():
    # build private to public ipset
    dst_setname = FLAGS.private_to_public_setname
    if dst_setname in ipsets_manager.list():
        ipsets_manager.flush(dst_setname)
    else:
        ipsets_manager.create(dst_setname, "hash:net")

    for dst in FLAGS.private_to_public_dst:
        ipsets_manager.add(dst_setname, dst)


@utils.synchronized('ipsets', external=True)
def init_default_private_snat():
    whitelist = FLAGS.private_to_public_whitelist_setname

    if whitelist in ipsets_manager.list():
        ipsets_manager.flush(whitelist)
    else:
        ipsets_manager.create(whitelist, "hash:net")

    for dst in FLAGS.private_to_public_whitelist_dst:
        ipsets_manager.add(whitelist, dst)


def _validate_fixed_ip(fixed_ips):
    if fixed_ips and len(fixed_ips) > 0:
        return fixed_ips[0].get('address', None)
    return None


def is_ipset_existed(tenant):
    return tenant[0:31] in ipsets_manager.list()


def is_address_in_ipset(address, setname):
    return address in ipsets_manager.members(setname[0:31])


@utils.synchronized('ipsets', external=True)
def create_tenant_ipset(tenant, setrange=FLAGS.ipset_range):
    admin_context = context.get_admin_context()
    setname = tenant[0:31]

    if is_ipset_existed(setname):
        LOG.warn(_('Ipset existed: %s, skipped ipset creation') % setname)
    else:
        ipsets_manager.create(setname, 'bitmap:ip', setrange)

    tenant_instances = db.instance_get_all_by_project(admin_context, tenant)
    for i in tenant_instances:
        fixed_ip = None
        try:
            fixed_ip = _validate_fixed_ip(
                        db.fixed_ip_get_by_instance(admin_context, i['uuid']))
        except exception.FixedIpNotFoundForInstance:
            LOG.warn(_('Instance %s fixed ip not found') % i['uuid'])

        if fixed_ip:
            if not is_address_in_ipset(fixed_ip, setname):
                ipsets_manager.add(setname, fixed_ip)


@utils.synchronized('ipsets', external=True)
def add_address_to_ipset(address, tenant):
    setname = tenant[0:31]
    if is_address_in_ipset(address, setname):
        LOG.warn(_('Address %(address)s was already in ipset %(setname)s'),
                    locals())
    else:
        ipsets_manager.add(setname, address)


@utils.synchronized('ipsets', external=True)
def delete_address_from_ipset(address, tenant):
    setname = tenant[0:31]
    if not is_address_in_ipset(address, setname):
        LOG.warn(_('Address %(address)s didnot exist in ipset %(setname)s'),
                    locals())
    else:
        ipsets_manager.delete(tenant[0:31], address)


def check_tc_params(*args, **kwargs):
    '''check type and regex of params to ensure that tc params are valid'''

    subcmd = kwargs.pop('subcmd')

    def check_func(func):

        @functools.wraps(func)
        def decorated(self, *args, **kwargs):

            expected_params = {
                               'qdisc':
                                  [
                                   'dev',
                                   'node',
                                   'handle',
                                   'type',
                                   'default',
                                   'params',
                                   'execute'
                                  ],

                               'class':
                                  [
                                   'dev',
                                   'node_id',
                                   'parent_id',
                                   'class_id',
                                   'type',
                                   'spec',
                                   'execute'
                                  ],

                               'filter':
                                  [
                                   'dev',
                                   'parent_id',
                                   'protocol',
                                   'pref',
                                   'filter_type',
                                   'filter_params',
                                   'class_id',
                                   'action',
                                   'execute'
                                  ],
                               }

            expected_type = {
                             'qdisc':
                                {
                                 'dev': [types.StringType],
                                 'node': [types.StringType],
                                 'handle': [types.StringType, types.NoneType],
                                 'type': [types.StringType, types.NoneType],
                                 'default': [types.IntType, types.NoneType],
                                 'params': [types.StringType, types.NoneType],
                                 'execute': [types.FunctionType,
                                             types.NoneType]
                                },

                             'class':
                                {
                                 'dev': [types.StringType],
                                 'node_id': [types.StringType],
                                 'parent_id': [types.StringType,
                                               types.NoneType],
                                 'class_id': [types.StringType],
                                 'type': [types.StringType],
                                 'spec': [types.DictType],
                                 'execute': [types.FunctionType,
                                             types.NoneType]
                                },

                             'filter':
                                {
                                 'dev': [types.StringType],
                                 'parent_id': [types.StringType,
                                               types.NoneType],
                                 'protocol': [types.StringType],
                                 'pref': [types.IntType, types.NoneType],
                                 'filter_type': [types.StringType],
                                 'filter_params': [types.StringType,
                                                   types.UnicodeType],
                                 'class_id': [types.StringType,
                                              types.NoneType],
                                 'action': [types.StringType, types.NoneType],
                                 'execute': [types.FunctionType,
                                             types.NoneType]
                                }
                            }

            expected_regex = {
                             'qdisc':
                                {
                                 'dev': '^\w+\d+$',
                                 'node': '^root|ingress$',
                                 'type': '^htb$',
                                },

                             'class':
                                {
                                 'dev': '^\w+\d+$',
                                 'type': '^htb$',
                                },

                             'filter':
                                {
                                 'dev': '^\w+\d+$',
                                 'protocol': '^ip$',
                                 'filter_type': '^handle|u32$',
                                }
                              }

            i = 0
            for arg in args:
                kwargs[expected_params[subcmd][i]] = arg
                i += 1
            args = ()

            for k in expected_params[subcmd]:
                if k not in kwargs.keys():
                    kwargs[k] = None

            msg = _("Unexpected value %(kwargs_arg)s (%(kwargs_arg_type)s) "
                    "for arg '%(arg)s' in tc %(subcmd)s, %(expect)s wanted")
            for arg in kwargs.keys():
                if not type(kwargs[arg]) in expected_type[subcmd][arg]:
                    kwargs_arg = kwargs[arg],
                    kwargs_arg_type = type(kwargs[arg])
                    expect = expected_type[subcmd][arg]
                    err = msg % locals()
                    raise exception.InvalidTcParam(err=err)

                cond = (arg in expected_regex[subcmd].keys() and
                        kwargs[arg] is not None)
                if cond:
                    if not re.match(expected_regex[subcmd][arg], kwargs[arg]):
                        kwargs_arg = kwargs[arg],
                        kwargs_arg_type = type(kwargs[arg])
                        expect = expected_type[subcmd][arg]
                        err = msg % locals()
                        raise exception.InvalidTcParam(err=err)

            return func(self, *args, **kwargs)

        return decorated

    return check_func


def check_network_qos_params(t, spec=None, node=None):
    if t not in ('public', 'private', 'snat'):
        msg = (_('Invalid network qos type %s, '
                 'public or private wanted') % t)
        raise exception.InvalidTcParam(err=msg)

    if spec:
        if type(spec) is not types.DictType:
            msg = (_('Invalid network qos spec %s, '
                     'a dict is required') % str(spec))
            raise exception.InvalidTcParam(err=msg)

        if not spec.get('rate', None):
            msg = (_('Invalid network qos spec %s, '
                     'rate is required') % str(spec))
            raise exception.InvalidTcParam(err=msg)

    if node:
        if node not in ('egress', 'ingress'):
            msg = (_('Invalid network qos node %s, '
                     'egress or ingress is required') % node)
            raise exception.InvalidTcParam(err=msg)


class TcQdisc(object):
    """Wrapper for tc qdisc"""

    @check_tc_params(subcmd='qdisc')
    def __init__(self, *args, **kwargs):
        # NOTE(stanzgy): tc qdisc synopsis
        #                tc qdisc [ add | change | replace | link ] dev DEV
        #                    [ parent qdisc-id | root ] [ handle qdisc-id ]
        #                    qdisc [ qdisc specific parameters ]

        self.dev = kwargs.get('dev', None)
        self.node = kwargs.get('node', None)
        self.handle = kwargs.get('handle', None)
        self.type = kwargs.get('type', None)
        self.default = kwargs.get('default', None)
        self.params = kwargs.get('params', None)

        self.cls = {}
        self.filt = {}

        execute = kwargs.get('execute', None)
        if not execute:
            self.execute = _execute
        else:
            self.execute = execute

    def __str__(self):
        qdisc = 'dev %s %s' % (self.dev, self.node)

        if self.handle:
            qdisc += ' handle %s:' % self.handle

        if self.type:
            qdisc += ' %s' % self.type

        if self.default:
            qdisc += ' default %d' % self.default

        if self.params:
            qdisc += ' %s' % self.params

        return qdisc

    def _apply(self, action):
        cmd = ['tc', 'qdisc', action]
        cmd += self.to_list()

        _str = self.__str__()
        LOG.debug(_('apply tc qdisc: %(action)s %(_str)s') % locals())
        self.execute(*cmd, run_as_root=True, check_exit_code=[0])

    def to_list(self):
        return self.__str__().split(' ')

    def apply(self):
        self._apply('add')
        self.state = 'added'

    def delete(self):
        self._apply('del')
        self.state = 'deleted'

    def add_class(self, class_id, spec, parent_id=None):
        # NOTE(stanzgy): add tc class only works on egress qdisc.
        cls = TcClass(dev=self.dev,
                      node_id=self.handle,
                      parent_id=parent_id,
                      class_id=class_id,
                      type=self.type,
                      spec=spec)

        cls.apply()
        self.cls[class_id] = cls

        return cls

    def add_filter(self, protocol, pref, filter_type,
                   filter_params, class_id=None, action=None):
        filt = TcFilter(dev=self.dev,
                        parent_id=self.handle,
                        protocol=protocol,
                        pref=pref,
                        filter_type=filter_type,
                        filter_params=filter_params,
                        class_id=class_id, action=action)

        filt.apply()
        self.filt[pref] = filt

        return filt

    def del_class(self, class_id):
        # NOTE(stanzgy): delete tc class only works on egress qdisc.
        self.cls[class_id].delete()

    def del_filter(self, pref):
        self.filt[pref].delete()

    def get_class(self, class_id):
        return self.cls.get(class_id, None)

    def get_filter(self, pref):
        return self.filt.get(pref, None)

    def get_valid_class_id(self):
        '''return valid class id *list* of this qdisc'''
        return filter(lambda x: self.cls.get(x).state != 'deleted',
                      self.cls.keys())

    def get_valid_class(self):
        '''return valid class *list* of this qdisc'''
        return filter(lambda x: x.state != 'deleted', self.cls.values())

    def get_all_class(self):
        '''return all class *dict* of this qdisc'''
        return self.cls

    def get_valid_filter_pref(self):
        '''return valid filter pref *list* of this qdisc'''
        return filter(lambda x: self.filt.get(x).state != 'deleted',
                      self.filt.keys())

    def get_valid_filter(self):
        '''return valid filter *list* of this qdisc'''
        return filter(lambda x: x.state != 'deleted', self.filt.values())

    def get_all_filter(self):
        '''return all filter *dict* of this qdisc'''
        return self.filt


class TcClass(object):
    """Wrapper for tc class"""

    @check_tc_params(subcmd='class')
    def __init__(self, *args, **kwargs):
        # NOTE(stanzgy): tc class synopsis
        #                tc class [ add | change | replace ] dev DEV
        #                    parent qdisc-id  [ classid class-id ] qdisc
        #                    [ qdisc specific parameters ]

        self.dev = kwargs.get('dev', None)
        self.node_id = kwargs.get('node_id', None)
        self.parent_id = kwargs.get('parent_id', None)
        self.class_id = kwargs.get('class_id', None)
        self.type = kwargs.get('type', None)
        self.spec = kwargs.get('spec', None)

        self.cls = {}
        self.filt = {}

        execute = kwargs.get('execute', None)
        if not execute:
            self.execute = _execute
        else:
            self.execute = execute

    def __str__(self):
        if not self.parent_id:
            parent_id = ""
        else:
            parent_id = self.parent_id

        cls = 'dev %s parent %s:%s classid %s:%s %s' % (self.dev,
                                                        self.node_id,
                                                        parent_id,
                                                        self.node_id,
                                                        self.class_id,
                                                        self.type)

        spec = ""
        for k in self.spec.keys():
            if k == 'type':
                pass
            elif k in ('rate', 'ceil', 'burst', 'cburst'):
                if type(self.spec[k]) is int:
                    spec += " %s %smbit" % (k, str(self.spec[k]))
                else:
                    spec += " %s %s" % (k, str(self.spec[k]))
            else:
                spec += " %s %s" % (k, str(self.spec[k]))

        cls += spec
        return cls

    def _apply(self, action):
        cmd = ['tc', 'class', action]
        cmd += self.to_list()

        _str = self.__str__()
        LOG.debug(_('apply tc class: %(action)s %(_str)s') % locals())
        self.execute(*cmd, run_as_root=True, check_exit_code=[0])

    def to_list(self):
        return self.__str__().split(' ')

    def apply(self):
        self._apply('add')
        self.state = 'added'

    def delete(self):
        # delete all filters relate to this class first
        try:
            for filt in self.get_valid_filter():
                filt.delete()
        except Exception:
            pass

        self._apply('del')
        self.state = 'deleted'

    def change(self, spec):
        if type(spec) is not types.DictionaryType:
            msg = "Unexpected value %s(%s) for arg '%s' in tc %s, %s wanted"
            msg = msg % (spec, type(spec), 'spec', 'class',
                         str(types.DictionaryType))
            raise exception.InvalidTcParam(err=msg)

        self.spec = spec
        self._apply('change')

    def add_class(self, class_id, spec):
        cls = TcClass(dev=self.dev,
                      node_id=self.node_id,
                      parent_id=self.class_id,
                      class_id=class_id,
                      type=self.type,
                      spec=spec)

        cls.apply()
        self.cls[class_id] = cls

        return cls

    def mod_class(self, class_id, spec):
        cls = self.cls.get(class_id)
        cls.change(spec)

        return cls

    def del_class(self, class_id):
        cls = self.cls.get(class_id)
        if cls:
            # delete all filters relate to this class first
            for filt in cls.get_valid_filter():
                try:
                    filt.delete()
                except Exception:
                    pass

            self.cls[class_id].delete()

    def add_filter(self, protocol, pref, node, address):
        filter_type = 'u32'

        if node == 'ingress':
            filter_params = 'match ip dst %s/32' % address
        else:
            filter_params = 'match ip src %s/32' % address

        filt = TcFilter(dev=self.dev,
                        parent_id=self.node_id,
                        protocol=protocol,
                        pref=pref,
                        filter_type=filter_type,
                        filter_params=filter_params,
                        class_id=self.class_id)

        filt.apply()
        self.filt[address] = filt

        return filt

    def add_snat_egress_filter(self, protocol, pref, fwmark):
        filt_type = 'handle'
        filt_cond = '%s fw' % fwmark

        filt = TcFilter(dev=self.dev,
                        parent_id=self.node_id,
                        protocol=protocol,
                        pref=pref,
                        filter_type=filt_type,
                        filter_params=filt_cond,
                        class_id=self.class_id)

        filt.apply()
        self.filt['snat'] = filt

    def del_filter(self, address):
        filt = self.filt.get(address)
        if filt:
            filt.delete()

    def get_class(self, class_id):
        return self.cls.get(class_id, None)

    def get_filter(self, address):
        return self.filt.get(address, None)

    def get_valid_class_id(self):
        '''return valid class id *list* of this class'''
        return filter(lambda x: self.cls.get(x).state != 'deleted',
                      self.cls.keys())

    def get_valid_class(self):
        '''return valid class *list* of this class'''
        return filter(lambda x: x.state != 'deleted',
                      self.cls.values())

    def get_all_class(self):
        '''return all class *dict* of this class'''
        return self.cls

    def get_valid_filter_addr(self):
        '''return valid filter address *list* of this class'''
        return filter(lambda x: self.filt.get(x).state != 'deleted',
                      self.filt.keys())

    def get_valid_filter(self):
        '''return valid filter *list* of this class'''
        return filter(lambda x: x.state != 'deleted',
                      self.filt.values())

    def get_all_filter(self):
        '''return all filter *dict* of this class'''
        return self.filt


class TcFilter(object):
    """Wrapper for filter"""

    @check_tc_params(subcmd='filter')
    def __init__(self, *args, **kwargs):
        # NOTE(stanzgy): tc filter synopsis
        #                tc filter [ add | change | replace ] dev DEV
        #                    [ parent qdisc-id | root ] protocol protocol
        #                    prio priority filtertype
        #                    [ filtertype specific param-eters ] flowid flow-id

        self.dev = kwargs.get('dev', None)
        self.parent_id = kwargs.get('parent_id', None)
        self.protocol = kwargs.get('protocol', None)
        self.pref = kwargs.get('pref', None)
        self.filter_type = kwargs.get('filter_type', None)
        self.filter_params = kwargs.get('filter_params', None)
        self.class_id = kwargs.get('class_id', None)
        self.action = kwargs.get('action', None)

        execute = kwargs.get('execute', None)
        if not execute:
            self.execute = _execute
        else:
            self.execute = execute

    def __str__(self):
        filt = 'dev %s protocol %s' % (self.dev,
                                       self.protocol)

        if self.parent_id:
            filt += ' parent %s:' % self.parent_id

        if self.pref:
            filt += ' pref %s' % self.pref

        filt += ' %s %s' % (self.filter_type,
                            self.filter_params)

        if self.class_id:
            filt += ' classid %s:%s' % (self.parent_id, self.class_id)

        if self.action:
            filt += ' action %s' % self.action

        return filt

    def _apply(self, action):
        cmd = ['tc', 'filter', action]
        cmd += self.to_list()

        _str = self.__str__()
        LOG.debug(_('apply tc filter: %(action)s %(_str)s') % locals())
        self.execute(*cmd, run_as_root=True, check_exit_code=[0])

    def to_list(self):
        return self.__str__().split(' ')

    def apply(self):
        self._apply('add')
        self.state = 'added'

    def delete(self):
        self._apply('del')
        self.state = 'deleted'


class TcManager(object):
    """Wrapper for tc"""

    # NOTE(stanzgy): use egress and ingress to save the factual network qos
    #                qdisc
    egress = None
    ingress = None

    e_pvt_cls = None
    e_pub_cls = None
    i_pvt_cls = None
    i_pub_cls = None
    i_snat_cls = None

    def __init__(self, execute=None):
        if not execute:
            self.execute = _execute
        else:
            self.execute = execute

        self.fw_mask = FLAGS.tc_fw_mask
        self.tc_class_pvt_mask = FLAGS.tc_class_pvt_mask
        self.tc_class_pub_mask = FLAGS.tc_class_pub_mask
        self.tc_filter_pvt_mask = FLAGS.tc_filter_pvt_mask
        self.tc_filter_pub_mask = FLAGS.tc_filter_pub_mask
        self.tc_filter_snat_mask = FLAGS.tc_filter_snat_mask

        # NOTE(stanzgy): use phydev_egress and phydev_ingress to save the
        #                redirect qdisc for original physical network interface
        self.phydev_egress = {}
        self.phydev_ingress = {}

        self.egress_dev = FLAGS.network_qos_egress_interface
        self.ingress_dev = FLAGS.network_qos_ingress_interface

        self.egress_private_class = '10'
        self.ingress_private_class = '20'
        self.egress_public_class = '30'
        self.ingress_public_class = '40'
        self.ingress_snat_class = '49'

        self.private_bandwidth = int(
                                FLAGS.network_qos_host_private_bandwidth *
                                FLAGS.network_qos_private_allocation_ratio -
                                FLAGS.reserved_host_network_private_bandwidth)
        self.public_bandwidth = int(
                                FLAGS.network_qos_host_public_bandwidth *
                                FLAGS.network_qos_public_allocation_ratio -
                                FLAGS.reserved_host_network_public_bandwidth)

    def _init_network_qos_device(self):
        # NOTE(stanzgy): to use network qos feature, ifb device is required.
        #                ifb module is in linux kernel mainline.
        #
        #                to use ifb dummy device, run command:
        #
        #                    # modprobe ifb [numifbs=N]
        #
        #                by default there should be two ifb dummy device
        #                created, you can specify numifbs to create specific
        #                number of ifb dummy device you want.

        LOG.debug(_('initializing network qos device'))

        self.config = self.get_network_qos_config()

        # NOTE(stanzgy): `dev` e.g. ['ifb0', 'ifb1']
        out, err = self.execute('ip', 'link',
                                run_as_root=True, check_exit_code=0)
        dev = map(lambda x: x[0], re.findall('((ifb)\d+)', out))

        if not dev:
            _err = _("ifb device for network qos not found")
            raise exception.TcDeviceNotFound(err=_err)

        msg = _("Invalid qos device %(qdev)s, %(dev)s wanted.")
        if self.egress_dev not in dev:
            qdev = self.egress_dev
            _err = msg % locals()
            raise exception.InvalidTcDevice(err=_err)

        if self.ingress_dev not in dev:
            qdev = self.ingress_dev
            _err = msg % locals()
            raise exception.InvalidTcDevice(err=_err)

        # ensure egress device and ingress device are not the same one
        if self.egress_dev == self.ingress_dev:
            raise exception.InvalidTcDevice(err=_("Egress qos device and "
                                                  "Ingress qos device cannot "
                                                  "be the same one"))

        # ensure device state is up
        self.execute('ip', 'link', 'set',
                     self.egress_dev,
                     'up',
                     run_as_root=True, check_exit_code=0)

        self.execute('ip', 'link', 'set',
                     self.ingress_dev,
                     'up',
                     run_as_root=True, check_exit_code=0)

        # clear device qdisc
        # `_dev` e.g. ('htb', 'ifb0'), ('ingress', 'ifb0')
        out, err = self.execute('tc', 'qdisc', 'ls',
                                run_as_root=True, check_exit_code=0)
        target_dev = [self.egress_dev,
                      self.ingress_dev] + FLAGS.network_qos_physical_interface
        _dev = filter(lambda x: x[1] in target_dev,
                      re.findall('qdisc (\w+) \w+: dev (\w+)', out))

        if _dev:
            for d in _dev:
                if d[0] == 'htb':
                    self.execute('tc', 'qdisc', 'del', 'dev', d[1], 'root',
                                 run_as_root=True, check_exit_code=0)
                if d[0] == 'ingress':
                    self.execute('tc', 'qdisc', 'del', 'dev', d[1], 'ingress',
                                 run_as_root=True, check_exit_code=0)

        # redirect all physical network interface traffic to ifb device
        for i in FLAGS.network_qos_physical_interface:
            self.phydev_egress[i] = TcQdisc(dev=i, node='root',
                                            handle='100', type='htb')
            self.phydev_egress[i].apply()
            self.phydev_egress[i].add_filter('ip', 1, 'u32', 'match u32 0 0',
                                       action='mirred egress redirect dev %s' %
                                              self.egress_dev)
            self.phydev_ingress[i] = TcQdisc(dev=i, node='ingress',
                                             handle='ffff')
            self.phydev_ingress[i].apply()
            self.phydev_ingress[i].add_filter('ip', 1, 'u32', 'match u32 0 0',
                                       action='mirred egress redirect dev %s' %
                                              self.ingress_dev)

        # init ifb device
        TcManager.egress = TcQdisc(dev=self.egress_dev, node='root',
                                   handle='9', type='htb')
        TcManager.egress.apply()
        TcManager.ingress = TcQdisc(dev=self.ingress_dev, node='root',
                                    handle='9', type='htb')
        TcManager.ingress.apply()

        # set openstack main network qos class
        private_spec = {
                        'rate': self.private_bandwidth,
                       }

        public_spec = {
                       'rate': self.public_bandwidth,
                      }

        TcManager.e_pvt_cls = TcManager.egress.add_class(
                                                self.egress_private_class,
                                                private_spec)
        TcManager.e_pub_cls = TcManager.egress.add_class(
                                                self.egress_public_class,
                                                public_spec)
        TcManager.i_pvt_cls = TcManager.ingress.add_class(
                                                self.ingress_private_class,
                                                private_spec)
        TcManager.i_pub_cls = TcManager.ingress.add_class(
                                                self.ingress_public_class,
                                                public_spec)

        # init whitelist that w/o network qos
        for n in FLAGS.network_qos_whitelist:
            net = netaddr.IPNetwork(n)
            u32_src = "match ip src %s" % str(net)
            u32_dst = "match ip dst %s" % str(net)
            TcManager.egress.add_filter('ip', 5, 'u32', u32_dst, '1')
            TcManager.ingress.add_filter('ip', 5, 'u32', u32_src, '1')

        # init network qos class and filter for default snat
        policy_snat = self.config['policy']['public']['default_snat']
        shaping_snat = self.config['shaping']['public']['default_snat']
        if policy_snat['shared_ingress']:
            TcManager.i_snat_cls = TcManager.i_pub_cls.add_class(
                                        self.ingress_snat_class,
                                        shaping_snat['shared_ingress'])
            TcManager.i_snat_cls.add_filter('ip', 9, 'ingress',
                                            FLAGS.routing_source_ip)

        if not FLAGS.allow_private_to_public:
            cmd = ['tc', 'filter', 'add', 'dev', self.egress_dev, 'pref',
                   FLAGS.tc_private_to_public_pref, 'parent', '9:', 'handle',
                   FLAGS.tc_private_to_public_fwmark, 'fw', 'action', 'drop']
            self.execute(*cmd, run_as_root=True, check_exit_code=[0])

    def get_network_qos_config(self):
        config_file_path = FLAGS.network_qos_config
        if os.path.exists(config_file_path):
            with open(config_file_path, 'r') as conf:
                try:
                    config = json.load(conf)

                except ValueError, e:
                    raise exception.InvalidTcConfigFile(err=e)
        else:
            msg = _("Network QoS config file not found: %s") % config_file_path
            raise exception.TcConfigFileNotFound(err=msg)

        return config

    @utils.synchronized('tc_register', external=True)
    def _register(self, instance_id):
        instance_id = int(instance_id)

        ctxt = context.get_admin_context()
        instances = db.instance_get_all_by_host(ctxt, FLAGS.host)
        tc_ids = {}
        instance = None

        for i in instances:
            smd = db.instance_system_metadata_get(ctxt,
                                                  i['uuid'])
            instance_tc_id = smd.get('network-tc-id', None)

            if i['id'] == instance_id:
                instance = i
                tc_id = instance_tc_id
                sys_metadata = smd

                if tc_id:
                    tc_id = int(tc_id)

            if instance_tc_id:
                instance_tc_id = int(instance_tc_id)

                if instance_tc_id in tc_ids.values():
                    i_id = i['id']
                    raise exception.InvalidTcInstanceId(
                        err=_("Duplicated tc id found, instance %(i_id)s, "
                        "tc_id %(instance_tc_id)s, "
                        "current tc ids: %(tc_ids)s") % locals())

                tc_ids[i['id']] = instance_tc_id

        LOG.debug(_('tc registered instances: %(tc_ids)s') % locals())

        if not instance:
            raise exception.TcNotFound(err=_("instance %(instance_id)s not "
                                             "found on this host.") % locals())

        if not tc_id:
            res = filter(lambda x: x not in tc_ids.values(), range(1, 998))
            tc_id = res[0]
            sys_metadata['network-tc-id'] = int(tc_id)
            db.instance_system_metadata_update(ctxt,
                                               instance['uuid'],
                                               sys_metadata,
                                               True)

        LOG.debug(_('instance %(instance_id)d registered in tc manager with '
                    'id %(tc_id)d') % locals())
        return tc_id

    @utils.synchronized('tc_register', external=True)
    def _get_instance_qos_id(self, instance_id):

        ctxt = context.get_admin_context()

        try:
            instance = db.instance_get(ctxt, instance_id)
        except exception.InstanceNotFound:
            raise exception.InvalidTcInstanceId(err=_("Instance %s not "
                                                      "found") %
                                                      instance_id)

        sys_metadata = db.instance_system_metadata_get(ctxt,
                                                       instance['uuid'])
        qos_id = sys_metadata.get('network-tc-id', None)

        if not qos_id:
            raise exception.InvalidTcInstanceId(err=_("Instance %s not "
                                                      "registered") %
                                                      instance_id)
        return int(qos_id)

    def _instance_fw_mark(self, instance_id):
        qos_id = self._get_instance_qos_id(instance_id)
        return hex(int(self.fw_mask, 16) + qos_id)

    def _instance_tc_class_id(self, instance_id, qtype):
        check_network_qos_params(qtype)
        qos_id = self._get_instance_qos_id(instance_id)

        if qtype == 'public':
            mask = self.tc_class_pub_mask
        else:
            mask = self.tc_class_pvt_mask

        return hex(int(mask, 16) + qos_id)

    def _instance_tc_filter_pref(self, instance_id, qtype):
        check_network_qos_params(qtype)

        if qtype == 'snat':
            mask = self.tc_filter_snat_mask
        elif qtype == 'public':
            mask = self.tc_filter_pub_mask
        else:
            mask = self.tc_filter_pvt_mask

        return (mask + self._get_instance_qos_id(instance_id))

    def add_instance_class(self, instance_id, qtype, node, spec):
        """add tc class for instance with specific
           network qos type, node and spec."""

        LOG.debug(_('adding tc class for instance %(instance_id)d with '
                    'type %(qtype)s, node %(node)s, spec %(spec)s.') %
                                                    locals())

        check_network_qos_params(qtype, spec, node)
        class_id = self._instance_tc_class_id(instance_id, qtype)

        # setup instance dedicated rules
        if node == 'ingress':
            if qtype == 'public':
                cls = TcManager.i_pub_cls
            else:
                cls = TcManager.i_pvt_cls
        else:
            if qtype == 'public':
                cls = TcManager.e_pub_cls
            else:
                cls = TcManager.e_pvt_cls

        if (class_id in cls.get_valid_class_id() and
            cls.get_class(class_id).state != 'deleted'):
            sc = cls.get_class(class_id)
            LOG.debug(_("'tc class '%(sc)s' already existed in "
                        "class '%(cls)s', deleted.") % locals())
            cls.del_class(class_id)

        cls.add_class(class_id, spec)

    def add_instance_filter(self, instance_id, qtype, node, address):
        """add tc filter for instance with specific
           network qos type, node and address."""
           # node = egress ingress 
           # qtype = floating_ip

        LOG.debug(_("add %(qtype)s address %(address)s to "
                    "instance %(instance_id)d network qos") % locals())

        check_network_qos_params(qtype, node=node)

        class_id = self._instance_tc_class_id(instance_id, qtype)
        pref = self._instance_tc_filter_pref(instance_id, qtype)

        if node == 'ingress':
            if qtype == 'public':
                cls = TcManager.i_pub_cls
            else:
                cls = TcManager.i_pvt_cls
        else:
            if qtype == 'public':
                cls = TcManager.e_pub_cls
            else:
                cls = TcManager.e_pvt_cls

        if (address in cls.get_valid_filter_addr() and
            cls.get_filter(address).state != 'deleted'):
            filt = cls.get_filter(pref)
            LOG.debug(_("'tc filter '%(filt)s' already existed in "
                        "class '%(cls)s', deleted.") % locals())
            cls.del_filter(address)

        c = cls.get_class(class_id)
        if not c:
            raise exception.TcClassNotFound(err=_("Tc class %(class_id)s for "
                                                  "instance %(instance_id)s "
                                                  "not found") % locals())
        c.add_filter('ip', pref, node, address)

    def add_snat_egress_filter(self, instance_id):
        """add tc filter for instance snat."""

        LOG.debug(_('add default snat network qos for instance %d') %
                                                    instance_id)

        class_id = self._instance_tc_class_id(instance_id, 'public')
        pref = self._instance_tc_filter_pref(instance_id, 'snat')
        fwmark = self._instance_fw_mark(instance_id)

        cls = TcManager.e_pub_cls
        c = cls.get_class(class_id)
        if not c:
            raise exception.TcClassNotFound(err=_("Tc class %(class_id)s for "
                                                  "instance %(instance_id)s "
                                                  "not found") % locals())

        snat = c.get_filter('snat')
        if snat:
            LOG.debug(_("'tc filter '%(snat)s' already existed in "
                        "class '%(c)s', deleted.") % locals())
            c.del_filter('snat')

        c.add_snat_egress_filter('ip', pref, fwmark)

    def del_instance_class(self, instance_id, qtype, node):
        """clean up network qos for an instance with specific type"""

        LOG.debug(_("delele tc class for instance %(instance_id)d, "
                    "type %(qtype)s node %(node)s") % locals())

        check_network_qos_params(qtype, node=node)

        class_id = self._instance_tc_class_id(instance_id, qtype)

        if node == 'ingress':
            if qtype == 'public':
                cls = TcManager.i_pub_cls
            else:
                cls = TcManager.i_pvt_cls
        else:
            if qtype == 'public':
                cls = TcManager.e_pub_cls
            else:
                cls = TcManager.e_pvt_cls

        c = cls.get_class(class_id)
        if c:
            try:
                filts = c.get_valid_filter()
                for filt in filts:
                    filt.delete()

                # ensure instance filter is clean
                if not filts:
                    LOG.warn(_("no valid filters found for class '%(c)s', try "
                               "to delete class filters manually.") % locals())

                    filt_pref = self._instance_tc_filter_pref(instance_id,
                                                          qtype)
                    if qtype == 'public':
                        snat_pref = self._instance_tc_filter_pref(instance_id,
                                                                  'snat')

                    if node == 'ingress':
                        dev = self.ingress_dev
                    else:
                        dev = self.egress_dev

                    try:
                        self.execute("tc", "filter", "del", "dev", dev,
                                     "pref", filt_pref,
                                     run_as_root=True, check_exit_code=[0])

                        if qtype == 'public':
                            self.execute("tc", "filter", "del", "dev", dev,
                                         "pref", snat_pref,
                                         run_as_root=True, check_exit_code=[0])
                    except Exception:
                        pass
            except Exception, e:
                LOG.warn(_("error when deleting filters related to "
                           "%(qtype)s %(node)s class for instance "
                           "%(instance_id)s: %(e)s") % locals())
            c.delete()
        else:
            LOG.warn(_("error while deleting instance class: "
                       "%(qtype)s %(node)s class for instance %(intance_id)s "
                       "not found") % locals())

    def del_instance_filter(self, instance_id, qtype, node, address):
        """delete instance tc filter for an instance with specific type"""

        LOG.debug(_('delele tc filter for instance %(instance_id)d, '
                    'type %(qtype)s, node %(node)s, address %(address)s') %
                                                    locals())

        check_network_qos_params(qtype, node=node)

        class_id = self._instance_tc_class_id(instance_id, qtype)

        if node == 'ingress':
            if qtype == 'public':
                cls = TcManager.i_pub_cls
            else:
                cls = TcManager.i_pvt_cls
        else:
            if qtype == 'public':
                cls = TcManager.e_pub_cls
            else:
                cls = TcManager.e_pvt_cls

        c = cls.get_class(class_id)
        filt = c.get_filter(address)
        if filt:
            filt.delete()
        else:
            LOG.warn(_("%(qtype)s %(node)s filter for address %(address)s "
                       "not found, try to delete manually.") % locals())

            pref = self._instance_tc_filter_pref(instance_id, qtype)

            if node == 'ingress':
                dev = self.ingress_dev
            else:
                dev = self.egress_dev

            try:
                self.execute("tc", "filter", "del", "dev", dev,
                             "pref", pref,
                             run_as_root=True, check_exit_code=[0])
            except Exception:
                pass

    def mod_instance_class(self, instance_id, qtype, node, spec):
        """mod tc class for instance with specific
           network qos type, node and spec."""

        LOG.debug(_('modifying tc class for instance %(instance_id)d with '
                    'type %(qtype)s, node %(node)s, spec %(spec)s') %
                                                    locals())

        check_network_qos_params(qtype, spec, node)
        class_id = self._instance_tc_class_id(instance_id, qtype)

        # setup instance dedicated rules
        if node == 'ingress':
            if qtype == 'public':
                cls = TcManager.i_pub_cls
            else:
                cls = TcManager.i_pvt_cls
        else:
            if qtype == 'public':
                cls = TcManager.e_pub_cls
            else:
                cls = TcManager.e_pvt_cls

        if class_id not in cls.get_valid_class_id():
            msg = _("'tc class '%(class_id)s' doesn't exist in "
                    "class '%(cls)s', can't modify.") % locals()
            raise exception.TcClassNotFound(err=msg)

        cls.mod_class(class_id, spec)


# NOTE(jkoelker) This is just a nice little stub point since mocking
#                builtins with mox is a nightmare
def write_to_file(file, data, mode='w'):
    with open(file, mode) as f:
        f.write(data)


def metadata_forward():
    """Create forwarding rule for metadata."""
    if FLAGS.metadata_host != '127.0.0.1':
        iptables_manager.ipv4['nat'].add_rule('PREROUTING',
                                          '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                                          '-p tcp -m tcp --dport 80 -j DNAT '
                                          '--to-destination %s:%s' %
                                          (FLAGS.metadata_host,
                                           FLAGS.metadata_port))
    else:
        iptables_manager.ipv4['nat'].add_rule('PREROUTING',
                                          '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                                          '-p tcp -m tcp --dport 80 '
                                          '-j REDIRECT --to-ports %s' %
                                           FLAGS.metadata_port)
    iptables_manager.apply()


def metadata_accept():
    """Create the filter accept rule for metadata."""
    iptables_manager.ipv4['filter'].add_rule('INPUT',
                                             '-s 0.0.0.0/0 -d %s '
                                             '-p tcp -m tcp --dport %s '
                                             '-j ACCEPT' %
                                             (FLAGS.metadata_host,
                                              FLAGS.metadata_port))
    iptables_manager.apply()


def add_snat_rule(ip_range):
    if FLAGS.routing_source_ip:
        if FLAGS.use_private_floating_ip:
            rule = ('-s %s -m set ! --match-set %s dst -j SNAT --to-source %s'
                                    % (ip_range,
                                       FLAGS.private_floating_ip_dst_setname,
                                       FLAGS.routing_source_ip))

        else:
            rule = '-s %s -j SNAT --to-source %s' % (ip_range,
                                                     FLAGS.routing_source_ip)
        if FLAGS.public_interface:
            rule += ' -o %s' % FLAGS.public_interface

        if FLAGS.add_default_private_snat:
            for i in FLAGS.private_interfaces:
                pr = ('-s %s -o %s -m set --match-set %s dst -j MASQUERADE'
                            % (ip_range,
                               i,
                               FLAGS.private_to_public_whitelist_setname))
                iptables_manager.ipv4['nat'].add_rule('snat', pr)

        if not FLAGS.allow_private_to_public:
            for i in FLAGS.private_interfaces:
                m = ('-s %s -m set --match-set %s dst -o %s -j MARK '
                     '--set-mark %s' %
                     (FLAGS.fixed_range,
                      FLAGS.private_to_public_setname, i,
                      FLAGS.tc_private_to_public_fwmark))
                iptables_manager.ipv4['nat'].add_rule('snat', m)

            m = ('-s %s -m set --match-set %s dst -o %s -j MARK '
                 '--set-mark %s' %
                 (FLAGS.fixed_range,
                  FLAGS.private_to_public_setname,
                  FLAGS.public_interface,
                  FLAGS.tc_private_to_public_fwmark))
            iptables_manager.ipv4['nat'].add_rule('snat', m)

            cmrule = ('-m mark --mark %s -j CONNMARK --save-mark' %
                      FLAGS.tc_private_to_public_fwmark)
            iptables_manager.ipv4['nat'].add_rule('snat', cmrule)

        iptables_manager.ipv4['nat'].add_rule('snat', rule)

        iptables_manager.apply()


def init_host(ip_range=None):
    """Basic networking setup goes here."""
    # NOTE(devcamcar): Cloud public SNAT entries and the default
    # SNAT rule for outbound traffic.
    if not ip_range:
        ip_range = FLAGS.fixed_range

    if FLAGS.use_private_floating_ip:
        init_private_floating()

    # NOTE(stanzgy): handle private to public flow rules here
    if (not FLAGS.allow_private_to_public and not FLAGS.use_network_qos):
        raise exception.Invalid(_("To set use_private_floating_ip False, "
                                  "use_network_qos should be True. "))

    if not FLAGS.allow_private_to_public:
        init_private_to_public()
        iptables_manager.ipv4['mangle'].add_rule('PREROUTING',
                                                 '-j CONNMARK --restore-mark')

    if FLAGS.add_default_private_snat:
        init_default_private_snat()

    add_snat_rule(ip_range)

    iptables_manager.ipv4['nat'].add_rule('POSTROUTING',
                                          '-s %s -d %s/32 -j ACCEPT' %
                                          (ip_range, FLAGS.metadata_host))

    for dmz in FLAGS.dmz_cidr:
        iptables_manager.ipv4['nat'].add_rule('POSTROUTING',
                                              '-s %s -d %s -j ACCEPT' %
                                              (ip_range, dmz))

    iptables_manager.ipv4['nat'].add_rule('POSTROUTING',
                                          '-s %(range)s -d %(range)s '
                                          '-m conntrack ! --ctstate DNAT '
                                          '-j ACCEPT' %
                                          {'range': ip_range})

    # NOTE(stanzgy): add filling DHCP checksum iptable rule here
    if FLAGS.enable_fill_dhcp_checksum:
        iptables_manager.ipv4['mangle'].add_chain('nova-postrouting-bottom',
                                      wrap=False)
        iptables_manager.ipv4['mangle'].add_rule('POSTROUTING',
                                     '-j nova-postrouting-bottom',
                                     wrap=True, top=False)

        iptables_manager.ipv4['mangle'].add_rule('nova-postrouting-bottom',
            '-m udp -p udp --dport 68 -j CHECKSUM --checksum-fill',
            wrap=False, top=False)

    iptables_manager.apply()


def send_arp_for_ip(ip, device, count):
    out, err = _execute('arping', '-U', ip,
                        '-A', '-I', device,
                        '-c', str(count),
                        run_as_root=True, check_exit_code=False)

    if err:
        LOG.debug(_('arping error for ip %s'), ip)


def bind_floating_ip(floating_ip, device):
    """Bind ip to public interface."""
    _execute('ip', 'addr', 'add', str(floating_ip) + '/32',
             'dev', device,
             run_as_root=True, check_exit_code=[0, 2, 254])

    if FLAGS.send_arp_for_ha and FLAGS.send_arp_for_ha_count > 0:
        send_arp_for_ip(floating_ip, device, FLAGS.send_arp_for_ha_count)


def unbind_floating_ip(floating_ip, device):
    """Unbind a public ip from public interface."""
    _execute('ip', 'addr', 'del', str(floating_ip) + '/32',
             'dev', device,
             run_as_root=True, check_exit_code=[0, 2, 254])


def ensure_metadata_ip():
    """Sets up local metadata ip."""
    _execute('ip', 'addr', 'add', '169.254.169.254/32',
             'scope', 'link', 'dev', 'lo',
             run_as_root=True, check_exit_code=[0, 2, 254])


def ensure_vpn_forward(public_ip, port, private_ip):
    """Sets up forwarding rules for vlan."""
    iptables_manager.ipv4['filter'].add_rule('FORWARD',
                                             '-d %s -p udp '
                                             '--dport 1194 '
                                             '-j ACCEPT' % private_ip)
    iptables_manager.ipv4['nat'].add_rule('PREROUTING',
                                          '-d %s -p udp '
                                          '--dport %s -j DNAT --to %s:1194' %
                                          (public_ip, port, private_ip))
    iptables_manager.ipv4['nat'].add_rule('OUTPUT',
                                          '-d %s -p udp '
                                          '--dport %s -j DNAT --to %s:1194' %
                                          (public_ip, port, private_ip))
    iptables_manager.apply()


def ensure_floating_forward(floating_ip, fixed_ip, device):
    """Ensure floating ip forwarding rule."""
    for chain, rule in floating_forward_rules(floating_ip, fixed_ip, device):
        iptables_manager.ipv4['nat'].add_rule(chain, rule)
    iptables_manager.apply()


def remove_floating_forward(floating_ip, fixed_ip, device):
    """Remove forwarding for floating ip."""
    for chain, rule in floating_forward_rules(floating_ip, fixed_ip, device):
        iptables_manager.ipv4['nat'].remove_rule(chain, rule)
    iptables_manager.apply()


def floating_forward_rules(floating_ip, fixed_ip, device):
    if FLAGS.use_private_floating_ip:
        private_range = netaddr.IPNetwork(FLAGS.private_floating_ip_range)
        floating = netaddr.IPAddress(floating_ip)
        if floating in private_range:
            rule = '-s %s -m set --match-set %s dst -j SNAT --to %s' % \
                    (fixed_ip, FLAGS.private_floating_ip_dst_setname,
                            floating_ip)
        else:
            rule = '-s %s -m set ! --match-set %s dst -j SNAT --to %s' % \
                    (fixed_ip, FLAGS.private_floating_ip_dst_setname,
                            floating_ip)
            srule = ('-s %s -d %s -m conntrack --ctstate DNAT --ctorigdst %s '
                     '-j SNAT --to %s' % (fixed_ip, fixed_ip,
                                          floating_ip, floating_ip))
    else:
        rule = '-s %s -j SNAT --to %s' % (fixed_ip, floating_ip)

    res = [('PREROUTING', '-d %s -j DNAT --to %s' % (floating_ip, fixed_ip)),
           ('OUTPUT', '-d %s -j DNAT --to %s' % (floating_ip, fixed_ip)),
           ('float-snat', rule)]

    if 'srule' in locals() and srule != None:
        res.append(('float-snat', srule))

    return res


def del_conntrack_entries(ip):
    """remove conntrack entries with specific ip address"""
    try:
        _execute('conntrack', '-D', '-s', ip,
                 run_as_root=True, check_exit_code=[0, 1])
        _execute('conntrack', '-D', '-d', ip,
                 run_as_root=True, check_exit_code=[0, 1])
        _execute('conntrack', '-D', '-r', ip,
                 run_as_root=True, check_exit_code=[0, 1])
        _execute('conntrack', '-D', '-q', ip,
                 run_as_root=True, check_exit_code=[0, 1])
    except Exception, e:
        LOG.warn(_("Error when deleting contrack entries: %s") % str(e))


def initialize_gateway_device(dev, network_ref):
    if not network_ref:
        return

    _execute('sysctl', '-w', 'net.ipv4.ip_forward=1', run_as_root=True)

    # NOTE(vish): The ip for dnsmasq has to be the first address on the
    #             bridge for it to respond to reqests properly
    full_ip = '%s/%s' % (network_ref['dhcp_server'],
                         network_ref['cidr'].rpartition('/')[2])
    new_ip_params = [[full_ip, 'brd', network_ref['broadcast']]]
    old_ip_params = []
    out, err = _execute('ip', 'addr', 'show', 'dev', dev,
                        'scope', 'global', run_as_root=True)
    for line in out.split('\n'):
        fields = line.split()
        if fields and fields[0] == 'inet':
            ip_params = fields[1:-1]
            old_ip_params.append(ip_params)
            if ip_params[0] != full_ip:
                new_ip_params.append(ip_params)
    if not old_ip_params or old_ip_params[0][0] != full_ip:
        old_routes = []
        result = _execute('ip', 'route', 'show', 'dev', dev,
                          run_as_root=True)
        if result:
            out, err = result
            for line in out.split('\n'):
                fields = line.split()
                if fields and 'via' in fields:
                    old_routes.append(fields)
                    _execute('ip', 'route', 'del', fields[0],
                             'dev', dev, run_as_root=True)
        for ip_params in old_ip_params:
            _execute(*_ip_bridge_cmd('del', ip_params, dev),
                     run_as_root=True, check_exit_code=[0, 2, 254])
        for ip_params in new_ip_params:
            _execute(*_ip_bridge_cmd('add', ip_params, dev),
                     run_as_root=True, check_exit_code=[0, 2, 254])

        for fields in old_routes:
            _execute('ip', 'route', 'add', *fields,
                     run_as_root=True)
        if FLAGS.send_arp_for_ha and FLAGS.send_arp_for_ha_count > 0:
            send_arp_for_ip(network_ref['dhcp_server'], dev,
                            FLAGS.send_arp_for_ha_count)
    if(FLAGS.use_ipv6):
        _execute('ip', '-f', 'inet6', 'addr',
                 'change', network_ref['cidr_v6'],
                 'dev', dev, run_as_root=True)


def get_dhcp_leases(context, network_ref):
    """Return a network's hosts config in dnsmasq leasefile format."""
    hosts = []
    host = None
    if network_ref['multi_host']:
        host = FLAGS.host
    for data in db.network_get_associated_fixed_ips(context,
                                                    network_ref['id'],
                                                    host=host):
        hosts.append(_host_lease(data))
    return '\n'.join(hosts)


def get_dhcp_hosts(context, network_ref):
    """Get network's hosts config in dhcp-host format."""
    hosts = []
    host = None
    if network_ref['multi_host']:
        host = FLAGS.host
    for data in db.network_get_associated_fixed_ips(context,
                                                    network_ref['id'],
                                                    host=host):
        hosts.append(_host_dhcp(data))
    return '\n'.join(hosts)


def _add_dnsmasq_accept_rules(dev):
    """Allow DHCP and DNS traffic through to dnsmasq."""
    table = iptables_manager.ipv4['filter']
    for port in [67, 53]:
        for proto in ['udp', 'tcp']:
            args = {'dev': dev, 'port': port, 'proto': proto}
            table.add_rule('INPUT',
                           '-i %(dev)s -p %(proto)s -m %(proto)s '
                           '--dport %(port)s -j ACCEPT' % args)
    iptables_manager.apply()


def get_dhcp_opts(context, network_ref):
    """Get network's hosts config in dhcp-opts format."""
    hosts = []
    host = None
    if network_ref['multi_host']:
        host = FLAGS.host
    data = db.network_get_associated_fixed_ips(context,
                                               network_ref['id'],
                                               host=host)

    if data:
        instance_set = set([datum['instance_uuid'] for datum in data])
        default_gw_vif = {}
        for instance_uuid in instance_set:
            vifs = db.virtual_interface_get_by_instance(context,
                                                        instance_uuid)
            if vifs:
                #offer a default gateway to the first virtual interface
                default_gw_vif[instance_uuid] = vifs[0]['id']

        for datum in data:
            if instance_uuid in default_gw_vif:
                # we don't want default gateway for this fixed ip
                if default_gw_vif[instance_uuid] != datum['vif_id']:
                    hosts.append(_host_dhcp_opts(datum))
    return '\n'.join(hosts)


def release_dhcp(dev, address, mac_address):
    utils.execute('dhcp_release', dev, address, mac_address, run_as_root=True)


def update_dhcp(context, dev, network_ref, kill_dhcp=False):
    conffile = _dhcp_file(dev, 'conf')
    write_to_file(conffile, get_dhcp_hosts(context, network_ref))
    restart_dhcp(context, dev, network_ref, kill_dhcp)


def update_dhcp_hostfile_with_text(dev, hosts_text):
    conffile = _dhcp_file(dev, 'conf')
    write_to_file(conffile, hosts_text)


def kill_dhcp(dev):
    pid = _dnsmasq_pid_for(dev)
    if pid:
        # Check that the process exists and looks like a dnsmasq process
        conffile = _dhcp_file(dev, 'conf')
        out, _err = _execute('cat', '/proc/%d/cmdline' % pid,
                             check_exit_code=False)
        if conffile.split('/')[-1] in out:
            _execute('kill', '-9', pid, run_as_root=True)
        else:
            LOG.debug(_('Pid %d is stale, skip killing dnsmasq'), pid)


# NOTE(ja): Sending a HUP only reloads the hostfile, so any
#           configuration options (like dchp-range, vlan, ...)
#           aren't reloaded.
@utils.synchronized('dnsmasq_start')
def restart_dhcp(context, dev, network_ref, kill_dhcp=False):
    """(Re)starts a dnsmasq server for a given network.

    If a dnsmasq instance is already running then send a HUP
    signal causing it to reload, otherwise spawn a new instance.

    """
    conffile = _dhcp_file(dev, 'conf')

    if FLAGS.use_single_default_gateway:
        # NOTE(vish): this will have serious performance implications if we
        #             are not in multi_host mode.
        optsfile = _dhcp_file(dev, 'opts')
        write_to_file(optsfile, get_dhcp_opts(context, network_ref))
        os.chmod(optsfile, 0644)

    # Make sure dnsmasq can actually read it (it setuid()s to "nobody")
    os.chmod(conffile, 0644)

    pid = _dnsmasq_pid_for(dev)

    # if dnsmasq is already running, then tell it to reload
    if pid:
        out, _err = _execute('cat', '/proc/%d/cmdline' % pid,
                             check_exit_code=False)
        # Using symlinks can cause problems here so just compare the name
        # of the file itself
        if conffile.split('/')[-1] in out:
            try:
                if kill_dhcp:
                    _execute('kill', '-9', pid, run_as_root=True)
                else:
                    _execute('kill', '-HUP', pid, run_as_root=True)
                    _add_dnsmasq_accept_rules(dev)
                    return
            except Exception as exc:  # pylint: disable=W0703
                LOG.error(_('Hupping/Killing dnsmasq threw %s'), exc)
        else:
            LOG.debug(_('Pid %d is stale, relaunching dnsmasq'), pid)

    cmd = ['FLAGFILE=%s' % FLAGS.dhcpbridge_flagfile,
           'NETWORK_ID=%s' % str(network_ref['id']),
           'dnsmasq',
           '--strict-order',
           '--bind-interfaces',
           '--conf-file=%s' % FLAGS.dnsmasq_config_file,
           '--domain=%s' % FLAGS.dhcp_domain,
           '--pid-file=%s' % _dhcp_file(dev, 'pid'),
           '--listen-address=%s' % network_ref['dhcp_server'],
           '--except-interface=lo',
           '--dhcp-range=set:\'%s\',%s,static,%ss' %
                         (network_ref['label'],
                          network_ref['dhcp_start'],
                          FLAGS.dhcp_lease_time),
           '--dhcp-lease-max=%s' % len(netaddr.IPNetwork(network_ref['cidr'])),
           '--dhcp-hostsfile=%s' % _dhcp_file(dev, 'conf'),
           '--dhcp-script=%s' % FLAGS.dhcpbridge,
           '--leasefile-ro']
    if FLAGS.dns_server:
        cmd += ['-h', '-R', '--server=%s' % FLAGS.dns_server]

    if FLAGS.use_single_default_gateway:
        cmd += ['--dhcp-optsfile=%s' % _dhcp_file(dev, 'opts')]

    _execute(*cmd, run_as_root=True)

    _add_dnsmasq_accept_rules(dev)


@utils.synchronized('radvd_start')
def update_ra(context, dev, network_ref):
    conffile = _ra_file(dev, 'conf')
    conf_str = """
interface %s
{
   AdvSendAdvert on;
   MinRtrAdvInterval 3;
   MaxRtrAdvInterval 10;
   prefix %s
   {
        AdvOnLink on;
        AdvAutonomous on;
   };
};
""" % (dev, network_ref['cidr_v6'])
    write_to_file(conffile, conf_str)

    # Make sure radvd can actually read it (it setuid()s to "nobody")
    os.chmod(conffile, 0644)

    pid = _ra_pid_for(dev)

    # if radvd is already running, then tell it to reload
    if pid:
        out, _err = _execute('cat', '/proc/%d/cmdline'
                             % pid, check_exit_code=False)
        if conffile in out:
            try:
                _execute('kill', pid, run_as_root=True)
            except Exception as exc:  # pylint: disable=W0703
                LOG.error(_('killing radvd threw %s'), exc)
        else:
            LOG.debug(_('Pid %d is stale, relaunching radvd'), pid)

    cmd = ['radvd',
           '-C', '%s' % _ra_file(dev, 'conf'),
           '-p', '%s' % _ra_file(dev, 'pid')]

    _execute(*cmd, run_as_root=True)


def _host_lease(data):
    """Return a host string for an address in leasefile format."""
    if data['instance_updated']:
        timestamp = data['instance_updated']
    else:
        timestamp = data['instance_created']

    seconds_since_epoch = calendar.timegm(timestamp.utctimetuple())

    return '%d %s %s %s *' % (seconds_since_epoch + FLAGS.dhcp_lease_time,
                              data['vif_address'],
                              data['address'],
                              data['instance_hostname'] or '*')


def _host_dhcp_network(data):
    return 'NW-%s' % data['vif_id']


def _host_dhcp(data):
    """Return a host string for an address in dhcp-host format."""
    if FLAGS.use_single_default_gateway:
        return '%s,%s.%s,%s,%s' % (data['vif_address'],
                               data['instance_hostname'],
                               FLAGS.dhcp_domain,
                               data['address'],
                               'net:' + _host_dhcp_network(data))
    else:
        return '%s,%s.%s,%s' % (data['vif_address'],
                               data['instance_hostname'],
                               FLAGS.dhcp_domain,
                               data['address'])


def _host_dhcp_opts(data):
    """Return an empty gateway option."""
    return '%s,%s' % (_host_dhcp_network(data), 3)


def _execute(*cmd, **kwargs):
    """Wrapper around utils._execute for fake_network."""
    if FLAGS.fake_network:
        LOG.debug('FAKE NET: %s', ' '.join(map(str, cmd)))
        return 'fake', 0
    else:
        return utils.execute(*cmd, **kwargs)


def _device_exists(device):
    """Check if ethernet device exists."""
    (_out, err) = _execute('ip', 'link', 'show', 'dev', device,
                           check_exit_code=False, run_as_root=True)
    return not err


def _dhcp_file(dev, kind):
    """Return path to a pid, leases or conf file for a bridge/device."""
    utils.ensure_tree(FLAGS.networks_path)
    return os.path.abspath('%s/nova-%s.%s' % (FLAGS.networks_path,
                                              dev,
                                              kind))


def _ra_file(dev, kind):
    """Return path to a pid or conf file for a bridge/device."""
    utils.ensure_tree(FLAGS.networks_path)
    return os.path.abspath('%s/nova-ra-%s.%s' % (FLAGS.networks_path,
                                              dev,
                                              kind))


def _dnsmasq_pid_for(dev):
    """Returns the pid for prior dnsmasq instance for a bridge/device.

    Returns None if no pid file exists.

    If machine has rebooted pid might be incorrect (caller should check).

    """
    pid_file = _dhcp_file(dev, 'pid')

    if os.path.exists(pid_file):
        try:
            with open(pid_file, 'r') as f:
                return int(f.read())
        except (ValueError, IOError):
            return None


def _ra_pid_for(dev):
    """Returns the pid for prior radvd instance for a bridge/device.

    Returns None if no pid file exists.

    If machine has rebooted pid might be incorrect (caller should check).

    """
    pid_file = _ra_file(dev, 'pid')

    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            return int(f.read())


def _ip_bridge_cmd(action, params, device):
    """Build commands to add/del ips to bridges/devices."""
    cmd = ['ip', 'addr', action]
    cmd.extend(params)
    cmd.extend(['dev', device])
    return cmd


def _create_veth_pair(dev1_name, dev2_name):
    """Create a pair of veth devices with the specified names,
    deleting any previous devices with those names.
    """
    for dev in [dev1_name, dev2_name]:
        if _device_exists(dev):
            try:
                utils.execute('ip', 'link', 'delete', dev1_name,
                              run_as_root=True, check_exit_code=[0, 2, 254])
            except exception.ProcessExecutionError:
                LOG.exception("Error clearing stale veth %s" % dev)

    utils.execute('ip', 'link', 'add', dev1_name, 'type', 'veth', 'peer',
                  'name', dev2_name, run_as_root=True)
    for dev in [dev1_name, dev2_name]:
        utils.execute('ip', 'link', 'set', dev, 'up', run_as_root=True)
        utils.execute('ip', 'link', 'set', dev, 'promisc', 'on',
                      run_as_root=True)


# Similar to compute virt layers, the Linux network node
# code uses a flexible driver model to support different ways
# of creating ethernet interfaces and attaching them to the network.
# In the case of a network host, these interfaces
# act as gateway/dhcp/vpn/etc. endpoints not VM interfaces.
interface_driver = None


def _get_interface_driver():
    global interface_driver
    if not interface_driver:
        interface_driver = importutils.import_object(
                FLAGS.linuxnet_interface_driver)
    return interface_driver


def plug(network, mac_address, gateway=True):
    return _get_interface_driver().plug(network, mac_address, gateway)


def unplug(network):
    return _get_interface_driver().unplug(network)


def get_dev(network):
    return _get_interface_driver().get_dev(network)


class LinuxNetInterfaceDriver(object):
    """Abstract class that defines generic network host API"""
    """ for for all Linux interface drivers."""

    def plug(self, network, mac_address):
        """Create Linux device, return device name"""
        raise NotImplementedError()

    def unplug(self, network):
        """Destory Linux device, return device name"""
        raise NotImplementedError()

    def get_dev(self, network):
        """Get device name"""
        raise NotImplementedError()


# plugs interfaces using Linux Bridge
class LinuxBridgeInterfaceDriver(LinuxNetInterfaceDriver):

    def plug(self, network, mac_address, gateway=True):
        if network.get('vlan', None) is not None:
            iface = FLAGS.vlan_interface or network['bridge_interface']
            LinuxBridgeInterfaceDriver.ensure_vlan_bridge(
                           network['vlan'],
                           network['bridge'],
                           iface,
                           network,
                           mac_address)
        else:
            iface = FLAGS.flat_interface or network['bridge_interface']
            LinuxBridgeInterfaceDriver.ensure_bridge(
                          network['bridge'],
                          iface,
                          network, gateway)

        # NOTE(vish): applying here so we don't get a lock conflict
        iptables_manager.apply()
        return network['bridge']

    def unplug(self, network):
        return self.get_dev(network)

    def get_dev(self, network):
        return network['bridge']

    @classmethod
    def ensure_vlan_bridge(_self, vlan_num, bridge, bridge_interface,
                                            net_attrs=None, mac_address=None):
        """Create a vlan and bridge unless they already exist."""
        interface = LinuxBridgeInterfaceDriver.ensure_vlan(vlan_num,
                                               bridge_interface, mac_address)
        LinuxBridgeInterfaceDriver.ensure_bridge(bridge, interface, net_attrs)
        return interface

    @classmethod
    @utils.synchronized('ensure_vlan', external=True)
    def ensure_vlan(_self, vlan_num, bridge_interface, mac_address=None):
        """Create a vlan unless it already exists."""
        interface = 'vlan%s' % vlan_num
        if not _device_exists(interface):
            LOG.debug(_('Starting VLAN inteface %s'), interface)
            _execute('ip', 'link', 'add', 'link', bridge_interface,
                     'name', interface, 'type', 'vlan',
                     'id', vlan_num, run_as_root=True,
                     check_exit_code=[0, 2, 254])
            # (danwent) the bridge will inherit this address, so we want to
            # make sure it is the value set from the NetworkManager
            if mac_address:
                _execute('ip', 'link', 'set', interface, 'address',
                         mac_address, run_as_root=True,
                         check_exit_code=[0, 2, 254])
            _execute('ip', 'link', 'set', interface, 'up', run_as_root=True,
                     check_exit_code=[0, 2, 254])
            if FLAGS.network_device_mtu:
                _execute('ip', 'link', 'set', interface, 'mtu',
                         FLAGS.network_device_mtu, run_as_root=True,
                         check_exit_code=[0, 2, 254])
        return interface

    @classmethod
    @utils.synchronized('ensure_bridge', external=True)
    def ensure_bridge(_self, bridge, interface, net_attrs=None, gateway=True):
        """Create a bridge unless it already exists.

        :param interface: the interface to create the bridge on.
        :param net_attrs: dictionary with  attributes used to create bridge.

        If net_attrs is set, it will add the net_attrs['gateway'] to the bridge
        using net_attrs['broadcast'] and net_attrs['cidr'].  It will also add
        the ip_v6 address specified in net_attrs['cidr_v6'] if use_ipv6 is set.

        The code will attempt to move any ips that already exist on the
        interface onto the bridge and reset the default gateway if necessary.

        """
        if not _device_exists(bridge):
            LOG.debug(_('Starting Bridge interface for %s'), interface)
            _execute('brctl', 'addbr', bridge, run_as_root=True)
            _execute('brctl', 'setfd', bridge, 0, run_as_root=True)
            # _execute('brctl setageing %s 10' % bridge, run_as_root=True)
            _execute('brctl', 'stp', bridge, 'off', run_as_root=True)
            # (danwent) bridge device MAC address can't be set directly.
            # instead it inherits the MAC address of the first device on the
            # bridge, which will either be the vlan interface, or a
            # physical NIC.
            _execute('ip', 'link', 'set', bridge, 'up', run_as_root=True)

        if interface:
            out, err = _execute('brctl', 'addif', bridge, interface,
                                check_exit_code=False, run_as_root=True)

            # NOTE(vish): This will break if there is already an ip on the
            #             interface, so we move any ips to the bridge
            # NOTE(danms): We also need to copy routes to the bridge so as
            #              not to break existing connectivity on the interface
            old_routes = []
            out, err = _execute('ip', 'route', 'show', 'dev', interface)
            for line in out.split('\n'):
                fields = line.split()
                if fields and 'via' in fields:
                    old_routes.append(fields)
                    _execute('ip', 'route', 'del', *fields,
                             run_as_root=True)
            out, err = _execute('ip', 'addr', 'show', 'dev', interface,
                                'scope', 'global', run_as_root=True)
            for line in out.split('\n'):
                fields = line.split()
                if fields and fields[0] == 'inet':
                    params = fields[1:-1]
                    _execute(*_ip_bridge_cmd('del', params, fields[-1]),
                             run_as_root=True, check_exit_code=[0, 2, 254])
                    _execute(*_ip_bridge_cmd('add', params, bridge),
                             run_as_root=True, check_exit_code=[0, 2, 254])
            for fields in old_routes:
                _execute('ip', 'route', 'add', *fields,
                         run_as_root=True)

            if (err and err != "device %s is already a member of a bridge;"
                     "can't ensubordinate it to bridge %s.\n" % (interface, bridge)):
                msg = _('Failed to add interface: %s') % err
                raise exception.NovaException(msg)

        # Don't forward traffic unless we were told to be a gateway
        ipv4_filter = iptables_manager.ipv4['filter']
        if gateway:
            ipv4_filter.add_rule('FORWARD',
                                 '--in-interface %s -j ACCEPT' % bridge)
            ipv4_filter.add_rule('FORWARD',
                                 '--out-interface %s -j ACCEPT' % bridge)
        else:
            ipv4_filter.add_rule('FORWARD',
                                 '--in-interface %s -j DROP' % bridge)
            ipv4_filter.add_rule('FORWARD',
                                 '--out-interface %s -j DROP' % bridge)


# plugs interfaces using Open vSwitch
class LinuxOVSInterfaceDriver(LinuxNetInterfaceDriver):

    def plug(self, network, mac_address, gateway=True):
        dev = self.get_dev(network)
        if not _device_exists(dev):
            bridge = FLAGS.linuxnet_ovs_integration_bridge
            _execute('ovs-vsctl',
                     '--', '--may-exist', 'add-port', bridge, dev,
                     '--', 'set', 'Interface', dev, 'type=internal',
                     '--', 'set', 'Interface', dev,
                     'external-ids:iface-id=%s' % dev,
                     '--', 'set', 'Interface', dev,
                     'external-ids:iface-status=active',
                     '--', 'set', 'Interface', dev,
                     'external-ids:attached-mac=%s' % mac_address,
                     run_as_root=True)
            _execute('ip', 'link', 'set', dev, 'address', mac_address,
                     run_as_root=True)
            if FLAGS.network_device_mtu:
                _execute('ip', 'link', 'set', dev, 'mtu',
                         FLAGS.network_device_mtu, run_as_root=True)
            _execute('ip', 'link', 'set', dev, 'up', run_as_root=True)
            if not gateway:
                # If we weren't instructed to act as a gateway then add the
                # appropriate flows to block all non-dhcp traffic.
                _execute('ovs-ofctl',
                         'add-flow', bridge, 'priority=1,actions=drop',
                         run_as_root=True)
                _execute('ovs-ofctl', 'add-flow', bridge,
                         'udp,tp_dst=67,dl_dst=%s,priority=2,actions=normal' %
                         mac_address, run_as_root=True)
                # .. and make sure iptbles won't forward it as well.
                iptables_manager.ipv4['filter'].add_rule('FORWARD',
                        '--in-interface %s -j DROP' % bridge)
                iptables_manager.ipv4['filter'].add_rule('FORWARD',
                        '--out-interface %s -j DROP' % bridge)
            else:
                iptables_manager.ipv4['filter'].add_rule('FORWARD',
                        '--in-interface %s -j ACCEPT' % bridge)
                iptables_manager.ipv4['filter'].add_rule('FORWARD',
                        '--out-interface %s -j ACCEPT' % bridge)

        return dev

    def unplug(self, network):
        dev = self.get_dev(network)
        bridge = FLAGS.linuxnet_ovs_integration_bridge
        _execute('ovs-vsctl', '--', '--if-exists', 'del-port',
                 bridge, dev, run_as_root=True)
        return dev

    def get_dev(self, network):
        dev = 'gw-' + str(network['uuid'][0:11])
        return dev


# plugs interfaces using Linux Bridge when using QuantumManager
class QuantumLinuxBridgeInterfaceDriver(LinuxNetInterfaceDriver):

    BRIDGE_NAME_PREFIX = 'brq'
    GATEWAY_INTERFACE_PREFIX = 'gw-'

    def plug(self, network, mac_address, gateway=True):
        dev = self.get_dev(network)
        bridge = self.get_bridge(network)
        if not gateway:
            # If we weren't instructed to act as a gateway then add the
            # appropriate flows to block all non-dhcp traffic.
            # .. and make sure iptbles won't forward it as well.
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--in-interface %s -j DROP' % bridge)
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--out-interface %s -j DROP' % bridge)
            return bridge
        else:
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--in-interface %s -j ACCEPT' % bridge)
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--out-interface %s -j ACCEPT' % bridge)

        QuantumLinuxBridgeInterfaceDriver.create_tap_dev(dev, mac_address)

        if not _device_exists(bridge):
            LOG.debug(_("Starting bridge %s "), bridge)
            utils.execute('brctl', 'addbr', bridge, run_as_root=True)
            utils.execute('brctl', 'setfd', bridge, str(0), run_as_root=True)
            utils.execute('brctl', 'stp', bridge, 'off', run_as_root=True)
            utils.execute('ip', 'link', 'set', bridge, 'address', mac_address,
                          run_as_root=True, check_exit_code=[0, 2, 254])
            utils.execute('ip', 'link', 'set', bridge, 'up', run_as_root=True,
                          check_exit_code=[0, 2, 254])
            LOG.debug(_("Done starting bridge %s"), bridge)

            full_ip = '%s/%s' % (network['dhcp_server'],
                                 network['cidr'].rpartition('/')[2])
            utils.execute('ip', 'address', 'add', full_ip, 'dev', bridge,
                          run_as_root=True, check_exit_code=[0, 2, 254])

        return dev

    def unplug(self, network):
        dev = self.get_dev(network)

        if not _device_exists(dev):
            return None
        else:
            try:
                utils.execute('ip', 'link', 'delete', dev, run_as_root=True,
                              check_exit_code=[0, 2, 254])
            except exception.ProcessExecutionError:
                LOG.error(_("Failed unplugging gateway interface '%s'"), dev)
                raise
            LOG.debug(_("Unplugged gateway interface '%s'"), dev)
            return dev

    @classmethod
    def create_tap_dev(_self, dev, mac_address=None):
        if not _device_exists(dev):
            try:
                # First, try with 'ip'
                utils.execute('ip', 'tuntap', 'add', dev, 'mode', 'tap',
                              run_as_root=True, check_exit_code=[0, 2, 254])
            except exception.ProcessExecutionError:
                # Second option: tunctl
                utils.execute('tunctl', '-b', '-t', dev, run_as_root=True)
            if mac_address:
                utils.execute('ip', 'link', 'set', dev, 'address', mac_address,
                              run_as_root=True, check_exit_code=[0, 2, 254])
            utils.execute('ip', 'link', 'set', dev, 'up', run_as_root=True,
                          check_exit_code=[0, 2, 254])

    def get_dev(self, network):
        dev = self.GATEWAY_INTERFACE_PREFIX + str(network['uuid'][0:11])
        return dev

    def get_bridge(self, network):
        bridge = self.BRIDGE_NAME_PREFIX + str(network['uuid'][0:11])
        return bridge

iptables_manager = IptablesManager()
ipsets_manager = IpsetsManager()
tc_manager = TcManager()
