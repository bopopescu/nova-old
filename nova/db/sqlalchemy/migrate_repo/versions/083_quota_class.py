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
#    under the License.

from sqlalchemy import Boolean, Column, DateTime, ForeignKey
from sqlalchemy import MetaData, Integer, String, Table, Text

from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # New table
    quota_classes = Table('quota_classes', meta,
            Column('created_at', DateTime(timezone=False)),
            Column('updated_at', DateTime(timezone=False)),
            Column('deleted_at', DateTime(timezone=False)),
            Column('deleted', Boolean(create_constraint=True, name=None)),
            Column('id', Integer(), primary_key=True),
            Column('class_name',
                   String(length=255, convert_unicode=True,
                          assert_unicode=None, unicode_error=None,
                          _warn_on_bytestring=False), index=True),
            Column('resource',
                   String(length=255, convert_unicode=True,
                          assert_unicode=None, unicode_error=None,
                          _warn_on_bytestring=False)),
            Column('hard_limit', Integer(), nullable=True),
            )

    try:
        quota_classes.create()
    except Exception:
        LOG.error(_("Table |%s| not created!"), repr(quota_classes))
        raise

    # add column host_ip:
    services = Table('services', meta)
    host_ip = Column('host_ip', String(length=255))
    try:
        services.create_column(host_ip)
    except Exception:
        LOG.error(_("Column |host_ip| not created!"))

    # NOTE(hzyangtk): Here add for new table instance_system_metadata_extension
    # load tables for fk
    instances = Table('instances', meta, autoload=True)

    instance_system_metadata_extension = Table(
            'instance_system_metadata_extension', meta,
            Column('created_at', DateTime(timezone=False)),
            Column('updated_at', DateTime(timezone=False)),
            Column('deleted_at', DateTime(timezone=False)),
            Column('deleted', Boolean(create_constraint=True, name=None)),
            Column('id', Integer(), primary_key=True, nullable=False),
            Column('instance_uuid', String(36), nullable=False),
            Column('key',
                   String(length=255, convert_unicode=True,
                          assert_unicode=None,
                          unicode_error=None, _warn_on_bytestring=False),
                   nullable=False),
            Column('value', Text, nullable=False),
            mysql_engine='InnoDB')

    try:
        instance_system_metadata_extension.create()
    except Exception:
        LOG.error(_("Table |%s| not created!"),
                  repr(instance_system_metadata_extension))
        raise

    # add colomns for Table compute_nodes
    compute_nodes = Table('compute_nodes', meta, autoload=True)
    private_network_mbps_used = Column('private_network_mbps_used', Integer)
    public_network_mbps_used = Column('public_network_mbps_used', Integer)
    total_private_network_mbps = Column('total_private_network_mbps', Integer)
    total_public_network_mbps = Column('total_public_network_mbps', Integer)

    compute_nodes.create_column(private_network_mbps_used)
    compute_nodes.create_column(public_network_mbps_used)
    compute_nodes.create_column(total_private_network_mbps)
    compute_nodes.create_column(total_public_network_mbps)
    compute_nodes.update().values(private_network_mbps_used=0).execute()
    compute_nodes.update().values(public_network_mbps_used=0).execute()
    compute_nodes.update().values(total_private_network_mbps=0).execute()
    compute_nodes.update().values(total_public_network_mbps=0).execute()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    quota_classes = Table('quota_classes', meta, autoload=True)
    try:
        quota_classes.drop()
    except Exception:
        LOG.error(_("quota_classes table not dropped"))
        raise

    # drop column host_ip:
    services = Table('services', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('host', String(length=255)),
        Column('host_ip', String(length=255)),
        Column('binary', String(length=255)),
        Column('topic', String(length=255)),
        Column('report_count', Integer, nullable=False),
        Column('disabled', Boolean),
        Column('availability_zone', String(length=255)),
        mysql_engine='InnoDB',
        #mysql_charset='utf8'
    )
    try:
        services.drop_column('host_ip')
    except Exception:
        LOG.error(_("Column |host_ip| not dropped!"))

    # load tables for fk
    instances = Table('instances', meta, autoload=True)

    instance_system_metadata_extension = Table(
            'instance_system_metadata_extension', meta, autoload=True)
    try:
        instance_system_metadata_extension.drop()
    except Exception:
        LOG.error(_("instance_system_metadata_extension table not dropped"))
        raise

    # drop columns from Table compute_nodes
    compute_nodes = Table('compute_nodes', meta, autoload=True)
    private_network_mbps_used = Column('private_network_mbps_used', Integer)
    public_network_mbps_used = Column('public_network_mbps_used', Integer)
    total_private_network_mbps = Column('total_private_network_mbps', Integer)
    total_public_network_mbps = Column('total_public_network_mbps', Integer)

    compute_nodes.drop_column('private_network_mbps_used')
    compute_nodes.drop_column('public_network_mbps_used')
    compute_nodes.drop_column('total_private_network_mbps')
    compute_nodes.drop_column('total_public_network_mbps')
