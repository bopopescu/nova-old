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

"""The volumes extension."""

import time
import webob
from webob import exc
from xml.dom import minidom

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import compute
from nova.compute import vm_states
from nova import exception
from nova import flags
from nova.openstack.common import log as logging
from nova.openstack.common import timeutils
from nova import utils
from nova import volume
from nova.volume import volume_types


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS
authorize = extensions.extension_authorizer('compute', 'volumes')


def _translate_volume_detail_view(context, vol):
    """Maps keys for volumes details view."""

    d = _translate_volume_summary_view(context, vol)

    # No additional data / lookups at the moment

    return d


def _translate_volume_summary_view(context, vol):
    """Maps keys for volumes summary view."""
    d = {}

    d['id'] = vol['id']
    d['status'] = vol['status']
    d['size'] = vol['size']
    d['availabilityZone'] = vol['availability_zone']
    d['createdAt'] = vol['created_at']

    if vol['attach_status'] == 'attached':
        d['attachments'] = [_translate_attachment_detail_view(vol['id'],
            vol['instance_uuid'],
            vol['mountpoint'])]
    else:
        d['attachments'] = [{}]

    d['displayName'] = vol['display_name']
    d['displayDescription'] = vol['display_description']

    if vol['volume_type_id'] and vol.get('volume_type'):
        d['volumeType'] = vol['volume_type']['name']
    else:
        d['volumeType'] = vol['volume_type_id']

    d['snapshotId'] = vol['snapshot_id']
    LOG.audit(_("vol=%s"), vol, context=context)

    if vol.get('volume_metadata'):
        metadata = vol.get('volume_metadata')
        d['metadata'] = dict((item['key'], item['value']) for item in metadata)
    else:
        d['metadata'] = {}

    return d


def make_volume(elem):
    elem.set('id')
    elem.set('status')
    elem.set('size')
    elem.set('availabilityZone')
    elem.set('createdAt')
    elem.set('displayName')
    elem.set('displayDescription')
    elem.set('volumeType')
    elem.set('snapshotId')

    attachments = xmlutil.SubTemplateElement(elem, 'attachments')
    attachment = xmlutil.SubTemplateElement(attachments, 'attachment',
                                            selector='attachments')
    make_attachment(attachment)

    # Attach metadata node
    elem.append(common.MetadataTemplate())


class VolumeTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('volume', selector='volume')
        make_volume(root)
        return xmlutil.MasterTemplate(root, 1)


class VolumesTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('volumes')
        elem = xmlutil.SubTemplateElement(root, 'volume', selector='volumes')
        make_volume(elem)
        return xmlutil.MasterTemplate(root, 1)


class CommonDeserializer(wsgi.MetadataXMLDeserializer):
    """Common deserializer to handle xml-formatted volume requests.

       Handles standard volume attributes as well as the optional metadata
       attribute
    """

    metadata_deserializer = common.MetadataXMLDeserializer()

    def _extract_volume(self, node):
        """Marshal the volume attribute of a parsed request."""
        volume = {}
        volume_node = self.find_first_child_named(node, 'volume')

        attributes = ['display_name', 'display_description', 'size',
                      'volume_type', 'availability_zone']
        for attr in attributes:
            if volume_node.getAttribute(attr):
                volume[attr] = volume_node.getAttribute(attr)

        metadata_node = self.find_first_child_named(volume_node, 'metadata')
        if metadata_node is not None:
            volume['metadata'] = self.extract_metadata(metadata_node)

        return volume


class CreateDeserializer(CommonDeserializer):
    """Deserializer to handle xml-formatted create volume requests.

       Handles standard volume attributes as well as the optional metadata
       attribute
    """

    def default(self, string):
        """Deserialize an xml-formatted volume create request."""
        dom = minidom.parseString(string)
        volume = self._extract_volume(dom)
        return {'body': {'volume': volume}}


class VolumeController(wsgi.Controller):
    """The Volumes API controller for the OpenStack API."""

    def __init__(self):
        self.compute_api = compute.API()
        self.volume_api = volume.API()
        super(VolumeController, self).__init__()

    @wsgi.serializers(xml=VolumeTemplate)
    def show(self, req, id):
        """Return data about the given volume."""
        context = req.environ['nova.context']
        authorize(context)

        try:
            vol = self.volume_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return {'volume': _translate_volume_detail_view(context, vol)}

    def delete(self, req, id):
        """Delete a volume."""
        context = req.environ['nova.context']
        authorize(context)

        LOG.audit(_("Delete volume with id: %s"), id, context=context)

        try:
            volume = self.volume_api.get(context, id)
            self.volume_api.delete(context, volume)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        return webob.Response(status_int=202)

    @wsgi.serializers(xml=VolumesTemplate)
    def index(self, req):
        """Returns a summary list of volumes."""
        return self._items(req, entity_maker=_translate_volume_summary_view)

    @wsgi.serializers(xml=VolumesTemplate)
    def detail(self, req):
        """Returns a detailed list of volumes."""
        return self._items(req, entity_maker=_translate_volume_detail_view)

    def _items(self, req, entity_maker):
        """Returns a list of volumes, transformed through entity_maker."""
        context = req.environ['nova.context']
        authorize(context)

        volumes = self.volume_api.get_all(context)
        limited_list = common.limited(volumes, req)
        res = [entity_maker(context, vol) for vol in limited_list]
        return {'volumes': res}

    @wsgi.serializers(xml=VolumeTemplate)
    @wsgi.deserializers(xml=CreateDeserializer)
    def create(self, req, body):
        """Creates a new volume."""
        context = req.environ['nova.context']
        authorize(context)

        if not self.is_valid_body(body, 'volume'):
            raise exc.HTTPUnprocessableEntity()

        vol = body['volume']

        vol_type = vol.get('volume_type', None)
        if vol_type:
            try:
                vol_type = volume_types.get_volume_type_by_name(context,
                                                                vol_type)
            except exception.NotFound:
                raise exc.HTTPNotFound()

        metadata = vol.get('metadata', None)

        snapshot_id = vol.get('snapshot_id')

        if snapshot_id is not None:
            snapshot = self.volume_api.get_snapshot(context, snapshot_id)
        else:
            snapshot = None

        size = vol.get('size', None)
        if size is None and snapshot is not None:
            size = snapshot['volume_size']

        LOG.audit(_("Create volume of %s GB"), size, context=context)

        availability_zone = vol.get('availability_zone', None)

        new_volume = self.volume_api.create(context,
                                            size,
                                            vol.get('display_name'),
                                            vol.get('display_description'),
                                            snapshot=snapshot,
                                            volume_type=vol_type,
                                            metadata=metadata,
                                            availability_zone=availability_zone
                                           )

        # TODO(vish): Instance should be None at db layer instead of
        #             trying to lazy load, but for now we turn it into
        #             a dict to avoid an error.
        retval = _translate_volume_detail_view(context, dict(new_volume))
        result = {'volume': retval}

        location = '%s/%s' % (req.url, new_volume['id'])

        return wsgi.ResponseObject(result, headers=dict(location=location))

    def _extend_nbs_volume(self, req, id, body):
        """Extend a exists nbs volume."""
        if FLAGS.nbs_api_server is None:
            explanation = _("Cannot extend nbs volume, nbs server is None.")
            raise exc.HTTPServerError(explanation=explanation)
        context = req.environ['nova.context']
        authorize(context)

        if 'size' not in body or not isinstance(body['size'], int):
            explanation = _("Invalid paramater in body.")
            raise exc.HTTPUnprocessableEntity(explanation=explanation)

        LOG.audit(_("Extend nbs volume %s") % id, context=context)

        size = body['size']    # in GB
        try:
            can_extend = self.compute_api.check_nbs_size(context, id, size)
            if not can_extend:
                explanation = _("Cannot extend volume, invalid size is given.")
                raise exc.HTTPForbidden(explanation=explanation)
        except exception.VolumeNotFound:
            explanation = _("Volume not found.")
            raise exc.HTTPNotFound(explanation=explanation)
        except exception.NbsException:
            explanation = _("Nbs volume server error.")
            raise exc.HTTPServerError(explanation=explanation)

        try:
            instance_uuid = self.compute_api.check_nbs_attached(context, id)
        except exception.NotFound:
            explanation = _("Volume not found.")
            raise exc.HTTPNotFound(explanation=explanation)
        except exception.Invalid:
            LOG.info(_("Volume %s is not attached.") % id)
            instance_uuid = None

        if instance_uuid is not None:
            try:
                # check instance exists
                instance = self.compute_api.get(context, instance_uuid)
                # Check os status if instance is 'ACTIVE'
                if instance['vm_state'] == vm_states.ACTIVE:
                    server_heartbeat_period = FLAGS.get(
                                                'server_heartbeat_period', 10)
                    os_status = self.compute_api.instance_os_boot_ready(
                                                    context,
                                                    instance['uuid'],
                                                    server_heartbeat_period)
                    if os_status['status'] != "up":
                        explanation = _("Cannot extend volume while instance "
                                        "os is starting.")
                        raise exc.HTTPForbidden(explanation=explanation)
            except exception.MemCacheClientNotFound:
                explanation = _("Memory cache client is not found.")
                raise exc.HTTPServerError(explanation=explanation)
            except exception.NotFound:
                explanation = _("Instance %s not found.") % instance_uuid
                raise exc.HTTPNotFound(explanation=explanation)

            # notify instance about this extension
            self.compute_api.extend_nbs_volume(context, id, size, instance)
        else:
            # call nbs to extend this volume directly
            self.compute_api.extend_nbs_volume(context, id, size)

        return {'requestId': context.request_id, 'size': size}

    # @wsgi.serializers(xml=VolumesTemplate)
    def update(self, req, id, body):
        """Extend a exists volume."""
        if FLAGS.ebs_backend == 'nbs':
            return self._extend_nbs_volume(req, id, body)
        else:
            raise exc.HTTPBadRequest()


def _translate_attachment_detail_view(volume_id, instance_uuid, mountpoint):
    """Maps keys for attachment details view."""

    d = _translate_attachment_summary_view(volume_id,
            instance_uuid,
            mountpoint)

    # No additional data / lookups at the moment
    return d


def _translate_attachment_summary_view(volume_id, instance_uuid, mountpoint):
    """Maps keys for attachment summary view."""
    d = {}

    # NOTE(justinsb): We use the volume id as the id of the attachment object
    d['id'] = volume_id

    d['volumeId'] = volume_id

    d['serverId'] = instance_uuid
    if mountpoint:
        d['device'] = mountpoint

    return d


def make_attachment(elem):
    elem.set('id')
    elem.set('serverId')
    elem.set('volumeId')
    elem.set('device')


class VolumeAttachmentTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('volumeAttachment',
                                       selector='volumeAttachment')
        make_attachment(root)
        return xmlutil.MasterTemplate(root, 1)


class VolumeAttachmentsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('volumeAttachments')
        elem = xmlutil.SubTemplateElement(root, 'volumeAttachment',
                                          selector='volumeAttachments')
        make_attachment(elem)
        return xmlutil.MasterTemplate(root, 1)


class VolumeAttachmentController(wsgi.Controller):
    """The volume attachment API controller for the OpenStack API.

    A child resource of the server.  Note that we use the volume id
    as the ID of the attachment (though this is not guaranteed externally)

    """

    def __init__(self):
        self.compute_api = compute.API()
        super(VolumeAttachmentController, self).__init__()

    @wsgi.serializers(xml=VolumeAttachmentsTemplate)
    def index(self, req, server_id):
        """Returns the list of volume attachments for a given instance."""
        return self._items(req, server_id,
                           entity_maker=_translate_attachment_summary_view)

    @wsgi.serializers(xml=VolumeAttachmentTemplate)
    def show(self, req, server_id, id):
        """Return data about the given volume attachment."""
        context = req.environ['nova.context']
        authorize(context)

        volume_id = id
        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        bdms = self.compute_api.get_instance_bdms(context, instance)

        if not bdms:
            LOG.debug(_("Instance %s is not attached."), server_id)
            raise exc.HTTPNotFound()

        assigned_mountpoint = None

        for bdm in bdms:
            if bdm['volume_id'] == volume_id:
                assigned_mountpoint = bdm['device_name']
                break

        if assigned_mountpoint is None:
            LOG.debug("volume_id not found")
            raise exc.HTTPNotFound()

        return {'volumeAttachment': _translate_attachment_detail_view(
            volume_id,
            instance['uuid'],
            assigned_mountpoint)}

    def _attach_nbs_volume(self, req, server_id, body):
        """Attach a nbs volume to an instance."""
        if FLAGS.nbs_api_server is None:
            explanation = _("Cannot attach nbs volume, nbs server is None.")
            raise exc.HTTPServerError(explanation=explanation)
        context = req.environ['nova.context']
        authorize(context)

        if not self.is_valid_body(body, 'volumeAttachment'):
            explanation = _("Invalid paramater in body.")
            raise exc.HTTPUnprocessableEntity(explanation=explanation)

        volume_id = body['volumeAttachment'].get('volumeId')
        if not volume_id:
            explanation = _("Invalid paramater in body.")
            raise exc.HTTPUnprocessableEntity(explanation=explanation)

        LOG.audit(_("Attach nbs volume %(volume)s to instance %(server)s")
                % {"volume": volume_id, "server": server_id}, context=context)

        try:
            instance = self.compute_api.get(context, server_id)
            # Check os status if instance is 'ACTIVE'
            if instance['vm_state'] == vm_states.ACTIVE:
                os_status = self.compute_api.instance_os_boot_ready(context,
                                                instance['uuid'],
                                                FLAGS.server_heartbeat_period)
                if os_status['status'] != "up":
                    explanation = _("Cannot attach volume while instance os "
                                    "is starting.")
                    raise exc.HTTPForbidden(explanation=explanation)
            device = self.compute_api.attach_nbs_volume(context, instance,
                                                        volume_id)
        except exception.MemCacheClientNotFound:
            explanation = _("Memory cache client is not found.")
            raise exc.HTTPServerError(explanation=explanation)
        except exception.VolumeNotFound:
            explanation = _("Volume not found.")
            raise exc.HTTPNotFound(explanation=explanation)
        except exception.NotFound:
            explanation = _("Instance %s not found.") % server_id
            raise exc.HTTPNotFound(explanation=explanation)
        except exception.NoFreeDevice:
            explanation = _("No free device to attach volume.")
            raise exc.HTTPUnprocessableEntity(explanation=explanation)
        except exception.Invalid:
            explanation = _("Volume is not available.")
            raise exc.HTTPForbidden(explanation=explanation)
        except exception.NbsAttachForbidden:
            explanation = _("Instance %s is forbidden to attach "
                            "volume.") % server_id
            raise exc.HTTPForbidden(explanation=explanation)

        # The attach is async
        attachment = {}
        attachment['instanceId'] = instance['uuid']
        attachment['volumeId'] = volume_id
        attachment['device'] = device
        attachment['status'] = "attaching"
        attachment['attachTime'] = long(time.time())

        # NOTE(justinsb): And now, we have a problem...
        # The attach is async, so there's a window in which we don't see
        # the attachment (until the attachment completes).  We could also
        # get problems with concurrent requests.  I think we need an
        # attachment state, and to write to the DB here, but that's a bigger
        # change.
        # For now, we'll probably have to rely on libraries being smart

        # TODO(justinsb): How do I return "accepted" here?
        return {'attachment': attachment, 'requestId': context.request_id}

    @wsgi.serializers(xml=VolumeAttachmentTemplate)
    def create(self, req, server_id, body):
        """Attach a volume to an instance."""
        # Go to our owned process if we are attaching a nbs volume
        if FLAGS.ebs_backend == 'nbs':
            return self._attach_nbs_volume(req, server_id, body)

        context = req.environ['nova.context']
        authorize(context)

        if not self.is_valid_body(body, 'volumeAttachment'):
            raise exc.HTTPUnprocessableEntity()

        volume_id = body['volumeAttachment']['volumeId']
        device = body['volumeAttachment'].get('device')

        msg = _("Attach volume %(volume_id)s to instance %(server_id)s"
                " at %(device)s") % locals()
        LOG.audit(msg, context=context)

        try:
            instance = self.compute_api.get(context, server_id)
            device = self.compute_api.attach_volume(context, instance,
                                                    volume_id, device)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        # The attach is async
        attachment = {}
        attachment['id'] = volume_id
        attachment['serverId'] = server_id
        attachment['volumeId'] = volume_id
        attachment['device'] = device

        # NOTE(justinsb): And now, we have a problem...
        # The attach is async, so there's a window in which we don't see
        # the attachment (until the attachment completes).  We could also
        # get problems with concurrent requests.  I think we need an
        # attachment state, and to write to the DB here, but that's a bigger
        # change.
        # For now, we'll probably have to rely on libraries being smart

        # TODO(justinsb): How do I return "accepted" here?
        return {'volumeAttachment': attachment}

    def _update_nbs_qos(self, req, server_id, id, body):
        """Update QoS parameters of nbs volume."""
        if FLAGS.nbs_api_server is None:
            explanation = _("Cannot update nbs qos info, nbs server is None.")
            raise exc.HTTPServerError(explanation=explanation)
        context = req.environ['nova.context']
        authorize(context)

        vol_project = None
        if context.is_admin:
            vol_project = req.headers.get('X-Vol-Project')
            if not vol_project:
                explanation = _("Project ID of volume is invalid.")
                raise exc.HTTPUnprocessableEntity(explanation=explanation)

        iotune_total_bytes = body.get('maxBandWidth')
        iotune_total_iops = body.get('maxIOPS')
        iotune_read_bytes = body.get('maxReadBandWidth')
        iotune_write_bytes = body.get('maxWriteBandWidth')
        iotune_read_iops = body.get('maxReadIOPS')
        iotune_write_iops = body.get('maxWriteIOPS')

        qos_info = {}
        if (iotune_read_bytes is not None or
                iotune_write_bytes is not None or
                iotune_read_iops is not None or
                iotune_write_iops is not None):
            if iotune_read_bytes is not None:
                qos_info['iotune_read_bytes'] = iotune_read_bytes
            if iotune_write_bytes is not None:
                qos_info['iotune_write_bytes'] = iotune_write_bytes
            if iotune_read_iops is not None:
                qos_info['iotune_read_iops'] = iotune_read_iops
            if iotune_write_iops is not None:
                qos_info['iotune_write_iops'] = iotune_write_iops
        elif (iotune_total_bytes is not None or
                iotune_total_iops is not None):
            if iotune_total_bytes is not None:
                qos_info['iotune_total_bytes'] = iotune_total_bytes
            if iotune_total_iops is not None:
                qos_info['iotune_total_iops'] = iotune_total_iops
        else:
            explanation = _("Invalid paramater in body.")
            raise exc.HTTPUnprocessableEntity(explanation=explanation)

        for value in qos_info.values():
            if not isinstance(value, int):
                explanation = _("Invalid paramater in body.")
                raise exc.HTTPUnprocessableEntity(explanation=explanation)

        volume_id = id
        LOG.audit(_("Update qos info of nbs volume %(volume)s on instance "
                    "%(server)s to %(qos_info)s") % {"volume": volume_id,
                                                     "server": server_id,
                                                     "qos_info": qos_info},
                    context=context)

        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            explanation = _("Instance %s not found.") % server_id
            raise exc.HTTPNotFound(explanation=explanation)

        # FIXME(wangpan): this API is used by nbs admin user, so the context
        #                 is belong to nova admin user for updating qos info
        #                 of all instances, but while calling the nbs API,
        #                 the real project id of volume is needed, so change
        #                 it here manually.
        if context.is_admin and vol_project:
            context.project_id = vol_project

        try:
            self.compute_api.check_nbs_attached(context, volume_id,
                                                instance['uuid'])
        except exception.NotFound:
            explanation = _("Volume not found.")
            raise exc.HTTPNotFound(explanation=explanation)
        except exception.Invalid:
            explanation = _("Volume is not attached.")
            raise exc.HTTPNotFound(explanation=explanation)
        else:
            self.compute_api.update_nbs_qos(context, instance, volume_id,
                                            qos_info)

        return {'requestId': context.request_id, 'return': True}

    def update(self, req, server_id, id, body):
        """
        Update a volume attachment.
        We currently only support updating QoS parameters of nbs volume.
        """
        if FLAGS.ebs_backend == 'nbs':
            return self._update_nbs_qos(req, server_id, id, body)
        else:
            raise exc.HTTPBadRequest()

    def _detach_nbs_volume(self, req, server_id, id):
        """Detach a nbs volume from an instance."""
        if FLAGS.nbs_api_server is None:
            explanation = _("Cannot detach nbs volume, nbs server is None.")
            raise exc.HTTPServerError(explanation=explanation)
        context = req.environ['nova.context']
        authorize(context)

        volume_id = id
        LOG.audit(_("Detach nbs volume %(volume)s from instance %(server)s")
                % {"volume": volume_id, "server": server_id}, context=context)

        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            explanation = _("Instance %s not found.") % server_id
            raise exc.HTTPNotFound(explanation=explanation)

        try:
            self.compute_api.detach_nbs_volume(context,
                    instance, volume_id)
        except exception.VolumeNotFound:
            explanation = _("Volume not found.")
            raise exc.HTTPNotFound(explanation=explanation)
        except exception.Invalid:
            explanation = _("Volume is not attached.")
            raise exc.HTTPNotFound(explanation=explanation)
        else:
            return {'requestId': context.request_id, 'return': True}

    def delete(self, req, server_id, id):
        """Detach a volume from an instance."""
        # Go to our owned process if we are attaching a nbs volume
        if FLAGS.ebs_backend == 'nbs':
            return self._detach_nbs_volume(req, server_id, id)

        context = req.environ['nova.context']
        authorize(context)

        volume_id = id
        LOG.audit(_("Detach volume %s"), volume_id, context=context)

        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        bdms = self.compute_api.get_instance_bdms(context, instance)

        if not bdms:
            LOG.debug(_("Instance %s is not attached."), server_id)
            raise exc.HTTPNotFound()

        found = False
        for bdm in bdms:
            if bdm['volume_id'] == volume_id:
                self.compute_api.detach_volume(context,
                    volume_id=volume_id)
                found = True
                break

        if not found:
            raise exc.HTTPNotFound()
        else:
            return webob.Response(status_int=202)

    def _items(self, req, server_id, entity_maker):
        """Returns a list of attachments, transformed through entity_maker."""
        context = req.environ['nova.context']
        authorize(context)

        try:
            instance = self.compute_api.get(context, server_id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        bdms = self.compute_api.get_instance_bdms(context, instance)
        limited_list = common.limited(bdms, req)
        results = []

        for bdm in limited_list:
            if bdm['volume_id']:
                results.append(entity_maker(bdm['volume_id'],
                        bdm['instance_uuid'],
                        bdm['device_name']))

        return {'volumeAttachments': results}


def _translate_snapshot_detail_view(context, vol):
    """Maps keys for snapshots details view."""

    d = _translate_snapshot_summary_view(context, vol)

    # NOTE(gagupta): No additional data / lookups at the moment
    return d


def _translate_snapshot_summary_view(context, vol):
    """Maps keys for snapshots summary view."""
    d = {}

    d['id'] = vol['id']
    d['volumeId'] = vol['volume_id']
    d['status'] = vol['status']
    # NOTE(gagupta): We map volume_size as the snapshot size
    d['size'] = vol['volume_size']
    d['createdAt'] = vol['created_at']
    d['displayName'] = vol['display_name']
    d['displayDescription'] = vol['display_description']
    return d


def make_snapshot(elem):
    elem.set('id')
    elem.set('status')
    elem.set('size')
    elem.set('createdAt')
    elem.set('displayName')
    elem.set('displayDescription')
    elem.set('volumeId')


class SnapshotTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('snapshot', selector='snapshot')
        make_snapshot(root)
        return xmlutil.MasterTemplate(root, 1)


class SnapshotsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('snapshots')
        elem = xmlutil.SubTemplateElement(root, 'snapshot',
                                          selector='snapshots')
        make_snapshot(elem)
        return xmlutil.MasterTemplate(root, 1)


class SnapshotController(wsgi.Controller):
    """The Volumes API controller for the OpenStack API."""

    def __init__(self):
        self.volume_api = volume.API()
        super(SnapshotController, self).__init__()

    @wsgi.serializers(xml=SnapshotTemplate)
    def show(self, req, id):
        """Return data about the given snapshot."""
        context = req.environ['nova.context']
        authorize(context)

        try:
            vol = self.volume_api.get_snapshot(context, id)
        except exception.NotFound:
            return exc.HTTPNotFound()

        return {'snapshot': _translate_snapshot_detail_view(context, vol)}

    def delete(self, req, id):
        """Delete a snapshot."""
        context = req.environ['nova.context']
        authorize(context)

        LOG.audit(_("Delete snapshot with id: %s"), id, context=context)

        try:
            snapshot = self.volume_api.get_snapshot(context, id)
            self.volume_api.delete_snapshot(context, snapshot)
        except exception.NotFound:
            return exc.HTTPNotFound()
        return webob.Response(status_int=202)

    @wsgi.serializers(xml=SnapshotsTemplate)
    def index(self, req):
        """Returns a summary list of snapshots."""
        return self._items(req, entity_maker=_translate_snapshot_summary_view)

    @wsgi.serializers(xml=SnapshotsTemplate)
    def detail(self, req):
        """Returns a detailed list of snapshots."""
        return self._items(req, entity_maker=_translate_snapshot_detail_view)

    def _items(self, req, entity_maker):
        """Returns a list of snapshots, transformed through entity_maker."""
        context = req.environ['nova.context']
        authorize(context)

        snapshots = self.volume_api.get_all_snapshots(context)
        limited_list = common.limited(snapshots, req)
        res = [entity_maker(context, snapshot) for snapshot in limited_list]
        return {'snapshots': res}

    @wsgi.serializers(xml=SnapshotTemplate)
    def create(self, req, body):
        """Creates a new snapshot."""
        context = req.environ['nova.context']
        authorize(context)

        if not self.is_valid_body(body, 'snapshot'):
            raise exc.HTTPUnprocessableEntity()

        snapshot = body['snapshot']
        volume_id = snapshot['volume_id']
        volume = self.volume_api.get(context, volume_id)

        force = snapshot.get('force', False)
        LOG.audit(_("Create snapshot from volume %s"), volume_id,
                context=context)

        if not utils.is_valid_boolstr(force):
            msg = _("Invalid value '%s' for force. ") % force
            raise exception.InvalidParameterValue(err=msg)

        if utils.bool_from_str(force):
            new_snapshot = self.volume_api.create_snapshot_force(context,
                                        volume,
                                        snapshot.get('display_name'),
                                        snapshot.get('display_description'))
        else:
            new_snapshot = self.volume_api.create_snapshot(context,
                                        volume,
                                        snapshot.get('display_name'),
                                        snapshot.get('display_description'))

        retval = _translate_snapshot_detail_view(context, new_snapshot)

        return {'snapshot': retval}


class Volumes(extensions.ExtensionDescriptor):
    """Volumes support"""

    name = "Volumes"
    alias = "os-volumes"
    namespace = "http://docs.openstack.org/compute/ext/volumes/api/v1.1"
    updated = "2011-03-25T00:00:00+00:00"

    def get_resources(self):
        resources = []

        # NOTE(justinsb): No way to provide singular name ('volume')
        # Does this matter?
        res = extensions.ResourceExtension('os-volumes',
                                        VolumeController(),
                                        collection_actions={'detail': 'GET'})
        resources.append(res)

        res = extensions.ResourceExtension('os-volume_attachments',
                                           VolumeAttachmentController(),
                                           parent=dict(
                                                member_name='server',
                                                collection_name='servers'))
        resources.append(res)

        res = extensions.ResourceExtension('os-volumes_boot',
                                           inherits='servers')
        resources.append(res)

        res = extensions.ResourceExtension('os-snapshots',
                                        SnapshotController(),
                                        collection_actions={'detail': 'GET'})
        resources.append(res)

        return resources
