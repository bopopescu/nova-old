# author: hzwangpan@corp.netease.com
# The extended API for getting host ip by instance uuid,
# the host ip info was saved in the 'service' table of nova DB.

"""The Extended Host Ip Admin API extension."""

from webob import exc

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova import db
from nova.openstack.common import log as logging


LOG = logging.getLogger(__name__)
authorize = extensions.soft_extension_authorizer('compute',
                                                 'extended_host_ip')


class ExtendedHostIpController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ExtendedHostIpController, self).__init__(*args, **kwargs)

    def _extend_server(self, context, server, instance):
        # FIXME(wangpan): the reason of using 'OS-EXT-SRV-ATTR' here is
        #                 compatible with M3 API used by NBS
        key = 'OS-EXT-SRV-ATTR:host_ip'
        server[key] = self._get_instance_host_ip(context, instance)

    @wsgi.extends
    def show(self, req, resp_obj, id):
        context = req.environ['nova.context']
        if authorize(context):
            # Attach our slave template to the response object
            # resp_obj.attach(xml=ExtendedStatusTemplate())
            server = resp_obj.obj['server']
            db_instance = req.get_db_instance(server['id'])
            # server['id'] is guaranteed to be in the cache due to
            # the core API adding it in its 'show' method.
            self._extend_server(context, server, db_instance)

    def _get_instance_host_ip(self, context, instance):
        """Get the host ip of an instance by it's host from the services
        table in DB."""
        if instance['host']:
            service_ref = db.service_get_all_by_host(context,
                                                     instance['host'])
            if service_ref and len(service_ref):
                return service_ref[0]['host_ip']
            LOG.warn(_("Host ip not found because service_ref %s.") % \
                     service_ref, context=context, instance=instance)
            return None
        else:
            LOG.warn(_("Host ip not found because instance host %s.") % \
                     instance['host'], context=context, instance=instance)
            return None


class Extended_host_ip(extensions.ExtensionDescriptor):
    """Extended Host ip which got by instance uuid"""

    name = "ExtendedHostIp"
    alias = "OS-EXT-IP"
    namespace = ("http://docs.openstack.org/compute/ext/os-ext-ip/api/v1.1")
    updated = "2012-11-20T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = ExtendedHostIpController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
