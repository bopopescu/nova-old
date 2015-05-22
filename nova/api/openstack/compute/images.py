# Copyright 2011 OpenStack LLC.
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

import webob.exc

from nova.api.openstack import common
from nova.api.openstack.compute.views import images as views_images
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import db
from nova import exception
from nova import flags
import nova.image.glance
from nova.openstack.common import log as logging
import nova.utils


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS

SUPPORTED_FILTERS = {
    'name': 'name',
    'status': 'status',
    'changes-since': 'changes-since',
    'server': 'property-instance_uuid',
    'type': 'property-image_type',
    'minRam': 'min_ram',
    'minDisk': 'min_disk',
}


def make_image(elem, detailed=False):
    elem.set('name')
    elem.set('id')

    if detailed:
        elem.set('updated')
        elem.set('created')
        elem.set('status')
        elem.set('progress')
        elem.set('minRam')
        elem.set('minDisk')

        server = xmlutil.SubTemplateElement(elem, 'server', selector='server')
        server.set('id')
        xmlutil.make_links(server, 'links')

        elem.append(common.MetadataTemplate())

    xmlutil.make_links(elem, 'links')


image_nsmap = {None: xmlutil.XMLNS_V11, 'atom': xmlutil.XMLNS_ATOM}


class ImageTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('image', selector='image')
        make_image(root, detailed=True)
        return xmlutil.MasterTemplate(root, 1, nsmap=image_nsmap)


class MinimalImagesTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('images')
        elem = xmlutil.SubTemplateElement(root, 'image', selector='images')
        make_image(elem)
        xmlutil.make_links(root, 'images_links')
        return xmlutil.MasterTemplate(root, 1, nsmap=image_nsmap)


class ImagesTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('images')
        elem = xmlutil.SubTemplateElement(root, 'image', selector='images')
        make_image(elem, detailed=True)
        return xmlutil.MasterTemplate(root, 1, nsmap=image_nsmap)


class Controller(wsgi.Controller):
    """Base controller for retrieving/displaying images."""

    _view_builder_class = views_images.ViewBuilder

    def __init__(self, image_service=None, **kwargs):
        """Initialize new `ImageController`.

        :param image_service: `nova.image.glance:GlanceImageService`

        """
        super(Controller, self).__init__(**kwargs)
        self._image_service = (image_service or
                               nova.image.glance.get_default_image_service())

    def _get_filters(self, req):
        """
        Return a dictionary of query param filters from the request

        :param req: the Request object coming from the wsgi layer
        :retval a dict of key/value filters
        """
        filters = {}
        for param in req.params:
            if param in SUPPORTED_FILTERS or param.startswith('property-'):
                # map filter name or carry through if property-*
                filter_name = SUPPORTED_FILTERS.get(param, param)
                filters[filter_name] = req.params.get(param)

        # ensure server filter is the instance uuid
        filter_name = 'property-instance_uuid'
        try:
            filters[filter_name] = filters[filter_name].rsplit('/', 1)[1]
        except (AttributeError, IndexError, KeyError):
            pass

        filter_name = 'status'
        if filter_name in filters:
            # The Image API expects us to use lowercase strings for status
            filters[filter_name] = filters[filter_name].lower()

        return filters

    @wsgi.serializers(xml=ImageTemplate)
    def show(self, req, id):
        """Return detailed information about a specific image.

        :param req: `wsgi.Request` object
        :param id: Image identifier
        """
        context = req.environ['nova.context']

        try:
            image = self._image_service.show(context, id)
        except (exception.NotFound, exception.InvalidImageRef):
            explanation = _("Image not found.")
            raise webob.exc.HTTPNotFound(explanation=explanation)

        return self._view_builder.show(req, image)

    def _image_is_using(self, req, context, id):
        """
        if the image isn't in use or user doesn't need force update,
        the function will return whether need force update
        if the image is in use and user need force update,
        the function will raise HTTPConfict Exception

        :param req: 'wsgi.Request' object
        :param context: nova request context
        :param id: image id

        :raise webob.exc.HTTPForbidden: the image is in use
        """
        def string_to_bool(arg):
            if isinstance(arg, bool):
                return arg
            return arg.strip().lower() in ('t', 'true', 'yes', '1')

        using_check = req.headers.get('x-glance-image-update-using-check',
                                      True)
        using_check = string_to_bool(using_check)
        if using_check:    # whether using by instance
            query = db.instance_get_all_by_image_ref(context, id)
            instances = {'instances': []}
            if query:
                uuids = [instance['uuid'] for instance in query.all()]
                instances['instances'] = uuids
            if instances['instances']:
                raise webob.exc.HTTPForbidden(explanation="%s is using the "
                                                "image %s" % (instances, id))
        return using_check

    def delete(self, req, id):
        """Delete an image, if allowed.

        :param req: `wsgi.Request` object
        :param id: Image identifier (integer)
        :raise HTTPConflict: some instances are using the image
        :raise HTTPNotFound: image not found
        """
        context = req.environ['nova.context']
        using_check = self._image_is_using(req, context, id)
        try:
            headers = {'x-glance-image-update-using-check': using_check}
            self._image_service.delete(context, id, **headers)
        except exception.ImageNotFound:
            explanation = _("Image not found.")
            raise webob.exc.HTTPNotFound(explanation=explanation)
        return webob.exc.HTTPNoContent()

    @wsgi.serializers(xml=MinimalImagesTemplate)
    def index(self, req):
        """Return an index listing of images available to the request.

        :param req: `wsgi.Request` object

        """
        context = req.environ['nova.context']
        filters = self._get_filters(req)
        params = req.GET.copy()
        page_params = common.get_pagination_params(req)
        for key, val in page_params.iteritems():
            params[key] = val

        try:
            images = self._image_service.detail(context, filters=filters,
                                                **page_params)
        except exception.Invalid as e:
            raise webob.exc.HTTPBadRequest(explanation=str(e))
        return self._view_builder.index(req, images)

    @wsgi.serializers(xml=ImagesTemplate)
    def detail(self, req):
        """Return a detailed index listing of images available to the request.

        :param req: `wsgi.Request` object.

        """
        context = req.environ['nova.context']
        filters = self._get_filters(req)
        params = req.GET.copy()
        page_params = common.get_pagination_params(req)
        for key, val in page_params.iteritems():
            params[key] = val
        try:
            images = self._image_service.detail(context, filters=filters,
                                                **page_params)
        except exception.Invalid as e:
            raise webob.exc.HTTPBadRequest(explanation=str(e))

        return self._view_builder.detail(req, images)

    def update(self, req, id):
        """update the image by id with properties in req """
        context = req.environ['nova.context']

        using_check = self._image_is_using(req, context, id)

        image = {}
        try:
            image = self._image_service.show(context, id)
        except exception.NotFound:
            msg = _("Image not found.")
            raise webob.exc.HTTPNotFound(explanation=msg)

        try:
            meta = image["properties"]
        except KeyError:
            expl = _('no properties found for image')
            raise webob.exc.HTTPNotFound(explanation=expl)

        if 'image_type' in meta and meta['image_type'] == 'snapshot':
            raise webob.exc.HTTPForbidden(
                            explanation="Cannot update a snapshot image")

        for key, value in meta.iteritems():
            image['properties'][key] = value

        common.check_img_metadata_properties_quota(context,
                                                   image['properties'])
        self._image_service.update(context, id, image, None,
                features={"x-glance-image-update-using-check": using_check})
        return dict(metadata=image['properties'])

    def create(self, *args, **kwargs):
        raise webob.exc.HTTPMethodNotAllowed()


def create_resource():
    return wsgi.Resource(Controller())
