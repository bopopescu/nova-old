# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

""" Keypair management extension"""

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova.compute import api as compute_api


authorize = extensions.extension_authorizer('compute', 'keypairs:search')


class KeypairsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('keypairs')
        elem = xmlutil.make_flat_dict('keypair', selector='keypairs',
                                      subselector='keypair')
        root.append(elem)

        return xmlutil.MasterTemplate(root, 1)


class KeypairSearchController(object):

    """ Keypair API controller for the OpenStack API """
    def __init__(self):
        self.api = compute_api.KeypairAPI()

    @wsgi.serializers(xml=KeypairsTemplate)
    def index(self, req):
        """
        List of keypairs for a user
        """
        context = req.environ['nova.context']
        authorize(context)

        search_opts = {}
        search_opts.update(req.GET)

        key_pairs = self.api.get_all_key_pairs(context, search_opts)
        rval = []
        for key_pair in key_pairs:
            rval.append({'keypair': {
                'name': key_pair['name'],
                'public_key': key_pair['public_key'],
                'fingerprint': key_pair['fingerprint'],
                'user_id': key_pair['user_id']
            }})

        return {'keypairs': rval}


class Keypairs_search(extensions.ExtensionDescriptor):
    """Keypair Support"""

    name = "KeypairsSearch"
    alias = "os-keypairs-search"
    namespace = "http://docs.openstack.org/compute/ext/keypairs/api/v1.1"
    updated = "2011-08-08T00:00:00+00:00"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension(
                'os-keypairs-search',
                KeypairSearchController())
        resources.append(res)
        return resources
