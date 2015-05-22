#   Copyright 2011 OpenStack, LLC.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

"""The Extended Keypairs API extension."""

from dateutil import tz
import time
import webob

from nosclient import operate_private_key as nos_api
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import db
from nova import exception
from nova import flags
from nova.nos import nos_connection
from nova.openstack.common import log as logging
from nova.openstack.common.notifier import api as notifier_api


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)
authorize = extensions.soft_extension_authorizer('compute',
                                                 'extended_keypairs')


class ExtendedKeypairsController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ExtendedKeypairsController,
              self).__init__(*args, **kwargs)
        if FLAGS.keypairs_connect_nos:
            self.call_nos = None
            self.expires_time = FLAGS.nos_keypairs_expires
            self.bucket_name = FLAGS.nos_keypairs_bucket
            self.use_domain = FLAGS.nos_use_domain

    def _init_nos_api(self, context):
        if not FLAGS.unified_log_dir and context:
            if (context.to_dict().get('unified_log_id')
                and context.to_dict().get('unified_log_seq')):
                context.unified_log_id = None
                context.unified_log_seq = None

        if FLAGS.keypairs_connect_nos:
            self.call_nos = nos_api.OperatePrivateKey(context,
                                                      FLAGS.nos_url,
                                                      FLAGS.nos_host,
                                                      FLAGS.nos_accessKey,
                                                      FLAGS.nos_accessSecret)

    @wsgi.extends
    def create(self, req, resp_obj, body):
        """
        When create action, not import, upload private key to NOS
        and update private_key_url in DB.
        """
        # NOTE(hzyangtk): Catch the create response from keypairs API.
        #                 If is create(not import), upload the generate
        #                 private key to NOS. And store private key url
        #                 of NOS into nova.keypairs table.
        context = req.environ['nova.context']
        authorize(context)

        self._init_nos_api(context)

        keypair = resp_obj.obj['keypair']
        params = body['keypair']

        # NOTE(hzyangtk): when do creating keypairs, fingerprint will
        #                 be add an extra string '.create' to end. This
        #                 action is target to idetify create and import
        is_create = False
        if 'public_key' not in params:
            is_create = True
            create_fingerprint = keypair['fingerprint'] + '.create'
            db.key_pair_update_fingerprint(context, context.user_id,
                                           keypair['name'],
                                           create_fingerprint)

        if is_create and FLAGS.keypairs_connect_nos:
            # NOTE(hzyangtk): This means this is create but not import.
            #                 Then, determine use nos to store
            #                 keypairs or not by FLAGS.keypairs_connect_nos.
            #                 if use nos to store keypairs, it will
            #                 upload private key to nos when create
            #                 return a private key url of nos to NOVA
            #                 and store it into db with private_key_url
            try:
                tmp_data = db.key_pair_get(context, context.user_id,
                                           keypair['name'])
                created_at_local_tz = self._tz_utc_to_local(
                                            tmp_data['created_at'])
                create_timestamp = self._datetime_to_timestamp(
                                        created_at_local_tz)
                expires = long(create_timestamp + self.expires_time)
                if context.user_name is not None:
                    private_key_name = context.user_name + '_' \
                                            + keypair['name'] \
                                            + '.private'
                else:
                    private_key_name = keypair['fingerprint'].replace(':', '')
                private_key_content = keypair['private_key']
                check_bucket = self.call_nos.check_bucket_exist(
                                    self.bucket_name)
                if not check_bucket:
                    self.call_nos.create_bucket(self.bucket_name)
                else:
                    check_object = self.call_nos.check_object_exist(
                                        self.bucket_name,
                                        private_key_name)
                    if check_object:
                        self.call_nos.delete_private_key(self.bucket_name,
                                                         private_key_name)
                private_key_url = self.call_nos.upload_private_key(
                                        self.bucket_name,
                                        private_key_name,
                                        private_key_content,
                                        expires,
                                        self.use_domain)

                keypair['private_key_url'] = private_key_url
            except (webob.exc.HTTPClientError, webob.exc.HTTPRequestTimeout):
                # NOTE(hzyangtk): when NOS connect error occurs, delete the
                #                 generated keypair.
                self._notify_NOS_connection_failure(context, tmp_data)
                try:
                    db.key_pair_destroy(context,
                                        context.user_id,
                                        keypair['name'])
                except exception.KeypairNotFound:
                    # NOTE(hzyangtk): when keypair not found, to do nothing
                    pass
                nos_url = FLAGS.nos_url
                nos_host = FLAGS.nos_host
                nos_accessKey = FLAGS.nos_accessKey
                nos_accessSecret = FLAGS.nos_accessSecret
                LOG.exception(_("Connect to NOS error, "
                                "nos_url: %(nos_url)s, "
                                "nos_host: %(nos_host)s, "
                                "nos_accessKey: %(nos_accessKey)s,"
                                "nos_accessSecret: %(nos_accessSecret)s."),
                              locals())
                err_msg = _("Private key URL generate failed")
                raise webob.exc.HTTPServerError(explanation=err_msg)

    def _notify_NOS_connection_failure(self, context, keypair):
        """
        Send a message to notification about NOS connection failure.
        """
        try:
            LOG.info(_('notify keypairs NOS connection failure'))
            payload = dict(keypair)
            notifier_api.notify(context,
                                notifier_api.publisher_id('api_keypairs'),
                                'api_keypairs.nos_connection_failure',
                                notifier_api.ERROR, payload)
        except Exception:
            LOG.exception(_('notification module error when do notifying '
                            'keypairs connect NOS failed.'))

    @wsgi.extends
    def show(self, req, resp_obj, id):
        """
        Show keypairs, additional add created_at and private_key_url to
        response.
        """
        context = req.environ['nova.context']
        authorize(context)

        self._init_nos_api(context)

        resp_keypair = resp_obj.obj['keypair']
        key_name = resp_keypair['name']
        keypair = db.key_pair_get(context, context.user_id, key_name)
        created_at_local_tz = self._tz_utc_to_local(keypair['created_at'])

        # NOTE(hzyangtk): when fingerprint is end with '.create', remove it
        is_create = keypair['fingerprint'].endswith('.create')
        if is_create:
            keypair['fingerprint'] = keypair['fingerprint'][:-7]

        if FLAGS.keypairs_connect_nos and is_create:
            create_timestamp = self._datetime_to_timestamp(created_at_local_tz)
            if not self._expire_time_check(create_timestamp):
                expires = long(create_timestamp + self.expires_time)
                if context.user_name is not None:
                    private_key_name = context.user_name + '_' \
                                            + keypair['name'] \
                                            + '.private'
                else:
                    private_key_name = \
                                    keypair['fingerprint'].replace(':', '')
                keypair['private_key_url'] = self.call_nos.get_object_url(
                                                            self.bucket_name,
                                                            private_key_name,
                                                            expires,
                                                            self.use_domain)
            resp_keypair['private_key_url'] = keypair.get('private_key_url',
                                                          'expired')
        resp_keypair['created_at'] = self._datetime_to_string(
                                        created_at_local_tz)

    @wsgi.extends
    def index(self, req, resp_obj):
        """
        List all keypairs of this user, additional add created_at and
        private_key_url to response.
        """
        context = req.environ['nova.context']
        authorize(context)

        self._init_nos_api(context)

        keypairs = db.key_pair_get_all_by_user(context, context.user_id)
        rval = []
        for keypair in keypairs:
            # NOTE(hzyangtk): when fingerprint is end with '.create', remove it
            is_create = keypair['fingerprint'].endswith('.create')
            if is_create:
                keypair['fingerprint'] = keypair['fingerprint'][:-7]

            keypair_element = {
                'name': keypair['name'],
                'public_key': keypair['public_key'],
                'fingerprint': keypair['fingerprint']
            }
            created_at_local_tz = self._tz_utc_to_local(keypair['created_at'])
            create_timestamp = self._datetime_to_timestamp(created_at_local_tz)
            if FLAGS.keypairs_connect_nos and is_create:
                if not self._expire_time_check(create_timestamp):
                    expires = long(create_timestamp + self.expires_time)
                    if context.user_name is not None:
                        private_key_name = context.user_name + '_' \
                                                + keypair['name'] \
                                                + '.private'
                    else:
                        private_key_name = \
                                        keypair['fingerprint'].replace(':', '')
                    keypair['private_key_url'] = self.call_nos.get_object_url(
                                                            self.bucket_name,
                                                            private_key_name,
                                                            expires,
                                                            self.use_domain)
                keypair_element['private_key_url'] = keypair.get(
                                                        'private_key_url',
                                                        'expired')
            keypair_element['created_at'] = self._datetime_to_string(
                                                created_at_local_tz)
            rval.append({'keypair': keypair_element})
        resp_obj.obj['keypairs'] = rval

    def _tz_utc_to_local(self, utc):
        """
        Timezone switch, from utc to local
        params:
            utc: datetime
        """
        # NOTE(hzyangtk): Change format of created_at from utc to local.
        from_zone = tz.tzutc()
        to_zone = tz.tzlocal()
        if utc.tzinfo is None:
            utc = utc.replace(tzinfo=from_zone)
        result = utc.astimezone(to_zone)
        return result

    def _datetime_to_timestamp(self, source_time):
        return long(time.mktime(source_time.timetuple()))

    def _datetime_to_string(self, source_time):
        return source_time.strftime('%Y-%m-%d %H:%M:%S')

    def _expire_time_check(self, create_timestamp):
        """
        Expire time check.
        @return:
            expired: True
            not expired: False
        """
        # NOTE(hzyangtk): Return expired while private key url is expired.
        expires = FLAGS.nos_keypairs_expires
        expires_time = create_timestamp + expires
        if expires_time < long(time.time()):
            return True
        return False


class Extended_keypairs(extensions.ExtensionDescriptor):
    """Extended Keypairs support"""

    name = "ExtendedKeypairs"
    alias = "OS-EXT-KP"
    namespace = ("not yet")
    updated = "2012-11-20T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = ExtendedKeypairsController()
        extension = extensions.ControllerExtension(self,
                                                   'os-keypairs',
                                                   controller)
        return [extension]
