#author: hzguanqiang@corp.netease.com
#

"""
Monitor nova services and HA instances,
notify HA when finding nova service or HA instance abnormal
"""

import datetime
import memcache
import time

from nova import context
from nova import db
from nova import exception
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova.openstack.common.notifier import api as notifier
from nova.openstack.common import rpc
from nova.openstack.common.rpc import dispatcher as rpc_dispatcher
from nova.openstack.common import timeutils
from nova import utils


LOG = logging.getLogger(__name__)

monitor_opts = [
    cfg.ListOpt('check_services',
               default=['nova-compute', 'nova-network'],
               help='nova services to be monitored'),
    cfg.IntOpt('service_failure_time',
               default=15,
               help='seconds to judge service is failure or not'),
    cfg.IntOpt('instance_failure_time',
               default=15,
               help='seconds to judge instance is failure or not'),
    cfg.IntOpt('service_recover_time',
               default=300,
               help='seconds for service to recover'),
    cfg.IntOpt('instance_recover_time',
               default=180,
               help='seconds to for instance to recover'),
    cfg.IntOpt('monitor_interval',
               default=15,
               help='seconds between monitor to check service and instances,'
                    'it must be greater than hearbeat interval'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(monitor_opts)


class MonitorManager(object):
    """ Monitor nova services """

    def __init__(self, host=None, topic=None, service_failure_time=None,
                 instance_failure_time=None, check_services=None):
        self.host = host
        self.topic = topic
        self.service_failure_time = (FLAGS.service_failure_time or
                                     service_failure_time)
        self.instance_failure_time = (FLAGS.instance_failure_time or
                                      instance_failure_time)
        self.check_services = FLAGS.check_services or check_services
        self.services_failure_info = []
        self.instances_failure_info = []
        self.service_recover_time = FLAGS.service_recover_time
        self.instance_recover_time = FLAGS.instance_recover_time
        self.state_cache = memcache.Client(FLAGS.memcached_servers)

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        """
        return rpc_dispatcher.RpcDispatcher([self])

    def init_host(self):
        periodic = utils.LoopingCall(self.monitor)
        periodic.start(interval=FLAGS.monitor_interval, initial_delay=0)
        periodic.wait()

    def is_time_valid(self, base, current, interval):
        """
        judge time 'current' is whether at the 'interval' since time 'base'

        :param base: datetime
        :param current: datetime
        :param interval: seconds

        :returns: False if current > base + interval, True otherwise
        """
        base = long(time.mktime(base.timetuple()))
        current = long(time.mktime(current.timetuple()))
        if current - base > interval:
            return False
        else:
            return True

    def _get_abnormal_service_by_topic(self, ctxt, topic):
        """
        get service info from db, judging service's status by
        the latest updated time.

        :param service_name: service name

        :returns: None if service is normal,
                  True if can not get service info from db,
                  service info if service is judged abnormal
        """
        try:
            abnormal_services = []
            services = db.service_get_all_by_topic(ctxt, topic)
            now = timeutils.utcnow()
            for service_ref in services:
                service_updated_time = service_ref['updated_at']
                service_failure_time = self.service_failure_time
                host = service_ref['host']
                if not self.is_time_valid(service_updated_time, now,
                                          service_failure_time):
                    LOG.info(_('check service nova-%(topic)s on %(host)s'
                               ' abnormal!'), locals())
                    LOG.debug(_('service nova-%(topic)s updated at '
                                '%(service_updated_time)s, now is %(now)s, '
                                'service_failure_time was set to '
                                '%(service_failure_time)s'), locals())
                    abnormal_services.append(service_ref)
            return abnormal_services
        except exception.NotFound:
            LOG.info(_('can not find service %s in db') % topic)
            return True

    def _confirm_service_failure(self, ctxt, service):
        """
        confirm wether service is failure by send a rpc call to the service

        :param  service: service info got from db

        :returns: False if service is ok, True if confirm service failed
        """
        host = service['host']
        service_topic = service['topic']
        service_binary = service['binary']
        try:
            topic = FLAGS.get('%s_topic' % service_topic, None)
            rpc_topic = rpc.queue_get_for(ctxt, topic, host)
            msg = {'method': 'service_version'}
            if service_topic == 'compute':
                msg['version'] = '2.0'
            service_version = rpc.call(ctxt, rpc_topic, msg)
            LOG.info(_('confirm service %(service_binary)s on %(host)s normal,'
                       ' version : %(service_version)s!'), locals())
            return False
        except Exception as ex:
            LOG.info(_('confirm service %(service_binary)s on %(host)s '
                       'abnormal!'), locals())
            return True

    def _notify_ha_service_failure(self, ctxt, service_name, service=None):
        """
        notify ha module that some nova service is failure.

        :param service_name: service name
        :param service: service info got from db.
        """
        try:
            if service is not None:
                payload = dict(service)
                host = service['host']
            else:
                payload = dict(abnormal_service=service_name)
                host = 'Any'
            notifier.notify(ctxt,
                            notifier.publisher_id("monitor"),
                            'monitor.host.down',
                            notifier.INFO, payload)
            LOG.info(_('notify ha module that service %(service_name)s on'
                       '%(host)s abnormal!'), locals())
        except Exception as ex:
            LOG.exception(_('notify ha module that service %(service_name)s'
                            ' abnormal failed, ex: %(ex)s'), locals())

    def _is_instance_abnormal(self, ctxt, instance):
        """
        judge whether instance is abnormal

        :returns: True if instance abnormal, False otherwise
        """
        if instance['task_state'] is not None:
            return False

        cache_key = str(instance['uuid']) + '_heart'
        updated_at = self.state_cache.get(cache_key)
        if updated_at:
            updated_at = datetime.datetime.strptime(updated_at,
                                                    "%Y-%m-%d %H:%M:%S")
            now = timeutils.utcnow()
            uuid = instance['uuid']
            instance_failure_time = self.instance_failure_time
            LOG.debug(_('instance %(uuid)s updated_at %(updated_at)s, now is '
                        '%(now)s, instance_failure_time is '
                        '%(instance_failure_time)s'), locals())
            if self.is_time_valid(updated_at, now, instance_failure_time):
                LOG.info(_('check instance %s normal') % instance['uuid'])
                return False
            else:
                LOG.info(_('check instance %s abnormal') % instance['uuid'])
                return True
        else:
            LOG.info(_('instance %s is still booting, hearbeat not started...')
                       % instance['uuid'])
            return False

    def _is_instance_ha(self, ctxt, instance):
        """
        judge whether the instance is a HA instance

        :returns: True if instance is HA, False otherwise
        """
        try:
            meta_item = db.instance_metadata_get_item(ctxt,
                                                      instance['uuid'], 'HA')
            if meta_item:
                LOG.info(_('instance %s is HA') % instance['uuid'])
                return True
        except Exception as ex:
            LOG.info(_('instance %s is not HA') % instance['uuid'])
        return False

    def _notify_ha_instance_failure(self, ctxt, instance, level):
        """
        notify ha module that some ha instance is failure.

        :param instance: instance info got from db.
        """
        uuid = instance['uuid']
        try:
            if level == 0:
                method = 'reboot'
            elif level == 1:
                method = 'rebuild'
            elif level < 5:
                method = 'move'
            else:
                return
            LOG.info(_('notify ha(level:%(level)s) %(method)s'
                       ' instance %(uuid)s'), locals())
            payload = dict(instance, method=method)
            notifier.notify(ctxt,
                            notifier.publisher_id("monitor"),
                            'monitor.vm.down',
                            notifier.ERROR, payload)
        except Exception as ex:
            LOG.exception(_('notifying ha module that instance'
                            ' %(uuid)s is abnormal failed, ex: %(ex)s'),
                          locals())

    def _notify_common_instance_failure(self, ctxt, instance):
        """
        notify some non-ha instance is failure.

        :param instance: instance info got from db.
        """
        try:
            LOG.info(_('notify instance %s is abnormal'), instance['uuid'])
            payload = dict(instance)
            notifier.notify(ctxt,
                            notifier.publisher_id("monitor"),
                            'monitor.vm.down',
                            notifier.ERROR, payload)
        except Exception as ex:
            LOG.exception(_('notifying instance %(uuid)s'
                            ' abnormal failed, ex: %(ex)s')
                          % {'uuid': instance['uuid'], 'ex': ex})

    def _get_instance_failure_info(self, instance):
        """
        get instance failure info from self.instances_failure_info

        :returns: return instance failure info if it's failed before,
                  otherwise return None
        """
        for failure_info in self.instances_failure_info:
            if failure_info['uuid'] == instance['uuid']:
                return failure_info
        return None

    def _report_failure_instances_info(self):
        if self.instances_failure_info:
            LOG.debug(_('================ failure instances info ==========='))
        else:
            LOG.debug(_('There is no abnormal instance now!'))
        for failure_info in self.instances_failure_info:
            uuid = failure_info['uuid']
            failure_times = failure_info['failure_times']
            last_failure_time = failure_info['last_failure_time']
            LOG.debug(_('instance %(uuid)s failed %(failure_times)s times, '
                        'the latest failure is at %(last_failure_time)s'),
                      locals())

    def monitor_instance(self, ctxt):
        """
        check and update instance status,
        if instance is ha and failure, notify the ha module.
        """
        instances_failure_info = []

        instances = db.instance_get_all(ctxt)
        for instance in instances:
            instance_failure_info = self._get_instance_failure_info(instance)
            if not instance_failure_info:
                instance_failure_info = dict(uuid=instance['uuid'],
                                        failure_times=0,
                                        last_failure_time=timeutils.utcnow())

            if self._is_instance_abnormal(ctxt, instance):
                if (instance_failure_info['failure_times'] != 0 and
                    self.is_time_valid(
                        instance_failure_info['last_failure_time'],
                        timeutils.utcnow(),
                        (self.instance_recover_time *
                         instance_failure_info['failure_times']))):
                    LOG.info(_('instance %s is still in recovering...')
                             % instance['uuid'])
                    LOG.debug(_('its last failure time is %s')
                             % instance_failure_info['last_failure_time'])
                    instances_failure_info.append(instance_failure_info)
                    continue
                if self._is_instance_ha(ctxt, instance):
                    self._notify_ha_instance_failure(ctxt, instance,
                                    instance_failure_info['failure_times'])
                else:
                    self._notify_common_instance_failure(ctxt, instance)

                instance_failure_info['failure_times'] += 1
                instance_failure_info['last_failure_time'] = timeutils.utcnow()
                instances_failure_info.append(instance_failure_info)
                LOG.debug(_('instance %(uuid)s failed %(times)s times, '
                            'the latest failure time is %(failure_time)s') %
                          {'uuid': instance['uuid'],
                           'times': instance_failure_info['failure_times'],
                           'failure_time':
                           instance_failure_info['last_failure_time']})

        self.instances_failure_info = instances_failure_info
        self._report_failure_instances_info()

    def _get_service_failure_info(self, service_name, service_host):
        """
        get service failure info from self.services_failure_info

        :returns: return service failure info if it's failed before,
                  otherwise return None
        """
        for failure_info in self.services_failure_info:
            if (failure_info['service_name'] == service_name and
                failure_info['service_host'] == service_host):
                return failure_info
        return None

    def _report_failure_services_info(self):
        if self.services_failure_info:
            LOG.debug(_('========= failure services info ============'))
        else:
            LOG.debug(_('Every service monitored is ok now!'))
        for failure_info in self.services_failure_info:
            service_name = failure_info['service_name']
            host = failure_info['service_host']
            failure_times = failure_info['failure_times']
            last_failure_time = failure_info['last_failure_time']
            LOG.debug(_('service %(service_name)s on host %(host)s failed '
                        '%(failure_times)s times, last failure time is '
                        '%(last_failure_time)s'), locals())

    def monitor_service(self, ctxt):
        """
        check service status, confirm whether service is abnormal,
        and notify the ha module if service is confirmed abnormal

        """
        services_failure_info = []

        for service_name in self.check_services:
            service_topic = service_name.rpartition('nova-')[2]
            abnormal_services = self._get_abnormal_service_by_topic(ctxt,
                                                                service_topic)
            if abnormal_services == True:
                self._notify_ha_service_failure(ctxt, service_name)
            elif abnormal_services:
                for abnormal_service in abnormal_services:
                    service_failure_info = self._get_service_failure_info(
                                       service_name, abnormal_service['host'])
                    if (service_failure_info is not None and
                        self.is_time_valid(
                            service_failure_info['last_failure_time'],
                            timeutils.utcnow(), self.service_recover_time)):
                        LOG.info(_('service %(service)s on %(host)s is'
                                   ' still in recovering...')
                                 % {'service': service_name,
                                    'host': abnormal_service['host']})
                        services_failure_info.append(service_failure_info)
                        continue
                    if self._confirm_service_failure(ctxt, abnormal_service):
                        self._notify_ha_service_failure(ctxt, service_name,
                                                        abnormal_service)
                        if service_failure_info is None:
                            service_failure_info = dict(
                                service_name=service_name,
                                service_host=abnormal_service['host'],
                                failure_times=1,
                                last_failure_time=timeutils.utcnow())
                        else:
                            service_failure_info['failure_times'] += 1
                            now = timeutils.utcnow()
                            service_failure_info['last_failure_time'] = now
                        LOG.info(_('monitor: service %(service)s on %(host)s'
                                   ' abnormal')
                                 % {'service': service_name,
                                    'host': abnormal_service['host']})
                        services_failure_info.append(service_failure_info)
            else:
                LOG.info(_('monitor: service %s is normal') % service_name)
        self.services_failure_info = services_failure_info
        self._report_failure_services_info()

    def monitor(self):
        ctxt = context.get_admin_context()
        self.monitor_service(ctxt)
        self.monitor_instance(ctxt)
