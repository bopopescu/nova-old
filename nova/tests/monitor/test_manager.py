#author: hzguanqiang@corp.netease.com
#

""" test for Monitor service """

import mox
import stubout

import datetime
import memcache
import time

from nova import context
from nova import db
from nova import exception
from nova import flags
from nova.monitor.manager import MonitorManager
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova.openstack.common.notifier import api as notifier
from nova.openstack.common import rpc
from nova.openstack.common.rpc import dispatcher as rpc_dispatcher
from nova.openstack.common import timeutils
from nova import test


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS


class MonitorManagerTestCase(test.TestCase):
    """ Test case for monitor manager """

    def setUp(self):
        super(MonitorManagerTestCase, self).setUp()
        self.flags(check_services=['nova-compute'],
                   service_failure_time=15,
                   instance_failure_time=15,
                   service_recover_time=300,
                   instance_recover_time=180,
                   memcached_servers=['127.0.0.1:11211'])

        self.service_name = 'fake_service'
        self.context = context.get_admin_context()
        self.topic = 'fake_topic'
        self.host = 'fake_host'
        self.service = {'host': 'fake_host', 'topic': 'fake',
                        'binary': 'fake_binary'}
        self.manager_cls = MonitorManager()
        self.manager = self.manager_cls

    def test_is_time_valid(self):
        base_time = datetime.datetime(2012, 11, 2, 6, 21, 35)
        valid_current_time = datetime.datetime(2012, 11, 2, 6, 21, 40)
        invalid_current_time = datetime.datetime(2012, 11, 2, 6, 21, 55)
        interval = 10

        #valid current time
        self.assertEqual(self.manager.is_time_valid(base_time,
                                valid_current_time, interval), True)

        #invalid current time
        self.assertEqual(self.manager.is_time_valid(base_time,
                                invalid_current_time, interval), False)

    def test_get_abnormal_service_by_topic(self):
        now = datetime.datetime.strptime('2012-11-02 07:59:40',
                                         "%Y-%m-%d %H:%M:%S")
        normal_time = datetime.datetime.strptime('2012-11-02 07:59:36',
                                                 "%Y-%m-%d %H:%M:%S")
        abnormal_time = datetime.datetime.strptime('2012-11-02 06:59:36',
                                                   "%Y-%m-%d %H:%M:%S")

        service1 = {'host': 'host1', 'updated_at': normal_time}
        service2 = {'host': 'host2', 'updated_at': abnormal_time}
        normal_services = [service1]
        abnormal_services = [service2]

        self.mox.StubOutWithMock(db, 'service_get_all_by_topic')
        self.mox.StubOutWithMock(timeutils, 'utcnow')

        # got abnormal services
        db.service_get_all_by_topic(self.context, self.topic).AndReturn(
                                                             abnormal_services)
        timeutils.utcnow().AndReturn(now)
        self.mox.ReplayAll()
        self.assertEqual(self.manager._get_abnormal_service_by_topic(
                         self.context, self.topic), abnormal_services)

        # all services is normal
        self.mox.ResetAll()
        db.service_get_all_by_topic(self.context, self.topic).AndReturn(
                                                               normal_services)
        timeutils.utcnow().AndReturn(now)
        self.mox.ReplayAll()
        self.assertEqual(self.manager._get_abnormal_service_by_topic(
                         self.context, self.topic), [])

        # can not get any service info from db
        self.mox.ResetAll()
        db.service_get_all_by_topic(self.context, self.topic).AndRaise(
                                                          exception.NotFound())
        self.mox.ReplayAll()
        self.assertEqual(self.manager._get_abnormal_service_by_topic(
                         self.context, self.topic), True)

    def test_confirm_service_failure(self):
        service = {'host': 'fake_host',
                   'topic': 'compute', 'binary': 'fake_binary'}
        fake_version = 'fake 2012.2'

        self.mox.StubOutWithMock(rpc, 'call')

        # service is normal
        rpc.call(self.context, mox.IgnoreArg(),
                 mox.IgnoreArg()).AndReturn(fake_version)
        self.mox.ReplayAll()
        self.assertEqual(self.manager._confirm_service_failure(
                                                 self.context, service), False)

        # service is abnormal
        self.mox.ResetAll()
        rpc.call(self.context, mox.IgnoreArg(),
                 mox.IgnoreArg()).AndRaise(Exception())
        self.mox.ReplayAll()
        self.assertEqual(self.manager._confirm_service_failure(
                                                  self.context, service), True)

    def test_is_instance_abnormal(self):
        fake_instance1 = {'uuid': 'fake_uuid1',
                         'host': 'fake_compute_host',
                         'task_state': None}
        fake_instance2 = {'uuid': 'fake_uuid2',
                          'host': 'fake_compute_host',
                          'task_state': None}
        fake_instance3 = {'uuid': 'fake_uuid3',
                          'host': 'fake_compute_host',
                          'task_state': 'something'}
        heart_state = '2012-11-02 07:59:30'
        normal_time = datetime.datetime.strptime('2012-11-02 07:59:36',
                                                 "%Y-%m-%d %H:%M:%S")
        abnormal_time = datetime.datetime.strptime('2012-11-02 08:59:36',
                                                   "%Y-%m-%d %H:%M:%S")

        def fake_normal_utcnow():
            return normal_time

        def fake_abnormal_utcnow():
            return abnormal_time

        class Fake_memcache_client(object):
            def __init__(self, servers):
                self.doc = {'fake_uuid1_heart': heart_state,
                            'fake_uuid2_heart': None}

            def set(self, key, value):
                self.doc = dict(self.doc, key=value)

            def get(self, key):
                return self.doc[key]

        self.manager.state_cache = Fake_memcache_client(['127.0.0.1:11211'])

        # instance is normal
        self.stubs.Set(timeutils, 'utcnow', fake_normal_utcnow)
        self.assertEqual(self.manager._is_instance_abnormal(
                         self.context, fake_instance1), False)

        # instance is abnormal
        self.stubs.Set(timeutils, 'utcnow', fake_abnormal_utcnow)
        self.assertEqual(self.manager._is_instance_abnormal(
                         self.context, fake_instance1), True)

        # can not get heartbeat state info for the instance,
        #take this as instance is booting
        self.assertEqual(self.manager._is_instance_abnormal(
                         self.context, fake_instance2), False)

        # instance is doing some task, and hearbeat may be stopped
        self.assertEqual(self.manager._is_instance_abnormal(
                         self.context, fake_instance3), False)

    def test_is_instance_ha(self):
        fake_instance = {'uuid': 'fake_uuid',
                         'host': 'fake_compute_host'}
        meta_item = {'HA': 'xxx'}

        def fake_instance_metadata_get_item(context, instance_uuid, item):
            raise Exception.NotFound

        # instance is ha
        self.mox.StubOutWithMock(db, 'instance_metadata_get_item')
        db.instance_metadata_get_item(self.context,
                            fake_instance['uuid'], 'HA').AndReturn(meta_item)
        self.mox.ReplayAll()
        self.assertEqual(self.manager._is_instance_ha(
                                          self.context, fake_instance), True)

        self.mox.ResetAll()

        # instance not ha
        self.stubs.Set(db, 'instance_metadata_get_item',
                       fake_instance_metadata_get_item)
        self.assertEqual(self.manager._is_instance_ha(
                         self.context, fake_instance), False)

    def test_monitor_normal_instance(self):
        fake_instance = {'uuid': 'fake_uuid',
                         'host': 'fake_compute_host'}

        instances = [fake_instance]

        self.mox.StubOutWithMock(db, 'instance_get_all')
        self.mox.StubOutWithMock(self.manager, '_is_instance_abnormal')
        self.mox.StubOutWithMock(self.manager, '_is_instance_ha')

        #instance normal
        db.instance_get_all(self.context).AndReturn(instances)
        self.manager._is_instance_abnormal(self.context,
                                           fake_instance).AndReturn(False)
        self.mox.ReplayAll()
        self.manager.monitor_instance(self.context)

    def test_monitor_abnormal_nonha_instance(self):
        fake_instance = {'uuid': 'fake_uuid',
                         'host': 'fake_compute_host'}

        instances = [fake_instance]

        self.mox.StubOutWithMock(db, 'instance_get_all')
        self.mox.StubOutWithMock(self.manager, '_is_instance_abnormal')
        self.mox.StubOutWithMock(self.manager, '_is_instance_ha')

        #instance abnormal,but no ha
        self.mox.ResetAll()
        db.instance_get_all(self.context).AndReturn(instances)
        self.manager._is_instance_abnormal(self.context,
                                           fake_instance).AndReturn(True)
        self.manager._is_instance_ha(self.context,
                                     fake_instance).AndReturn(False)
        self.mox.ReplayAll()
        self.manager.monitor_instance(self.context)

    def test_monitor_ha_instance_abnormal_once(self):
        fake_instance = {'uuid': 'fake_uuid',
                         'host': 'fake_compute_host'}

        instances = [fake_instance]

        fake_instance_failure_info = {'uuid': 'fake_uuid',
                                      'failure_times': 1,
                                      'last_failure_time': 'fake_time'}
        fake_instances_failure_info = []
        fake_instances_failure_info.append(fake_instance_failure_info)

        def fake_instance_get_all(context):
            return instances

        def fake_is_instance_abnormal(context, instance):
            return True

        def fake_is_instance_ha(context, instance):
            return True

        def fake_utcnow():
            return 'fake_time'

        #instance is ha and abnormal
        self.stubs.Set(db, 'instance_get_all', fake_instance_get_all)
        self.stubs.Set(self.manager, '_is_instance_abnormal',
                       fake_is_instance_abnormal)
        self.stubs.Set(self.manager, '_is_instance_ha',
                       fake_is_instance_ha)
        self.stubs.Set(timeutils, 'utcnow', fake_utcnow)
        self.manager.monitor_instance(self.context)
        self.assertEqual(self.manager.instances_failure_info,
                         fake_instances_failure_info)

    def test_monitor_ha_instance_still_recovering_after_first_failure(self):
        fake_instance = {'uuid': 'fake_uuid',
                         'host': 'fake_compute_host'}

        instances = [fake_instance]

        fake_instance_failure_info1 = {'uuid': 'fake_uuid',
                                      'failure_times': 1,
                                      'last_failure_time': 'fake_time1'}
        fake_instances_failure_info1 = []
        fake_instances_failure_info1.append(fake_instance_failure_info1)

        def fake_instance_get_all(context):
            return instances

        def fake_is_instance_abnormal(context, instance):
            return True

        def fake_is_instance_ha(context, instance):
            return True

        def fake_is_time_valid(base, current, interval):
            return True

        #instance is ha and abnormal
        self.stubs.Set(db, 'instance_get_all', fake_instance_get_all)
        self.stubs.Set(self.manager, '_is_instance_abnormal',
                       fake_is_instance_abnormal)
        self.stubs.Set(self.manager, '_is_instance_ha', fake_is_instance_ha)
        self.stubs.Set(self.manager, 'is_time_valid', fake_is_time_valid)
        self.manager.instances_failure_info = fake_instances_failure_info1
        self.manager.monitor_instance(self.context)
        self.assertEqual(self.manager.instances_failure_info,
                         fake_instances_failure_info1)

    def test_monitor_ha_instance_abnormal_twice(self):
        fake_instance = {'uuid': 'fake_uuid',
                         'host': 'fake_compute_host'}

        instances = [fake_instance]

        fake_instance_failure_info1 = {'uuid': 'fake_uuid',
                                      'failure_times': 1,
                                      'last_failure_time': 'fake_time1'}
        fake_instance_failure_info2 = {'uuid': 'fake_uuid',
                                      'failure_times': 2,
                                      'last_failure_time': 'fake_time2'}
        fake_instances_failure_info1 = []
        fake_instances_failure_info2 = []
        fake_instances_failure_info1.append(fake_instance_failure_info1)
        fake_instances_failure_info2.append(fake_instance_failure_info2)

        def fake_instance_get_all(context):
            return instances

        def fake_is_instance_abnormal(context, instance):
            return True

        def fake_is_instance_ha(context, instance):
            return True

        def fake_is_time_valid(base, current, interval):
            return False

        def fake_utcnow():
            return 'fake_time2'

        #instance is ha and abnormal
        self.stubs.Set(db, 'instance_get_all', fake_instance_get_all)
        self.stubs.Set(self.manager, '_is_instance_abnormal',
                       fake_is_instance_abnormal)
        self.stubs.Set(self.manager, '_is_instance_ha', fake_is_instance_ha)
        self.stubs.Set(self.manager, 'is_time_valid', fake_is_time_valid)
        self.stubs.Set(timeutils, 'utcnow', fake_utcnow)
        self.manager.instances_failure_info = fake_instances_failure_info1
        self.manager.monitor_instance(self.context)
        self.assertEqual(self.manager.instances_failure_info,
                         fake_instances_failure_info2)

    def test_monitor_service(self):
        abnormal_service = {'host': 'fake_host',
                            'topic': 'fake', 'binary': 'fake_binary'}
        abnormal_services = [abnormal_service]

        def fake_get_abnormal_service_by_topic_normal(context, topic):
            return []

        def fake_get_abnormal_service_by_topic_abnormal_db(context, topic):
            return True

        def fake_get_abnormal_service_by_topic_abnormal(context, topic):
            return abnormal_services

        def fake_confirm_service_failure_normal(context, service):
            return False

        def fake_confirm_service_failure_abnormal(context, service):
            return True

        #service normal
        self.stubs.Set(self.manager, '_get_abnormal_service_by_topic',
                       fake_get_abnormal_service_by_topic_normal)
        self.manager.monitor_service(self.context)

        #service abnormal because can't get any info from db
        self.stubs.Set(self.manager, '_get_abnormal_service_by_topic',
                       fake_get_abnormal_service_by_topic_abnormal_db)
        self.manager.monitor_service(self.context)

        #find service abnormal but confirmed normal
        self.stubs.Set(self.manager, '_get_abnormal_service_by_topic',
                       fake_get_abnormal_service_by_topic_abnormal)
        self.stubs.Set(self.manager, '_confirm_service_failure',
                       fake_confirm_service_failure_normal)
        self.manager.monitor_service(self.context)

        #find service abnormal and confirmed abnormal
        self.stubs.Set(self.manager, '_get_abnormal_service_by_topic',
                       fake_get_abnormal_service_by_topic_abnormal)
        self.stubs.Set(self.manager, '_confirm_service_failure',
                       fake_confirm_service_failure_abnormal)
        self.manager.monitor_service(self.context)
