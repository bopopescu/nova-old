# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2010 OpenStack, LLC.
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

"""
Scheduler that allows routing some calls to one driver and others to another.
"""

from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import importutils
from nova.scheduler import driver


multi_scheduler_opts = [
    cfg.StrOpt('compute_scheduler_driver',
               default='nova.scheduler.'
                    'filter_scheduler.FilterScheduler',
               help='Driver to use for scheduling compute calls'),
    cfg.StrOpt('volume_scheduler_driver',
               default='nova.scheduler.chance.ChanceScheduler',
               help='Driver to use for scheduling volume calls'),
    cfg.StrOpt('default_scheduler_driver',
               default='nova.scheduler.chance.ChanceScheduler',
               help='Default driver to use for scheduling calls'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(multi_scheduler_opts)


class MultiScheduler(driver.Scheduler):
    """A scheduler that holds multiple sub-schedulers.

    This exists to allow flag-driven composibility of schedulers, allowing
    third parties to integrate custom schedulers more easily.

    """

    def __init__(self):
        super(MultiScheduler, self).__init__()
        compute_driver = importutils.import_object(
                FLAGS.compute_scheduler_driver)
        volume_driver = importutils.import_object(
                FLAGS.volume_scheduler_driver)
        default_driver = importutils.import_object(
                FLAGS.default_scheduler_driver)

        self.drivers = {'compute': compute_driver,
                        'volume': volume_driver,
                        'default': default_driver}

    def schedule_run_instance(self, *args, **kwargs):
        return self.drivers['compute'].schedule_run_instance(*args, **kwargs)

    def schedule_prep_resize(self, *args, **kwargs):
        return self.drivers['compute'].schedule_prep_resize(*args, **kwargs)

    def schedule_relocate(self, *args, **kwargs):
        return self.drivers['compute'].schedule_relocate(*args, **kwargs)

    def schedule_create_volume(self, *args, **kwargs):
        return self.drivers['volume'].schedule_create_volume(*args, **kwargs)

    def update_service_capabilities(self, service_name, host, capabilities):
        # Multi scheduler is only a holder of sub-schedulers, so
        # pass the capabilities to the schedulers that matter
        for d in self.drivers.values():
            d.update_service_capabilities(service_name, host, capabilities)
