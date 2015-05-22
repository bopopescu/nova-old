# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Piston Cloud Computing, Inc.
# All Rights Reserved.

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

"""Test of Policy Engine For Nova"""

import os.path

from nova import flags
from nova import inject_files
from nova import test
from nova import utils


FLAGS = flags.FLAGS


class InjectFilesTestCase(test.TestCase):
    def setUp(self):
        super(InjectFilesTestCase, self).setUp()
        inject_files.reset()
        self.target = {}

    def tearDown(self):
        super(InjectFilesTestCase, self).tearDown()
        inject_files.reset()

    def test_modified_policy_reloads(self):
        with utils.tempdir() as tmpdir:
            tmpfilename = os.path.join(tmpdir, 'inject_files')
            self.flags(inject_content_file=tmpfilename)

            inject_files.reset()
            with open(tmpfilename, "w") as policyfile:
                policyfile.write("""{"inject_files":
                                            [
                                                {
                                                    "path":"test_path",
                                                    "contents":"test_content"
                                                }
                                            ]
                                    }""")
            inject_files_dict = inject_files.get_inject_files()
            expect_dict = {
                                "inject_files": [
                                    {
                                        "path": "test_path",
                                        "contents": "test_content"
                                    }
                                ]
                            }
            self.assertEqual(expect_dict, inject_files_dict)
