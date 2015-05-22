#
#    Created on 2012-10-30
#
#    @author: hzyangtk@corp.netease.com
#
#    /etc/nova/inject_files.json
#
#    {
#        "inject_files" : [
#            {
#                "path" : "/etc/vm_monitor/send_monitor_data.py",
#                "contents" : "IyEvdXNyL"
#            }
#        ]
#    }
#

import os

from nova import exception
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import jsonutils
from nova import utils

inject_files_opts = [
    cfg.BoolOpt('allow_inject_files',
                default=False,
                help='Determine allow inject files from inject_files.json.'),
    cfg.StrOpt('inject_content_file',
               default='inject_files.json',
               help='JSON file representing inject files contents'),
    ]


FLAGS = flags.FLAGS
FLAGS.register_opts(inject_files_opts)

_INJECT_FILES_PATH = None
_INJECT_FILES_CACHE = {}
_INJECT_FILES_DICT = {}


def reset():
    global _INJECT_FILES_PATH
    global _INJECT_FILES_CACHE
    _INJECT_FILES_PATH = None
    _INJECT_FILES_CACHE = {}


def init():
    global _INJECT_FILES_PATH
    global _INJECT_FILES_CACHE
    if not _INJECT_FILES_PATH:
        _INJECT_FILES_PATH = FLAGS.inject_content_file
        if not os.path.exists(_INJECT_FILES_PATH):
            _INJECT_FILES_PATH = FLAGS.find_file(_INJECT_FILES_PATH)
        if not _INJECT_FILES_PATH:
            raise exception.ConfigNotFound(path=FLAGS.inject_content_file)
    utils.read_cached_file(_INJECT_FILES_PATH, _INJECT_FILES_CACHE,
                           reload_func=_load_inject_files)


def _load_inject_files(data):
    global _INJECT_FILES_DICT
    try:
        _INJECT_FILES_DICT = jsonutils.loads(data)
    except ValueError:
        raise exception.Invalid()


def get_inject_files():
    global _INJECT_FILES_DICT
    init()
    return _INJECT_FILES_DICT
