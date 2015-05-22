#
# Created on 2012-8-19
#
# @author: Para: hzyangtk@corp.netease.com
#

from nova import flags
from nova.openstack.common import cfg

nos_opts = [
    cfg.StrOpt('nos_url',
               default='172.17.2.64:8182',
               help='nos service url'),
    cfg.StrOpt('nos_host',
               default='nos.netease.com',
               help='nos host name'),
    cfg.StrOpt('nos_accessKey',
               default='91cd6926fe90445fb1086bfac7629a8a',
               help='nos access public key'),
    cfg.StrOpt('nos_accessSecret',
               default='915c0b090d0c1558846eccb2e9908c38',
               help='nos access secret key'),
    cfg.StrOpt('nos_keypairs_bucket',
               default='private-key',
               help='keypairs bucket name'),
    cfg.IntOpt('nos_keypairs_expires',
               default=86400,
               help='Private key url expires time, default 24 hours'),
    cfg.BoolOpt('keypairs_connect_nos',
                default=True,
                help='Use nos to store private key, default is true'),
    cfg.BoolOpt('nos_use_domain',
                default=True,
                help='Use host domain to connect nos but not url'),
]


FLAGS = flags.FLAGS
FLAGS.register_opts(nos_opts)
