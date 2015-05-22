# author: hzwangpan@corp.netease.com
# client of nbs api for nova to interact with nbs service

import httplib
import json
import time

from nova import exception
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova.openstack.common.notifier import api as notifier_api


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)


class API():
    def __init__(self):
        self._nbs_api_server = FLAGS.nbs_api_server or ""
        if "http://" in self._nbs_api_server:
            self._nbs_api_server = self._nbs_api_server.replace("http://", "")
        if "/" in self._nbs_api_server:
            self._nbs_api_server = self._nbs_api_server.replace("/", "")

        if FLAGS.nbs_prefix_url:
            self._nbs_prefix_url = "/" + FLAGS.nbs_prefix_url
        else:
            self._nbs_prefix_url = ""

    def get(self, context, volume_id):
        """Get volume detail by calling nbs DescribeVolumes api"""
        if not volume_id:
            LOG.warn(_("params missing: %(vol_id)s") % {"vol_id": volume_id},
                        context=context)
            return None

        project_id = context.project_id
        url = (self._nbs_prefix_url + "/?Action=DescribeVolumes"
                + "&ProjectId=" + str(project_id)
                + "&VolumeId=" + str(volume_id))

        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        params = None
        method = "GET"
        return self._request(context, method, url, params, headers)

    def attach(self, context, volume_id, instance_uuid, host_ip, device):
        """Attach a nbs volume to host by calling nbs AttachVolume api"""
        if not volume_id or not instance_uuid or not host_ip or not device:
            LOG.warn(_("params missing: %(vol_id)s, %(uuid)s, %(host_ip)s, "
                       "%(device)s") % {"vol_id": volume_id,
                                        "uuid": instance_uuid,
                                        "host_ip": host_ip, "device": device},
                        context=context)
            return None

        project_id = context.project_id
        url = (self._nbs_prefix_url + "/?Action=AttachVolume"
                + "&ProjectId=" + str(project_id)
                + "&VolumeId=" + str(volume_id)
                + "&InstanceId=" + str(instance_uuid)
                + "&HostIp=" + str(host_ip)
                + "&Device=" + str(device))
        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        params = None
        method = "GET"
        return self._request(context, method, url, params, headers)

    def detach(self, context, volume_id, host_ip):
        """Detach a nbs volume from host by calling nbs DetachVolume api"""
        if not volume_id or not host_ip:
            LOG.warn(_("params missing: %(vol_id)s, %(host_ip)s")
                        % {"vol_id": volume_id, "host_ip": host_ip},
                        context=context)
            return None

        project_id = context.project_id
        url = (self._nbs_prefix_url + "/?Action=DetachVolume"
                + "&ProjectId=" + str(project_id)
                + "&VolumeId=" + str(volume_id)
                + "&HostIp=" + host_ip)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        params = None
        method = "GET"
        return self._request(context, method, url, params, headers)

    def extend(self, context, volume_id, size, host_ip=None):
        """Extend a nbs volume by calling nbs ExtendVolume api"""
        if not volume_id or not size:
            LOG.warn(_("params missing: %(vol_id)s, %(size)s")
                        % {"vol_id": volume_id, "size": size},
                        context=context)
            return None

        project_id = context.project_id
        url = (self._nbs_prefix_url + "/?Action=ExtendVolume"
                + "&ProjectId=" + str(project_id)
                + "&VolumeId=" + str(volume_id)
                + "&Size=" + str(size))
        if host_ip:
            url += "&HostIp=" + host_ip
        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        params = None
        method = "GET"
        return self._request(context, method, url, params, headers)

    def wait_for_attached(self, context, volume_id, instance_uuid,
                            check_interval=3):
        """
        Wait for nbs finished to attach the volume to host by checking status
        """
        # FIXME(wangpan): How to deal with the timeout situation?
        start = time.time()
        times = 1
        while (time.time() - start < FLAGS.nbs_attach_wait_timeout):
            # FIXME(wangpan): we just deal with single attachment status now
            try:
                volume = self.get(context, volume_id)["volumes"][0]
            except (IndexError, KeyError, TypeError):
                LOG.warn(_("Get nothing from nbs server, sleep %(interval)ds "
                           "and retry, times: %(times)d")
                           % {"interval": check_interval, "times": times},
                           context=context)
                time.sleep(check_interval)
                times += 1
                continue

            try:
                attachment = volume["attachments"][0]
                if attachment["status"] == "attached":
                    return True
            except (IndexError, KeyError, TypeError):
                LOG.warn(_("Get wrong info from nbs server, sleep "
                           "%(interval)ds and retry, times: %(times)d")
                           % {"interval": check_interval, "times": times},
                           context=context)

            LOG.info(_("sleep %(interval)ds and retry to check volume's "
                       "status, times: %(times)d")
                       % {"interval": check_interval, "times": times},
                       context=context)
            time.sleep(check_interval)
            times += 1
        LOG.warn(_("volume %(volume)s can not be attached successfully "
                   "after %(timeout)ds")
                   % {"volume": volume_id,
                      "timeout": FLAGS.nbs_attach_wait_timeout},
                   context=context)
        return False

    def wait_for_extended(self, context, volume_id, expected_size,
                            check_interval=3):
        """Wait for nbs finished to extend the volume by checking size"""
        # FIXME(wangpan): How to deal with the timeout situation?
        start = time.time()
        times = 1
        while (time.time() - start < FLAGS.nbs_extend_wait_timeout):
            # FIXME(wangpan): we just deal with single attachment status now
            try:
                volume = self.get(context, volume_id)["volumes"][0]
            except (IndexError, KeyError, TypeError):
                LOG.warn(_("Get nothing from nbs server, sleep %(interval)ds "
                           "and retry, times: %(times)d")
                           % {"interval": check_interval, "times": times},
                           context=context)
                time.sleep(check_interval)
                times += 1
                continue

            try:
                if int(volume["size"]) == expected_size:
                    return True
            except (KeyError, TypeError, ValueError):
                LOG.warn(_("Get wrong info from nbs server, sleep "
                           "%(interval)ds and retry, times: %(times)d")
                           % {"interval": check_interval, "times": times},
                           context=context)

            LOG.info(_("sleep %(interval)ds and retry to check volume's "
                       "size, times: %(times)d")
                       % {"interval": check_interval, "times": times},
                       context=context)
            time.sleep(check_interval)
            times += 1

        LOG.warn(_("volume %(volume)s can not be extended successfully "
                   "after %(timeout)ds")
                   % {"volume": volume_id,
                      "timeout": FLAGS.nbs_attach_wait_timeout},
                   context=context)
        return False

    def wait_for_detach(self, context, bdms, check_interval=3):
        """Wait for nbs finished to detach the volume by checking status"""
        # FIXME(wangpan): How to deal with the timeout situation?
        volumes = [{"id": vol["volume_id"], "detached": False} for vol in bdms]
        start = time.time()
        times = 1
        while (time.time() - start < FLAGS.nbs_detach_wait_timeout):
            all_detached = True
            for vol in volumes:
                if vol["detached"]:
                    continue

                # FIXME(wangpan): we just handle single attachment status now
                try:
                    volume = self.get(context, vol["id"])["volumes"][0]
                except (IndexError, KeyError, TypeError):
                    LOG.warn(_("Get nothing from nbs server, sleep "
                               "%(interval)ds and retry, times: %(times)d")
                               % {"interval": check_interval, "times": times},
                               context=context)
                    all_detached = False
                    break

                try:
                    if volume["status"] != "available":
                        all_detached = False
                        break
                    else:
                        vol["detached"] = True
                except (KeyError, TypeError, ValueError):
                    LOG.warn(_("Get wrong info from nbs server, sleep "
                               "%(interval)ds and retry, times: %(times)d")
                               % {"interval": check_interval, "times": times},
                               context=context)
                    all_detached = False
                    break

            if all_detached:
                return True
            LOG.info(_("sleep %(interval)ds and retry to check volume's "
                       "status, times: %(times)d")
                       % {"interval": check_interval, "times": times},
                       context=context)
            time.sleep(check_interval)
            times += 1

        LOG.warn(_("volumes %(volumes)s can not be detached successfully after"
                   " %(timeout)ds") % {"volumes": volumes,
                                    "timeout": FLAGS.nbs_detach_wait_timeout},
                   context=context)
        return False

    def get_host_dev_and_qos_info(self, context, volume_id, host_ip):
        """Get host device and QoS info from nbs server"""
        if not volume_id or not host_ip:
            LOG.warn(_("params missing: %(vol_id)s, %(host_ip)s")
                        % {"vol_id": volume_id, "host_ip": host_ip},
                        context=context)
            return None

        project_id = context.project_id
        url = (self._nbs_prefix_url + "/?Action=GetVolumeQos"
                + "&ProjectId=" + str(project_id)
                + "&VolumeId=" + str(volume_id)
                + "&HostIp=" + str(host_ip))

        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        params = None
        method = "GET"
        result = self._request(context, method, url, params, headers)
        if result is None:
                raise exception.NbsException()

        host_dev = result.get('devicePath', None)
        if host_dev is None:
            raise exception.NbsException()

        iotune_total_bytes = result.get('maxBandWidth')
        iotune_total_iops = result.get('maxIOPS')
        iotune_read_bytes = result.get('maxReadBandWidth')
        iotune_write_bytes = result.get('maxWriteBandWidth')
        iotune_read_iops = result.get('maxReadIOPS')
        iotune_write_iops = result.get('maxWriteIOPS')

        qos_info = {}
        if (iotune_read_bytes is not None or
                iotune_write_bytes is not None or
                iotune_read_iops is not None or
                iotune_write_iops is not None):
            if iotune_read_bytes is not None:
                qos_info['iotune_read_bytes'] = int(iotune_read_bytes)
            if iotune_write_bytes is not None:
                qos_info['iotune_write_bytes'] = int(iotune_write_bytes)
            if iotune_read_iops is not None:
                qos_info['iotune_read_iops'] = int(iotune_read_iops)
            if iotune_write_iops is not None:
                qos_info['iotune_write_iops'] = int(iotune_write_iops)
        elif (iotune_total_bytes is not None or
                iotune_total_iops is not None):
            if iotune_total_bytes is not None:
                qos_info['iotune_total_bytes'] = int(iotune_total_bytes)
            if iotune_total_iops is not None:
                qos_info['iotune_total_iops'] = int(iotune_total_iops)
        else:
            LOG.error(_("Nbs volume %s qos info is missing") % volume_id)

        return (host_dev, qos_info)

    def notify_nbs_libvirt_result(self, context, volume_id, operation, result,
                    device=None, host_ip=None, instance_uuid=None, size=None):
        """
        Tell nbs the operation result of libvirt, so they can get an identical
        status with us.
        Only attachment operation is notified currently.
        """

        if not volume_id or not operation or not isinstance(result, bool):
            LOG.warn(_("params missing: %(vol_id)s, %(operation)s, %(result)s")
                        % {"vol_id": volume_id, "operation": operation,
                           "result": result},
                        context=context)
            return None

        if operation == "attach":
            if not device or not host_ip or not instance_uuid:
                LOG.warn(_("params missing: %(device)s, %(host_ip)s, %(uuid)s")
                            % {"device": device, "host_ip": host_ip,
                               "uuid": instance_uuid},
                            context=context)
                return None
        elif operation == "extend":
            if not size:
                LOG.warn(_("params missing: %(size)s") % {"size": size},
                            context=context)
                return None

        project_id = context.project_id
        url = (self._nbs_prefix_url + "/?Action=NotifyState"
                + "&ProjectId=" + str(project_id)
                + "&VolumeId=" + str(volume_id)
                + "&OperateType=" + str(operation))

        if operation == "attach":
            url += ("&Device=" + str(device)
                    + "&HostIp=" + str(host_ip)
                    + "&InstanceId=" + str(instance_uuid))
        elif operation == "extend":
            url += "&Size=" + str(size)

        if result:
            url += "&OperateState=" + "success"
        else:
            url += "&OperateState=" + "fail"

        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        params = None
        method = "GET"
        return self._request(context, method, url, params, headers)

    def notify_nbs_qos_updated(self, context, volume_id, qos_info):
        """
        Tell nbs the qos updating operation result of libvirt, so they can get
        an identical status with us.
        """
        if not volume_id or not qos_info:
            LOG.warn(_("params missing: %(vol_id)s, %(qos_info)s")
                        % {"vol_id": volume_id, "qos_info": qos_info},
                        context=context)
            return None

        project_id = context.project_id
        url = (self._nbs_prefix_url + "/?Action=UpdateVolumeQos"
                + "&ProjectId=" + str(project_id)
                + "&VolumeId=" + str(volume_id))

        iotune_total_bytes = qos_info.get('iotune_total_bytes')
        iotune_total_iops = qos_info.get('iotune_total_iops')
        iotune_read_bytes = qos_info.get('iotune_read_bytes')
        iotune_write_bytes = qos_info.get('iotune_write_bytes')
        iotune_read_iops = qos_info.get('iotune_read_iops')
        iotune_write_iops = qos_info.get('iotune_write_iops')
        if (iotune_read_bytes is not None or
                iotune_write_bytes is not None or
                iotune_read_iops is not None or
                iotune_write_iops is not None):
            if iotune_read_bytes is not None:
                url += "&MaxReadBandWidth=" + str(iotune_read_bytes)
            if iotune_write_bytes is not None:
                url += "&MaxWriteBandWidth=" + str(iotune_write_bytes)
            if iotune_read_iops is not None:
                url += "&MaxReadIOPS=" + str(iotune_read_iops)
            if iotune_write_iops is not None:
                url += "&MaxWriteIOPS=" + str(iotune_write_iops)
        elif (iotune_total_bytes is not None or
                iotune_total_iops is not None):
            if iotune_total_bytes is not None:
                url += "&MaxBandWidth=" + str(iotune_total_bytes)
            if iotune_total_iops is not None:
                url += "&MaxIOPS=" + str(iotune_total_iops)
        else:
            LOG.error(_("qos info is invalid, info: %(qos_info)s, "
                        "id: %(vol_id)s") % {"qos_info": qos_info,
                        "vol_id": volume_id}, context=context)
            return

        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        params = None
        method = "GET"
        return self._request(context, method, url, params, headers)

    def _request(self, context, method, url, params, headers):
        """The essential implement of nbs api client"""
        if not self._nbs_api_server:
            LOG.warn(_("nbs_api_server is null, can't connect to it"))
            return None

        unified_log_id = None
        unified_log_seq = None
        if context:
            unified_log_id = context.to_dict().get('unified_log_id', None)
            unified_log_seq = context.to_dict().get('unified_log_seq', None)
        if unified_log_id and unified_log_seq:
            log_seq_nums = unified_log_seq.split('.')
            log_seq_nums[-1] = str(int(log_seq_nums[-1]) + 1)
            new_log_seq = '.'.join(log_seq_nums)
            context.unified_log_seq = new_log_seq

            url = url + "&LogId=" + str(unified_log_id)
            url = url + "&LogSeq=" + str(new_log_seq)

        full_url = self._nbs_api_server + url

        LOG.info(_("send request to %(full_url)s, method: %(method)s, "
                   "body: %(params)s, headers: %(headers)s")
                   % {"full_url": full_url, "method": method,
                      "params": params, "headers": headers},
                   context=context)
        try:
            nbs_conn = httplib.HTTPConnection(self._nbs_api_server)
        except Exception, ex:
            LOG.error(_("exception occurs when connect to nbs server, "
                        "error msg: %s") % str(ex), context=context)
            self._notify_NBS_connection_failure(context, self._nbs_api_server)
            return None

        try:
            nbs_conn.request(method, url, params, headers)
            resp = nbs_conn.getresponse()
            if resp:
                if resp.status == 200:
                    data = json.loads(resp.read())
                    request_id = data["requestId"]
                    LOG.info(_("request id: %(request_id)s, data: "
                               "%(data)s") % locals(), context=context)
                    return data
                else:
                    err_code = resp.status
                    err_reason = resp.reason
                    LOG.error(_("error occurs when contact to nbs server, "
                                "error code: %(code)d, reason: %(reason)s")
                                % {"code": err_code, "reason": err_reason},
                                context=context)
                    self._notify_NBS_connection_failure(context, full_url)
                    return None
            else:
                LOG.error(_("nbs server doesn't return any response"),
                            context=context)
                self._notify_NBS_connection_failure(context, full_url)
                return None

        except Exception, ex:
            LOG.error(_("exception occurs when send request to nbs server, "
                        "error msg: %s") % str(ex), context=context)
            self._notify_NBS_connection_failure(context, full_url)
            return None
        finally:
            nbs_conn.close()

    def _notify_NBS_connection_failure(self, context, url):
        """Send a message to notification about NBS connection failure"""
        try:
            LOG.info(_('notify NBS connection failure'))
            payload = dict({'url': url})
            notifier_api.notify(context,
                                notifier_api.publisher_id('api_nbs'),
                                'api_nbs.nvs_connect_nbs_failure',
                                notifier_api.ERROR, payload)
        except Exception:
            LOG.exception(_('notification module error when do notifying '
                            'NVS connect NBS failed.'))
