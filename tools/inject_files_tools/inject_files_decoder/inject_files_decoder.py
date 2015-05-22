#!/usr/bin/env python
#
# Created on 2013-1-6
#
# @author: hzyangtk@corp.netease.com
#

import base64
import json
import os


FILE_PATH_CONF_NAME = 'inject_path.conf'
DECODER_SOURCE_FILE_PATH = 'decoder_source_files/'
INJECT_FILE_PATH = '../../../etc/nova/'
INJECT_FILE_NAME = 'inject_files.json'


def read_inject_files_json():
    if os.path.exists(INJECT_FILE_PATH):
        open_file = open(INJECT_FILE_PATH + INJECT_FILE_NAME, 'r')
        try:
            inject_files = open_file.read()
            return json.loads(inject_files)
        except (IOError, TypeError):
            print 'Inject files read failed'
            raise
        finally:
            open_file.close()
    else:
        print 'Path for generate inject_files.json is not exist'


def write_file_paths(paths):
    open_file = open(FILE_PATH_CONF_NAME, 'w')
    try:
        paths = open_file.write(paths)
        return True
    except (IOError, TypeError):
        print 'Configuration file write failed'
        raise
    finally:
        open_file.close()


def write_source_files(file_name, content):
    open_file = open(DECODER_SOURCE_FILE_PATH + file_name, 'w')
    try:
        return open_file.write(content)
        return True
    except IOError:
        print 'Source file content write failed, with file name: ' + file_name
        raise
    finally:
        open_file.close()


def decoder_inject_files():
    inject_files_dict = read_inject_files_json()
    inject_files = inject_files_dict['inject_files']
    paths = []
    for inject_file in inject_files:
        path = inject_file['path']
        paths.append(path)
        content_decoded = base64.b64decode(inject_file['contents'])
        write_source_files(path.split('/')[-1], content_decoded)
    paths_json = json.dumps(paths)
    write_file_paths(paths_json)


if __name__ == '__main__':
    print 'Start decoder inject files from path: ' + INJECT_FILE_PATH + \
                                                            INJECT_FILE_NAME
    decoder_inject_files()
    print 'Finish decoder inject files'
