#!/usr/bin/env python
#
# Created on 2013-1-6
#
# @author: hzyangtk@corp.netease.com
#

import base64
import json
import os
import sys


FILE_PATH_CONF_NAME = 'inject_path.conf'
SOURCE_FILE_PATH = 'source_input_files/'
INJECT_FILE_PATH = '../../../etc/nova/'
INJECT_FILE_NAME = 'inject_files.json'


def read_file_paths():
    open_file = open(FILE_PATH_CONF_NAME, 'r')
    try:
        paths = open_file.read()
        paths_dict = json.loads(paths)
        return paths_dict
    except (IOError, TypeError):
        print 'Configuration file read failed'
        raise
    finally:
        open_file.close()


def read_source_file_content(file_name):
    open_file = open(SOURCE_FILE_PATH + file_name, 'r')
    try:
        return open_file.read()
    except IOError:
        print 'Source file content read failed'
        raise
    finally:
        open_file.close()


def write_inject_files(inject_files_json):
    if os.path.exists(INJECT_FILE_PATH):
        open_file = open(INJECT_FILE_PATH + INJECT_FILE_NAME, 'w')
        try:
            open_file.write(inject_files_json)
            return True
        except IOError:
            print 'Inject files write failed'
            raise
        finally:
            open_file.close()
    else:
        print 'Path for generate inject_files.json is not exist'


def generate_inject_files():
    inject_files = []
    paths_list = read_file_paths()
    for path in paths_list:
        file_name = path.split('/')[-1]
        try:
            contents = read_source_file_content(file_name)
        except IOError:
            print 'Read source file content IOError occurs, skip this file: ' \
                                                            + path
            continue
        # use base64 encode contents
        contents_base64 = base64.b64encode(contents)
        inject_file = {'path': path,
                       'contents': contents_base64}
        inject_files.append(inject_file)
    inject_files_json = json.dumps({'inject_files': inject_files})
    # print result to user and judge user`s selection
    print inject_files_json
    print ('Above is the generation inject_files.json content,'
           ' if you want to generate it please input YES,'
           ' other inputs will cancel this mission')
    line = sys.stdin.readline()
    user_input = line.split()
    if user_input[0] == 'YES':
        write_inject_files(inject_files_json)
        print 'Finish generating inject files'
    else:
        print 'You have canceled this generation mission'


if __name__ == '__main__':
    print 'Start generating inject files to path: ' + INJECT_FILE_PATH + \
                                                            INJECT_FILE_NAME
    generate_inject_files()
