#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
 #the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" This is the library for miscellaneous auxiliary functions for
    Apache Warble (incubating) nodes.
"""

# Socket imports
import select
import socket
import ssl
import struct
from socket import AF_INET, SOCK_DGRAM
import time
import uuid

def hostname():
    return socket.gethostname()

def appid():
    return "%s/%s" % (hostname(), uuid.uuid4())

def adjustTime(host):
    TS_1970 = 2208988800
    client = socket.socket( AF_INET, SOCK_DGRAM )
    client.settimeout(5)
    data = b'\x1b' + 47 * b'\0'
    ipaddr = socket.gethostbyname(host)
    client.sendto( data, ( ipaddr, 123 ))
    try:
        data, address = client.recvfrom( 1024 )
        if data:
            t = struct.unpack( '!12I', data )[10]
            t -= TS_1970
            offset = time.time() - t
            if offset > 0:
                print("NTP: Offsetting time by %d miliseconds (machine clock is slightly ahead of real time)" % (offset * 1000))
            elif offset < 0:
                print("NTP: Offsetting time by %d miliseconds (machine clock is slightly behind real time)" % (offset * 1000))
            return offset
        else:
            return 0
    except Exception as err:
        return 0



class timer():
    def __init__(self):
        self.started = time.time() - toffset
        self.last = time.time();
        self.log = {}
    def add(self, logtype):
        self.log['time_' + logtype] = time.time() - toffset
        if (time.time() - self.last) > 60:
            raise Exception("Monitoring step took more than 60 seconds to complete")
        self.last = time.time()

class debugger():
    def __init__(self):
        self.started = time.time()
        self.log = ""
    def add(self, message):
        self.log += "[%s]: %s\r\n" % (time.asctime(time.gmtime()), message)
        print("[%s]: %s\r\n" % (time.asctime(time.gmtime()), message))


def makeError(component, errmsg):
    log = {}
    log['time'] = time.time() - toffset
    log['component'] = component
    log['error'] = errmsg
    return log

