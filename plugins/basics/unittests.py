#!/usr/bin/env python3.4
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

""" This is a generic unit testing lib for
    Apache Warble (incubating) nodes.
"""

import plugins.basics
import plugins.tests
import datetime

def spit(t):
    # All done, spit out report
    print("TEST %s COMPLETED" % t.report.id)
    print()
    
    print("DEBUG:")
    print('-' * 80)
    for k, v in t.report._debug:
        print(datetime.datetime.fromtimestamp(k).strftime("%Y-%m-%d %H:%M:%S.%f"), v)
    print('-' * 80)
    print("TIMESTAMPS:")
    print('-' * 80)
    previous = None
    first = None
    for k, v in sorted(t.report.timeseries.items(), key = lambda x: x[1]):
        if not previous:
            previous = v
            first = v
        print("%-10s: +%3dms (%3dms)" % (k, ((v - previous) * 1000), (v - first) * 1000))
        previous = v
    print('-' * 80)

def uprint(t, params):
    print("Running test %s:" % t.report.id)
    print('-' * 80)
    for k, v in params.items():
        print("%-16s: %s" % (k, v))
    print('-' * 80)
    
def run(gc):
    gc['debug'] = True
    
    # TCP test
    params = {
        'host': 'www-us.apache.org',
        'port': 80
    }
    t = plugins.tests.tcp.test(gc)
    uprint(t, params)
    t.run(params)
    spit(t)
    
    # HTTP test
    params = {
        'host': 'www-eu.apache.org',
        'vhost': 'www.apache.org',
        'URI': '/',
        'port': 80
    }
    t = plugins.tests.http.test(gc)
    uprint(t, params)
    t.run(params)
    spit(t)
    
    # SMTP test
    params = {
        'host': 'mail-relay.apache.org',
        'type': 'smtp',
        'SSL': True,
        'port': 465
    }
    uprint(t, params)
    t = plugins.tests.smtp.test(gc)
    t.run(params)
    spit(t)
    