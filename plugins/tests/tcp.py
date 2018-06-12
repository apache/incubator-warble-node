#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This is the generic TCP test suite for Apache Warble (incubating).
It basically just connects to an port and disconnects.
"""

import plugins.basics
import plugins.reports

class test:
    def __init__(self, globalConfig):
        self.config = globalConfig
        
        # Initialize a report object to store our findings
        self.report = plugins.reports.generic.template(self.config)
    
    def run(self, testParameters):
        
        
        try:
            # Open up a TCP socket, tie to the report object and pass test parameters (host, port etc)
            request = plugins.basics.socket.tcp(testParameters, self.report)
            
            # Connect to host
            request.connect()
            
            # If SSL, wrap the socket to OpenSSL via the built-in secure() call.
            SSL = testParameters.get('SSL', False)
            if SSL == True:
                request.secure(SNI = testParameters.get('host'))
            
            # We're connected, that's it! goodbye!
            self.report.debug("Connected to host")
            request.status_code = "Connection accepted"
            status = True
            self.report.timer('data')
            self.report.debug("All went well, closing socket.")
            self.report.timer('end')
            
        except Exception as err:
            print("Caught error:" + str(err))
            if not self.report.error:
                self.report.error('response', str(err))

