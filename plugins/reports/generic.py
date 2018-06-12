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

"""
This is the generic node report class for Apache Warble (incubating)
"""

import time
import plugins.basics.misc
import uuid

class template:
    
    def __init__(self, globalConfig):
        self._debug = [] # Generic debug array with tuples in it
        self._warn = [] # Generic warning array with tuples in it
        self._alert = [] # Generic alert array with tuples in it
        self._error = None # Error placeholder
        self.timeseries = {} # Generic dictionary timeseries
        self.id = uuid.uuid4() # Report ID
        self.config = globalConfig
        self.offset = globalConfig['misc'].get('offset', 0) # timestamp offset
        
    def debug(self, string):
        """ Logs a debug string in the report with a timestamp """
        now = time.time() - self.offset
        self._debug.append( (now, string) )
        if self.config.get('debug', False) == True:
            print(string)
        
    def error(self, tag, string):
        self._error = {
            'time': time.time() - self.offset,
            'component': tag,
            'message': string
        }
        
    def warn(self, string):
        """ Logs a warning message """
        now = time.time() - self.offset
        self._warn.append( (now, string) )
    
    def alert(self, string):
        """ Logs an alert message """
        now = time.time() - self.offset
        self._alert.append( (now, string) )
    
    def timer(self, tag):
        """ Logs an event in a timeseries list """
        now = time.time() - self.offset
        self.timeseries[tag] = now
    
