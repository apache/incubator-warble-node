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

"""
This is the TCP/UDP Socket Library for Apache Warble (incubating)
"""

# Socket imports
import select
import socket
import ssl
import struct
from socket import AF_INET, SOCK_DGRAM
import time


class tcp():
    def __init__(self, testParameters, report):
        self.report = report
        self.iptype = socket.AF_INET6 if (testParameters.get('ipv6', False) == True) else socket.AF_INET
        self.host = testParameters.get('host')
        self.port = int(testParameters.get('port', 80))
        self.error = None
        self.socket = socket.socket(self.iptype, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        self.bytes = 0
        self.report.debug("Initialising socket")
        self.report.timer('init')
        self.status_code = None
        self.location = None
        self.server = None
        self.realip = None
        self.cert = None
    
        try:
            self.report.debug("Looking up hostname %s..." % self.host)
            af, socktype, proto, canonname, sa = socket.getaddrinfo(self.host, self.port, self.iptype, socket.SOCK_STREAM)[0]
            self.report.timer('dns')
            self.sa = sa
        except Exception as err:
            raise Exception("Could not resolve hostname: %s" % err)
            

        self.realip = sa[0];
        if not self.realip:
            self.report.error('dns', "Could not resolve host %s" % self.host)
            return None
        if self.realip and self.realip == '127.0.0.1' or self.realip == '::1':
            self.report.error('dns', "Hostname %s points to localhost!" % self.host)
            return None
        self.report.debug("Connecting to %s:%u" % (self.realip, self.port))
        self.socket = socket.socket(af, socktype, proto)
    
    def __del__(self):
        # Close socket if not already closed
        try:
            self.socket.close()
        except:
            pass
    
    def secure(self, SNI = None, verify = False):
        """ Wrap socket in OpenSSL """
        self.report.debug("Wrapping socket for TLS")
        if SNI:
            self.report.debug("Using SNI extension for %s" % SNI)
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) # SSL, TLS1, TLS1.1 is largely deprecated now.
            context.verify_mode = ssl.CERT_OPTIONAL
            # Are we going to test the certificate for validity?
            if verify == True:
                context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            
            self.socket = context.wrap_socket(self.socket, server_hostname = SNI)
            
            while True:
                try:
                    self.socket.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    select.select([self.socket], [], [])
                except ssl.SSLWantWriteError:
                    select.select([], [self.socket], [])
            self.report.debug("Shook hands, TLS ready")
            
            return context
        else:
            self.socket = ssl.wrap_socket(self.socket)
        
        
    def connect(self):
        try:
            self.socket.connect(self.sa)
            self.report.timer('connect')
        except Exception as err:
            print("Connection to %s failed" % self.realip)
            raise Exception("Could not connect to host: %s" % str(err))
    
    def send(self, b):
        """ Send bytes (or convert string to bytes) to socket """
        if type(b) is str:
            self.socket.send(b.encode('ascii', errors = 'replace'))
        else:
            self.socket.send(b)
        
    def readline(self, recv_buffer=256, delim=b'\n'):
        """ Reads a line from a TCP (SSL?) socket, if presented within 60 seconds """
        buffer = b''
        data = True
        self.socket.setblocking(0)
        while data:
            try:
                data = self.socket.recv(recv_buffer)
                buffer += data
                self.bytes += len(data)
                while delim in buffer:
                    line, buffer = buffer.split(delim, 1)
                    yield line
            except BlockingIOError as err:
                ready = select.select([self.socket], [], [], 60)
                if ready[0]:
                    continue
                else:
                    raise Exception("Socket timeout after 60 seconds")
            except ssl.SSLWantReadError as err:
                ready = select.select([self.socket], [], [], 60)
                if ready[0]:
                    continue
                else:
                    raise Exception("Socket timeout after 60 seconds")
            except Exception as err:
                print(type(err))
                raise err
        
