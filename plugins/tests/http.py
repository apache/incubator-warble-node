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
This is the HTTP(S) test suite for Apache Warble (incubating).
"""

import plugins.basics
import plugins.reports
import ssl
import re

class test:
    def __init__(self, globalConfig):
        self.config = globalConfig
        # Initialize a report object to store our findings
        self.report = plugins.reports.generic.template(self.config)
    
    def getCertData(cert):
        """ Collates certificate data for HTTPS checks """
        cn = ["none"]
        ou = ["none"]
        on = ["none"]
        if 'subjectAltName' in cert:
            cn = [x[1] for x in cert['subjectAltName']
                         if x[0].lower() == 'dns']
        else:
            cn =  [x[0][1] for x in cert['subject']
                            if x[0][0].lower() == 'commonname']
        ou =  [x[0][1] for x in cert['subject']
                            if x[0][0].lower() == 'organizationalunitname']
        on =  [x[0][1] for x in cert['subject']
                            if x[0][0].lower() == 'organizationname']
        return ("O=%s/OU=%s/CN=%s" % (str(on[0]) if len(on) > 0 else "Unknown", str(ou[0]) if len(ou) > 0 else "Unknown", str(cn[0]) if len(cn) > 0 else "Unknown"))
    
            
    def run(self, testParameters):
        request = plugins.basics.socket.tcp(testParameters, self.report)
        
        try:
            # Basic initialization and settings
            pid = testParameters.get('id')
            try:
                request.init(testParameters)
            except Exception as err:
                self.report.error('init', str(err))
            
            SSL = True if testParameters.get('type') == "https" else False # SSL/TLS request?
            ise = testParameters.get('ise', 999) # Which status code(s) to treat as Internal Server Error/failure
            method = testParameters.get('method', 'GET')
            vhost = testParameters.get('vhost', testParameters.get('host', 'localhost'))
            
            # Try to connect, if fail, report and return
            try:
                request.connect()
            except Exception as err:
                self.report.error('connect', str(err))
                return report
            
            # If SSL/TLS, initiate OpenSSL context
            if SSL:
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) # SSL, TLS1, TLS1.1 is largely deprecated now.
                context.verify_mode = ssl.CERT_OPTIONAL
                # Are we going to test the certificate for validity?
                if testParameters.get('checkcert', False) == True:
                    context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                context.load_default_certs()
                
                # Hope for a vhost setting, fall back to host name or 'localhost'
                request.socket = context.wrap_socket(sock.socket, server_hostname = vhost)
                
                self.report.debug("Connected, sending HTTPS payload.")
                request.cert = {}
                
                cert = request.socket.getpeercert(binary_form=False)
                cipher = request.socket.cipher()
                request.cert['protocol'] = cipher[1]
                request.cert['algorithm'] = cipher[0]
                if cert:
                    self.report.debug("Analyzing server certificate")
                    request.cert['notbefore'] = cert['notBefore'] if 'notBefore' in cert else None
                    request.cert['notafter'] = cert['notAfter']
                    request.cert['subject'] = self.getCertData(cert)
                    request.cert['issuer'] = "Validated Certificate Authority"
                    now = time.time() - toffset
                    if not pid in certDates or certDates[pid] <= (now - (86400)):
                        self.report.debug("Saving certificate data")
                    if testParameters.get('checkcert', False) == True:
                        first = ssl.cert_time_to_seconds(cert['notBefore'])
                        last = ssl.cert_time_to_seconds(cert['notAfter'])
                        if first > now:
                            self.report.error('certificate', "HTTPS certificate is not yet valid (notBefore is greater than today)")
                            return
                        if last < now:
                            self.report.error('certificate', "HTTPS certificate has expired (notAfter is less than today)")
                            return
                    if testParameters.get('warncert', False) == True:
                        last = ssl.cert_time_to_seconds(cert['notAfter'])
                        if last < (time.time() + (86400*7)):
                            days = int((last - time.time()) / 86400)
                            self.report.error('certificate', "HTTPS certificate is about to expire (%u days from now)!" % days)
                            return
    
            else:
                self.report.debug("Connected, sending HTTP payload.")
            request.send("%s %s HTTP/1.1\r\nConnection: close\r\nHost: %s\r\nUser-Agent: Apache Warble/%s\r\n\r\n" % (method.upper(), testParameters.get('uri', '/'), vhost, self.config.get('version')))
            self.report.timer('send')
            status = None
            ISE = None
            self.report.debug("Reading response header from server")
            for line in request.readline():
                line = str(line, 'utf-8')
                if not status:
                    self.report.timer('read')
                    match = re.match("HTTP/[0-9.]+ (\d+)(.*)", line, flags=re.I)
                    if match:
                        rc = int(match.group(1))
                        request.status_code = match.group(1) + match.group(2)
                        self.report.debug("Server response code: %s" % request.status_code)
                        if rc > ise and ise > 0:
                            ISE = line
                        status = True
                    else:
                        raise Exception("Invalid HTTP response received: " + line)
                    if not request.status_code:
                        request.status_code = line
                if line == "" or line == "\r":
                    break
                match = re.match("Server: (.+)", line, flags=re.I)
                if match:
                    request.server = match.group(1)
                    self.report.debug("Server software is: %s" % request.server)
                match = re.match("Location: (.+)", line, flags=re.I)
                if match:
                    request.location = match.group(1)
            
            # Did we catch an internal server error or equivalent? bork!
            if ISE:
                self.report.error('response', "Internal Server Error or equivalent bad message received: " + ISE)
                return
            
            self.report.debug("Reading response body (up to 10kb)")
            data = ""
            while len(data) < 10240:
                try:
                    bucket = request.socket.recv(1024)
                    if not bucket:
                        break
                    data += bucket
                except Exception as err:
                    break
            self.report.timer('data')
            if data:
                request.bytes += len(data)
            self.report.debug("All went well, closing socket.")
            request.socket.close()
            self.report.timer('end')
        except Exception as err:
            print("Caught error:" + str(err))
            self.report.error('response', str(err))
            
