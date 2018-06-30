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
This is the main node script for Apache Warble (incubating)
"""
_VERSION = '0.1.0'

# Basic imports
import os
import sys
import stat
import time
import ruamel.yaml
import requests
import datetime
import argparse
import socket
import base64
import json

# Warble-specific libraries
import plugins.tests
import plugins.basics.misc
import plugins.basics.crypto

basepath = os.path.dirname(os.path.realpath(__file__))
configpath = "%s/conf/node.yaml" % basepath
hostname = socket.gethostname()

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description = "Run-time configuration options for Apache Warble (incubating)")
    parser.add_argument('--version', action = 'store_true', help = 'Print node version and exit')
    parser.add_argument('--test', action = 'store_true', help = 'Run debug unit tests')
    parser.add_argument('--fingerprint', action = 'store_true', help = 'Print fingerprint and exit')
    parser.add_argument('--wait', action = 'store_true', help = 'Wait for node to be fully registered on server before continuing')
    parser.add_argument('--config', type = str, help = 'Load a specific configuration file')
    args = parser.parse_args()
    
    # Miscellaneous CLI args
    if args.version: # --version: print version and exit
        print(_VERSION)
        sys.exit(0)
    
    # Specific conf file to load?
    if args.config:
        if os.path.exists(args.config):
            configpath = args.config
        else:
            print("Bork: --config passed to program, but could not find config file %s" % args.config)
            sys.exit(-1)

    
    # Init yaml, load configuration.
    # We use ruamel.yaml here, because it preserves the existing structure and
    # comments, unlike the traditional yaml library.
    yaml = ruamel.yaml.YAML()
    yaml.indent(sequence=4, offset=2)
    conftext = open(configpath).read()
    gconf = yaml.load(conftext)
    
    # On first run, or in the case of removing/forgetting the encryption
    # key pair, we need to generate a new pair for communication
    # purposes. This requires read+write access to the conf/ dir. In
    # subsequent runs, we can just load the existing (registered) key.
    privkey = None
    keypath = "%s/conf/privkey.pem" % basepath

    # If key exists, load it...
    if os.path.exists(keypath):
        if not args.fingerprint: # Skip this line if we just want the fingerprint
            print("INFO: Loading private key from %s" % keypath)
        try:
            privkey = plugins.basics.crypto.loadprivate(keypath)
        except Exception as err:
            print("ALERT: Could not read PEM file %s: %s" % (keypath, err))
            print("Warble has detected that the PEM file used for secure communications exists on disk, but cannot be read and/or parsed by the client. This may be due to either a permission error (warble requires that you run the application as the owner of the PEM file), or the file may have been corrupted. Further assistance may be available on our mailing list, users@warble.apache.org ")
            sys.exit(-1)
    # Otherwise, generate using the crypto lib and save in PEM format
    else:
        print("Generating 4096 bit async encryption key pair as %s..." % keypath)
        privkey = plugins.basics.crypto.keypair(bits = 4096)
        privpem = plugins.basics.crypto.pem(privkey)
        try:
            with open(keypath, "wb") as f:
                f.write(privpem)
                f.close()
        except OSError as err:
            print("ALERT: Could not write PEM file %s: %s" % (keypath, err))
            print("Warble is unable to write the key pair used for secure communications to disk. This may be a permission issue. As this file is crucial to continuous operation of the Warble node, the program cannot continue. If you are unable to address this issue, further assistance may be available via our mailing list, users@warble.apache.org")
            sys.exit(-1)
        os.chmod(keypath, stat.S_IWUSR|stat.S_IREAD) # chmod 600, only user can read/write
        print("Key pair successfully generated and saved!")
    if args.fingerprint:
        print(plugins.basics.crypto.fingerprint(privkey.public_key()))
        sys.exit(0)
    print("INFO: Starting Warble node software, version %s" % _VERSION)
    
    # Unit test mode?
    if args.test:
        print("Testing crypto library")
        plugins.basics.crypto.test()
                        
        print("Running unit tests...")
        import plugins.basics.unittests
        gconf['version'] = _VERSION
        plugins.basics.unittests.run(gconf)
        sys.exit(0)
    
    
    
    serverurl = gconf['client'].get('server')
    
    # If no api key has been retrieved yet, get one
    if gconf['client'].get('apikey', 'UNSET') == 'UNSET':
        if not serverurl:
            print("ALERT: Could not find the URL for the Warble server. Please set it in %s first." % configpath)
            sys.exit(-1)
        print("Uninitialized node, trying to register and fetch API key from %s" % serverurl)
        try:
            rv = requests.post('%s/api/node/register' % serverurl, json = {
                'version': _VERSION,
                'hostname': hostname,
                'pubkey': str(plugins.basics.crypto.pem(privkey.public_key()), 'ascii')
                })
            if rv.status_code == 200:
                payload = rv.json()
                apikey = payload['key']
                if payload['encrypted']:
                    apikey = str(plugins.basics.crypto.decrypt(privkey, base64.b64decode(apikey)), 'ascii')
                print("INFO: Fetched API key %s from server" % apikey)
                print("INFO: Registered with fingerprint: %s" % plugins.basics.crypto.fingerprint(privkey.public_key()))
                print("INFO: Please verify that the node request has this fingerprint when verifying the node.")
                gconf['client']['apikey'] = apikey
                # Save updated changes to disk
                yaml.dump(gconf, open(configpath, "w"))
            else:
                print("ALERT: Got unexpected status code %u from Warble server!")
                print(rv.text)
                sys.exit(-1)
        except Exception as err:
            print("ALERT: Could not connect to the Warble server at %s: %s" % (serverurl, err))
            sys.exit(-1)
    else:
        apikey = gconf['client'].get('apikey')
    
    # Now we check if we're eligible to do tests.
    # If --wait is passed, we'll pause and retry until we get our way.
    print("INFO: Checking for node eligibility...")
    while True:
        rv = requests.get('%s/api/node/status' % serverurl, headers = {'APIKey': apikey})
        if rv.status_code == 200:
            payload = rv.json()
            if payload.get('enabled'):
                break # We're enabled, yaaay
            else:
                if args.wait:
                    print("WARNING: Node not eligible yet, but --wait passed, so waiting 30 seconds...")
                    time.sleep(30)
                else:
                    print("WARNING: Node has not been marked as enabled on the server, exiting")
                    sys.exit(0)
        else:
            print("ALERT: Unexpected status code %u from Warble server!" % rv.status_code)
            print(rv.text)
            sys.exit(-1)
            
    ## Get tasks to perform
    print("INFO: Fetching tasks to perform")
    rv = requests.get('%s/api/node/tasks' % serverurl, headers = {'APIKey': apikey})
    if rv.status_code == 200:
        # Decrypt or die trying
        try:
            plain = plugins.basics.crypto.decrypt(privkey, base64.b64decode(rv.text))
        except:
            print("ALERT: Could not retrieve task data from Warble master due to an encryption error.")
            sys.exit(-1)
        # All good, load json payload and process!
        payload = json.loads(plain.decode('utf-8'))
        print("Got the following tasks:")
        for task in payload['tasks']:
            print("- %04u: %s" % (task['id'], task['name']))
    else:
        print("ALERT: Got status %u from warble master!" % rv.status_code)
        print(rv.text)
        sys.exit(-1)

    # Set node software version for tests
    gconf['version'] = _VERSION
    
    # Get local time offset from NTP
    toffset = plugins.basics.misc.adjustTime(gconf['misc']['ntpserver'])
    gconf['misc']['offset'] = toffset
    
    
    
