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
import ruamel.yaml
import requests
import datetime
import argparse

# Warble-specific libraries
import plugins.tests
import plugins.basics.misc
import plugins.basics.crypto

basepath = os.path.dirname(os.path.realpath(__file__))
configpath = "%s/conf/node.yaml" % basepath

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description = "Run-time configuration options for Apache Warble (incubating)")
    parser.add_argument('--version', action = 'store_true', help = 'Print node version and exit')
    parser.add_argument('--test', action = 'store_true', help = 'Run debug unit tests')
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
        print("Loading private key from %s" % keypath)
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

    # Unit test mode?
    if args.test:
        print("Testing crypto library")
        plugins.basics.crypto.test()
                
        print("Running unit tests...")
        import plugins.basics.unittests
        gconf['version'] = _VERSION
        plugins.basics.unittests.run(gconf)
        sys.exit(0)
    
    
    # If no app id set, get a unique app id for this node.
    if gconf['client'].get('appid', 'UNSET') == 'UNSET':
        gconf['client']['appid'] = plugins.basics.misc.appid()
        print("Uninitialized node, setting base App ID to %s" % gconf['client']['appid'])
        # Save updated changes to disk
        yaml.dump(gconf, open(configpath, "w"))
    
    # Set node software version for tests
    gconf['version'] = _VERSION
    
    # Get local time offset from NTP
    toffset = plugins.basics.misc.adjustTime(gconf['misc']['ntpserver'])
    gconf['misc']['offset'] = toffset
    
    # Connect to master (or at least try to), leave a calling card if not known.
    # TDB
    
    
