#!/usr/bin/python

"""===================================================================================
makemeone.py

Usage:
    $ python makemeone.py [agent-IPv4]

Description:
    script to create a one-of-everything configuration on a 6.x switch
    via the net-SNMP suite of command-line tools

Prerequisites:
    Net-SNMP suite of command-line tools.
    The script here has been tested with version 5.7.2
    It is available from: http://net-snmp.org/

    A valid directory of *.my MIB files reflecting the MIBs on your switch.
    The global config for the net-SNMP tools looks in /home/username/.snmp/mibs
    for *.my files.  The easiest way to set up the MIB file directory is to copy
    all the *.my files from each sub-directory <ciena|standard|wwp> directly to
    this location.

    makemeone.conf local configuration file in JSON format
    containing the index references and minimum leaves to create a table entry.
    rowStatus leaf must be the last object for each config entry
    with SOME-MODULE-MIB being the top-level object in the JSON structure.

    Example:

    {
        "SOME-MODULE-MIB":{
            "mibObjectEntry":{
                "index":{
                    "mibObjectIndexRef":"some index",
                    "mibObject2ndIndexRef":"another index"
                },
                "requiredMibLeaf1":{
                    "type":"i",
                    "value":"1"
                },
                "requiredMibLeaf2":{
                    "type":"o",
                    "value":"1.3.6.1..."
                },
                "mibEntryRowStatus":{
                    "type":"i",
                    "value":"3"
                }
            }
        }
    }
                

Parameters:
    agent-IPv4: the IP address of the SNMP manager agent.
    
Revision:
    version 1.0, 08/22/2017 -- original version.

Author:
    Jeremy Mattfeld, jmattfel@ciena.com
==================================================================================="""

from subprocess import Popen, PIPE, check_output, check_call, CalledProcessError, STDOUT
from collections import OrderedDict
import json
import IPy
import sys
import re


def rowStatusGet(ip, module, obj):
    cmd = "snmpget -v 2c -c public -Oqv %s %s::%s" % (ip, module, obj)

    try:
        output = check_output(cmd, shell=True)
        match = re.match('active',output,flags=0)
        if match == None:
            return True
        else:
            return False
    except CalledProcessError:
        print("ERROR getting value from %s::%s" % (module, obj))


def nameToOidIndexGet(string):
    print(string)

    index = ''

    for char in range(len(string)):
        dec = ord(string[char])
        index = index + '.' + str(dec)
    return index


def snmpSetCmdHandler(ip, module, entry, obj):
    setArgs = ''

    for key, val in obj.iteritems():
        data = val #this is an ordered dict
        #if key == 'index' then grab index(es) then continue")
        if key == 'index':
            index = ''
            for key, val in data.iteritems():
                if 'Name' in key:
                    index = nameToOidIndexGet(val)
                else:
                    index = index + '.' + val
            continue
        #else just build command str with [leaf.index type value]")
        else:
            leaf = key
            setObject = leaf + index
            for key, val in data.iteritems():
                if key == 'type':
                    syntaxType = val
                else: #this is the value to set leaf to
                    setValue = val
            setArgs = setArgs + " %s::%s %s %s" % (module, setObject, syntaxType, setValue)
            #we have all the data we need to start building the setArgs and the cmd str

    cmd = "snmpset -v 2c -c private %s %s" % (ip, setArgs)
    print(cmd)

    #send the snmpset command to the shell
    try:
        output = check_output(cmd, shell=True)
        print(output)
    except CalledProcessError:
        print("ERROR setting %s" % (entry))

    #this is check for createAndGo(4) rowStatus sets that automatically validate to active(1)
    needToValidate = rowStatusGet(ip, module, setObject)

    #if rowStatus set was an underCreation(3) it will need to be validated
    if needToValidate:

        setArgs = "%s::%s i 1" % (module, setObject)
        cmd = "snmpset -v 2c -c private %s %s" % (ip, setArgs)
        print(cmd)

        try:
            output = check_output(cmd, shell=True)
            print(output)
        except CalledProcessError:
            print("ERROR setting %s" % (obj))
        finally:
            return
    else:
        return


######
# main execution starts here
######

usage = '''Usage: $ python makemeone.py [agent-IPv4]'''

#command line arguments error checking
if (len(sys.argv) < 2) or (sys.argv[1] == '-h') or (sys.argv[1] == '--help'):
    if (len(sys.argv) < 2):
        print("ERROR: missing required argument\n%s" %usage)
        sys.exit()
    print(__doc__)
    sys.exit()

if (len(sys.argv) > 2):
    print("ERROR: unexpected argument %s\n%s" %(sys.argv[2], usage))
    sys.exit()

#check IPv4 address
agentIp = str(sys.argv[1])
try:
    IPy.IP(agentIp)
except:
    print("ERROR: you must use a valid SNMP-agent IPv4\n%s" %usage)
    sys.exit()

#file I/O
#configFilename = "makemeone.conf"
configFilename = "testing.conf"
try:
    with open(configFilename) as jsonConfigFile:
        configData = json.load(jsonConfigFile, object_pairs_hook=OrderedDict)
except IOError:
    print("Error: could not find file %s" % (configFilename))
    sys.exit()

#parse JSON config data
for key, value in configData.iteritems():
    module = key
    children = value #this is an ordered dict
    for key, value in children.iteritems():
        entry = key
        obj = value #this is an ordered dict
        #could send entry,obj to function here
        snmpSetCmdHandler(agentIp, module, entry, obj)
