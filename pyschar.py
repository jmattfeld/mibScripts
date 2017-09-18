#!/usr/bin/python

"""
Usage:
    $ python pyschar.py [-mode(-s|-m)] [agent-IPv4] [input(singleOID|confFile)] [outputFilename]
"""
    
from __future__ import print_function

'''===================================================================================
pyschar.py

Description:
    script to excercise setting writeable string MIB leaves with special chars
    and produce a helpful result report

Prerequisites:
    Net-SNMP suite of command-line tools.
    The script here has been tested with version 5.7.2
    It is available from: http://net-snmp.org/

Parameters:
    mode (-s|-m):
        -s: exercises snmpset on a single OID, input must be a single OID
        -m: exercises snmpset on a list of OIDSs, input must be a .csv file
            containing a columnar list of OIDs with the header 'oid'
    agent-IPv4:
        the IP address of the SNMP manager agent.
    input:
        either an OID or a .conf file, depending on the mode (see above).
    outputFilename:
        filename of the output .csv to write the special char report to.
    
Author:
    Jeremy Mattfeld, jmattfel@ciena.com
==================================================================================='''

from subprocess import Popen, PIPE, check_output, check_call, CalledProcessError, STDOUT
from collections import OrderedDict
import json
import IPy
import string
import re
import csv
import sys


class Callonce(object):
# this is a decorator for functions we only want to execute once

    def __init__(self, f):
        self.f = f
        self.called = False


    def __call__(self, *args, **kwargs):
        if not self.called:
            self.called = True
            return self.f(*args, **kwargs)
        return


@Callonce
def csvHeaderWrite(writer, fieldnames, out):
    writer.writeheader()
    return


def instanceIndexGet(agentIp, obj):
    oid = check_output(['snmptranslate -On %s 2>/dev/null' %obj], shell=True)
    oid = oid.rstrip('\n')
    oidPlus = check_output(["snmpgetnext -v 2c -c public -Onq %s %s 2>/dev/null" % (agentIp, obj)],
                                shell=True)
    pattern = r'(.\d+)+'
    match = re.match(pattern, oidPlus)
    oidWithIndex = match.group(0)

    index = oidWithIndex.split(oid)[1]

    return index


def expectedStringLengthGet(obj):
    p1 = Popen(["snmptranslate -Td %s" %obj], stderr=STDOUT, shell=True, stdout=PIPE)
    p2 = Popen(["grep 'SYNTAX'"], shell=True, stdin=p1.stdout, stdout=PIPE)
    p1.stdout.close()

    output = p2.communicate()[0]
    truncOutput = output.split('..')[0]
    if '|' in truncOutput:
        minStringLength = truncOutput.split('|')[1]
    else:
        minStringLength = truncOutput.split('(')[1]

    return int(minStringLength)


def charPrefix(cmd, char):
    '''
    some special chars will not be allowed if they are alone or at the beginning of a string (test 1)
    BUT they MAY be allowed if they appear in a string with other alphanumeric characters.
    This function attempts to set a string type leaf with special a special char by prefixing
    it with the letter 'a'.  The logic is "So you will not take a '.' but will you take an 'a.'?"
    This constitutes test 2
    '''    
    #substitue the char exp with a an 'a'-prefixed char exp 
    if char == "'":
        newCmd = re.sub(' "%s" ' %char, ' "a%s" ' %char, cmd)
    elif char == "\\":
        newCmd = re.sub(" '%s' " %char, " 'a%s' " %char, cmd)
    else:
        newCmd = re.sub(" '\%s' " %char, " 'a%s' " %char, cmd)
    return newCmd


def charSandwich(cmd, char):
    '''
    And it goes on...
    This function says, "Ok, you will not take '-' or 'a-', but will you take 'a-b'?"
    This constitutes test 3
    '''    
    #substitute the char exp with an 'a'-'b' sandwiched exp
    if char == "'":
        newCmd = re.sub(' "%s" ' %char, ' "a%sb" ' %char, cmd)
    elif char == "\\":
        newCmd = re.sub(" '%s' " %char, " 'a%sb' " %char, cmd)
    else:
        newCmd = re.sub(" '\%s' " %char, " 'a%sb' " %char, cmd)
    return newCmd


def snmpSetHandler(ip, obj):
    
    failedChars = []

    inst = instanceIndexGet(ip, obj)

    for index in range(len(string.punctuation)):
        returnChar = False
        char = string.punctuation[index]
        #get the expected string length
        minStringLength = expectedStringLengthGet(obj)
        if minStringLength > 1:
            #setValue = char * minStringLength
            setValue = char * 8
        else:
            setValue = char

        #single/double quote handling
        if char == "'":
            setArgs = ' %s%s s "%s"' % (obj, inst, setValue)
        else:
            setArgs = " %s%s s '%s'" % (obj, inst, setValue)
        
        cmd = 'snmpset -v 2c -c private %s %s 2>/dev/null' %(ip, setArgs)

        '''
        the nested exception handling here will try setting each char using
        different formats until we get a successful snmpset packet or we tried
        all three formats without success.  See docstrings on charPrefix() and
        charSandwich() for more info
        '''
        #print(cmd)
        try:
            output = check_output(cmd, stderr=STDOUT, shell=True)
            #print(output)
        except CalledProcessError:
            returnChar = char + "1"
            preCmd = charPrefix(cmd, char)
            #print(preCmd)
            try:
                output = check_output(preCmd, stderr=STDOUT, shell=True)
                #print(output)
            except CalledProcessError:
                returnChar = char + "2"
                swCmd = charSandwich(cmd, char)
                #print(swCmd)
                try:
                    output = check_output(swCmd, stderr=STDOUT, shell=True)
                    #print(output)
                except CalledProcessError:
                    returnChar = char + "3"

        if returnChar:
            failedChars.append(returnChar)

    if not failedChars:
        return None
    else:
        return string.join(failedChars)


def specialCharReportSingleLineWrite(moduleAndLeaf, chars, out):

    # initialize csv dictwriter
    fieldnames = ['MODULE::leafName', 'disallowed-chars']
    writer = csv.DictWriter(out, fieldnames=fieldnames, dialect='singlequote') 
    csvHeaderWrite(writer, fieldnames, out)

    # write the csv line
    writer.writerow({'MODULE::leafName':moduleAndLeaf, 'disallowed-chars':chars})

    return
    

######
# main
######

#csv writer definitions
csv.register_dialect('singlequote', delimiter='\t', escapechar=None, doublequote=True, quoting=csv.QUOTE_MINIMAL, quotechar="'")


#command line arguments error checking
if (len(sys.argv) < 5) or (sys.argv[1] == '-h') or (sys.argv[1] == '--help'):
    if (len(sys.argv) < 5):
        print("ERROR: missing required argument")
    print(__doc__)
    sys.exit()

if (len(sys.argv) > 5):
    print("ERROR: unexpected argument " + sys.argv[3])
    print(__doc__)
    sys.exit()

mode = str(sys.argv[1])
if ((mode != '-s') and (mode != '-m')):
    print("ERROR: unrecognized mode argument " + mode)
    print(__doc__)
    sys.exit()

#check IPv4 address
agentIp = str(sys.argv[2])
try:
    IPy.IP(agentIp)
except:
    print("ERROR: you must use a valid SNMP-agent IPv4")
    print(__doc__)
    sys.exit()

#report file I/O
outFilename = str(sys.argv[4])
try:
    specialCharReport = open(outFilename, 'w')
except IOError:
    print("Error: %s cannot be opened for writing." % (outFilename))
    sys.exit()


if mode == '-s':
    #check OID
    singleOid = str(sys.argv[3])
    print('mode -s, processing snmpset on %s' % (singleOid))
    obj = check_output(['snmptranslate ' + singleOid], shell=True)
    disallowedChars = snmpSetHandler(agentIp, obj)

    if status != 0:
        print('snmpSetCall returned %d on %s\n' % (status, singleOid))
    sys.exit()
else:
    #mode is '-m' so get a dictionary of OIDs to process
    configFilename = str(sys.argv[3])

    print('mode -m, parsing %s for OIDs...\n' %configFilename)
    
    try:
        with open(configFilename) as jsonConfigFile:
            configData = json.load(jsonConfigFile, object_pairs_hook=OrderedDict)
    except IOError:
        print("Error: could not find file %s" % (configFilename))
        sys.exit()

    for key, val in configData.iteritems():
        module = key
        leaves = val
        for leaf in leaves:
            obj = module + "::" + leaf
            print(obj)
            disallowedChars = snmpSetHandler(agentIp, obj)
            print('disallowed chars: %s\n' %disallowedChars)

            specialCharReportSingleLineWrite(obj, disallowedChars, specialCharReport)
