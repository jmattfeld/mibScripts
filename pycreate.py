#!/usr/bin/python

"""
======================================================================================
pycreate.py

Usage:
    $ python pycreate.py [agent-IPv4] [outputFilename]

Description:
    script to exercise special characters on read-create DisplayString leaves
    during mib table creation on a 6.x switch via the net-SNMP suite of command-line tools

Prerequisites:
    Net-SNMP suite of command-line tools.
    The script here has been tested with version 5.7.2
    It is available from: http://net-snmp.org/

    A valid directory of *.my MIB files reflecting the MIBS on your switch.
    The global config for the net-SNMP tools looks in /home/username/.snmp/mibs
    for *.my files.  The easiest way to set up the MIB file directory is to copy
    all the *.my files from each sub-directory <ciena|standard|wwp> directly to
    this location.

    pycreate.conf local configuration file in JSON format containing the minimum
    leaves to create a table entry plus the DisplayString type leaves that you want
    to exercise special chars on. DisplayString leaf needs the "value" attr set to
    null so the script knows to exercise a set of strings on this leaf.
    rowStatus leaf must be the last object for each config entry
    with SOME-MODULE-MIB being the top-level object in the JSON structure.

    Example:

    {
        "SOME-MODULE-MIB":{
            "mibObjectEntry":{
                "index":{
                    "mibObjectIndex":"1"
                },
                "requiredMibLeaf1":{
                    "type":"i",
                    "value":"1"
                },
                "requiredMibLeaf2":{
                    "type":"o",
                    "value":"1.3.6.1..."
                },
                "mibDisplayString":{
                    "type":"s",
                    "value":null
                }
                "mibEntryRowStatus":{
                    "type":"i",
                    "value":"3"
                }
            }
        }
    }
                

Parameters:
    agent-IPv4: the IP address of the SNMP manager agent.

    outputFilename: the .csv filename where you want the special char report saved.
    
Revision:
    original version 1.0, 08/24/2017

Author:
    Jeremy Mattfeld, jmattfel@ciena.com
==================================================================================="""

from subprocess import Popen, PIPE, check_output, check_call, CalledProcessError, STDOUT
from collections import OrderedDict
import re
import json
import IPy
import csv
import sys
import string


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


def rowStatusNotActiveCheck(ip, module, obj):
    '''
    The rowStatus leaf on a createAndGo will switch to valid(1) on its own.
    This function checks for that.
    '''
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
    '''
    Some tables are indexed with an arbritary OID string made of the decimal ascii
    values of the entry name.  This function takes the name and returns the
    corresponding OID index for that name.
    '''
    index = ''

    for char in range(len(string)):
        dec = ord(string[char])
        index = index + '.' + str(dec)
    return index


def expectedStringLengthGet(module, obj):
    '''
    Some string type leaves expect strings of a certain number of bytes.
    This function parses the MIB for this info.
    '''
    p1 = Popen(["snmptranslate -On -Td  %s::%s 2>/dev/null" % (module, obj)], shell=True, stdout=PIPE)
    p2 = Popen(["grep 'SYNTAX'"], shell=True, stdin=p1.stdout, stdout=PIPE)
    p1.stdout.close()

    output = p2.communicate()[0]
    truncOutput = output.split('..')[0]
    if '|' in truncOutput:
        minStringLength = truncOutput.split('|')[1]
    else:
        minStringLength = truncOutput.split('(')[1]

    return int(minStringLength)


def charInsert(cmd, char, iteration):
    '''
    some MIB tables have multiple string leaves we wish to test during a create.
    However, if we set all of them in one snmp packet, we will only get an error
    on the first object that fails.  So we need to test them individually (sigh).
    This function will insert the test char as the setValue on the object corresponding
    to the iteration of the command.
    '''    
    #substitue the iteration index with the test char 
    if char == "'":
        newCmd = re.sub(' "%s." ' %iteration, ' "%s" ' %char, cmd)
    else:
        newCmd = re.sub(" '%s.' " %iteration, " '%s' " %char, cmd)
    return newCmd


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


def tableEntryValidate(ip, module, setObject):
    setArgs = "%s::%s i 1" % (module, setObject)
    validateCmd = "snmpset -v 2c -c private %s %s" % (ip, setArgs)

    try:
        output = check_output(validateCmd, stderr=STDOUT, shell=True)
    except CalledProcessError:
        print("ERROR setting %s, cmd:%s" % (setObject, validateCmd))
    return


def snmpCreateTableEntryHandler(ip, module, key, obj, char):
    '''
    This is the workhorse function for this script.  It is called for every
    char in string.punctuation (all the special chars).

    Parameters:
        ip:     the ipv4 of the remote snmp agent
        module: the name of the MIB module we are currently working with
        key:    the table entry object
        obj:    data for the table entry from the .conf file
        char:   the special character we are testing

    Returns:
        failedChars:    a dictionary containing failed string objects as keys
                        with the failed char as the corresponding value for
                        that key.

                        returns None if snmpset was successful for this char.
    '''

    #initialize empty snmpset argument strings
    createArgs = ""
    setArgs = ""
    
    #initialize some values
    #returnChar = None
    rowStatusLeaf = False
    numStringLeaves = 0
    lastChar = (char == "~")

    #assume we will have a successful snmpset packet,
    #we will toggle this false if we need to.
    successfulPkt = True

    #initialize some return structures
    stringLeavesList = []
    failedChars = {}

    for key, val in obj.iteritems():
        data = val #this is an ordered dict
        #if key == 'index' then grab index(es) then continue")
        if key == 'index':
            index = ''
            #this catches multiple indexed instances and OID representations of entry names
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

        #special command string handling for " and ' strings
        if ((syntaxType == "s") and (setValue == None)):

            #initialize the dictionary entry and indexing list for this leaf
            failedChars[setObject] = ''
            stringLeavesList.append(setObject)
            
            numStringLeaves = numStringLeaves + 1
            
            #get the expected string length
            minStringLength = expectedStringLengthGet(module, leaf)
            if minStringLength > 1:
                setValue = char * minStringLength
            else:
                setValue = char

            if char == "'":
                createArgs = createArgs + ' %s::%s %s "%s."' % (module, setObject, syntaxType, numStringLeaves)
            else:
                createArgs = createArgs + " %s::%s %s '%s.'" % (module, setObject, syntaxType, numStringLeaves)
        else: #not a DisplayString type leaf
            createArgs = createArgs + ' %s::%s %s %s' % (module, setObject, syntaxType, setValue)
            #if the table has a rowStatus leaf this will be sure to catch it.
            rowStatusLeaf = True
    
    if numStringLeaves > 0:
        for iteration in range(numStringLeaves):
            '''
            the default cmd string just has placeholders for setValues on string leaves.
            This way we can set the special char to one leaf per iteration with the charInsert
            function and return useful info when a snmpset packet fails.
            '''
            defaultCmd = "snmpset -v 2c -c private %s %s" % (ip, createArgs)
            cmd = charInsert(defaultCmd, char, str(iteration + 1))

            '''
            the nested exception handling here will try setting each char using
            different formats until we get a successful snmpset packet or we tried
            all three formats without success.  See docstrings on charPrefix() and
            charSandwich() for more info
            '''
            try:
                output = check_output(cmd, stderr=STDOUT, shell=True)
            except CalledProcessError:
                returnChar = char + "1"
                failedChars[stringLeavesList[iteration]] = returnChar
                preCmd = charPrefix(cmd, char)
                try:
                    output = check_output(preCmd, stderr=STDOUT, shell=True)
                except CalledProcessError:
                    returnChar = char + "2"
                    failedChars[stringLeavesList[iteration]] = returnChar
                    swCmd = charSandwich(cmd, char)
                    try:
                        output = check_output(swCmd, stderr=STDOUT, shell=True)
                    except CalledProcessError:
                        successfulPkt = False
                        returnChar = char + "3"
                        failedChars[stringLeavesList[iteration]] = returnChar

            if rowStatusLeaf:
                '''We have discovered that some tables always exist and therefore do not have
                rowStatus leaves.  So now we will only direct execution to this block for
                tables that do have them.  Also, the only tables with with string leaves that
                we would want to exercise would come to this if statement so we should not have
                to worry about the code in the outer else branch.
                '''
                if successfulPkt: 
                    #we had a successful packet so lets check table entry status, if its not active(1) then we 
                    if rowStatusNotActiveCheck(ip, module, setObject):
                        tableEntryValidate(ip, module, setObject)
                
                    if not lastChar:
                        #now destroy it so we can create it again
                        #try destroy(6) first, if value is invalid, we will try invalid(4)
                        setArgs = "%s::%s i 6" % (module, setObject)
                        destroyCmd = "snmpset -v 2c -c private %s %s" % (ip, setArgs)

                        try:
                            output = check_output(destroyCmd, shell=True, stderr=STDOUT)
                        except CalledProcessError:
                            try:
                                setArgs = "%s::%s i 4" % (module, setObject)
                                destroyCmd = "snmpset -v 2c -c private %s %s" % (ip, setArgs)
                                output = check_output(destroyCmd, shell=True, stderr=STDOUT)
                            except CalledProcessError:
                                print("ERROR deleting %s, cmd:%s" % (setObject, destroyCmd))

                elif lastChar:
                    '''
                    We are on the last char but we did not have a successful packet, therefore
                    we do not have a valid table entry (we destroyed it after the last successful create).
                    We need to perform a create using a trusted command string to make sure that
                    we have an entry we can exercise post-create sets on.  The defaultCmd string
                    should work (string arguments are '1.' '2.' ...).
                    '''
                    try:
                        output = check_output(defaultCmd, stderr=STDOUT, shell=True)
                    except CalledProcessError:
                        print("ERROR setting %s, cmd:%s" % (setObject, defaultCmd))
                        
    else:
        '''
        This entry has no display string leaves to set but we need to create it anyway
        probably so that other dependent table creates will be successful.
        '''
        if rowStatusNotActiveCheck(ip, module, setObject):
            cmd = "snmpset -v 2c -c private %s %s" % (ip, createArgs)

            try:
                output = check_output(cmd, stderr=STDOUT, shell=True)
            except CalledProcessError:
                print("ERROR setting %s, cmd:%s" % (setObject, cmd))
        else:
            #this rowStatus is active with no strings to set so let's bug out
            return None

    return failedChars


def snmpPostCreateTableEntryHandler(ip, module, key, obj, char):
    '''
    This function is similar to the one ablove except it only exercises
    post-create sets on allready created tables.

    Parameters:
        ip:     the ipv4 of the remote snmp agent
        module: the name of the MIB module we are currently working with
        key:    the table entry object
        obj:    data for the table entry from the .conf file
        char:   the special character we are testing

    Returns:
        failedChars:    a dictionary containing failed string objects as keys
                        with the failed char as the corresponding value for
                        that key.

                        returns None if snmpset was successful for this char.
    '''

    #initialize empty snmpset argument strings
    setArgs = ""
    
    #initialize some values
    numStringLeaves = 0

    #initialize some return structures
    stringLeavesList = []
    failedChars = {}

    for key, val in obj.iteritems():
        data = val #this is an ordered dict
        #if key == 'index' then grab index(es) then continue")
        if key == 'index':
            index = ''
            #this catches multiple indexed instances and OID representations of entry names
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

        #special command string handling for " and ' strings
        if ((syntaxType == "s") and (setValue == None)):

            #initialize the dictionary entry and indexing list for this leaf
            failedChars[setObject] = ''
            stringLeavesList.append(setObject)
            
            numStringLeaves = numStringLeaves + 1
            
            #get the expected string length
            minStringLength = expectedStringLengthGet(module, leaf)
            if minStringLength > 1:
                setValue = char * minStringLength
            else:
                setValue = char

            if char == "'":
                setArgs = setArgs + ' %s::%s s "%s."' % (module, setObject, numStringLeaves)
            else:
                setArgs = setArgs + " %s::%s s '%s.'" % (module, setObject, numStringLeaves)
    
    if numStringLeaves > 0:
        for iteration in range(numStringLeaves):
            '''
            the default cmd string just has placeholders for setValues on string leaves.
            This way we can set the special char to one leaf per iteration with the charInsert
            function and return useful info when a snmpset packet fails.
            '''
            defaultCmd = "snmpset -v 2c -c private %s %s" % (ip, setArgs)
            cmd = charInsert(defaultCmd, char, str(iteration + 1))

            '''
            the nested exception handling here will try setting each char using
            different formats until we get a successful snmpset packet or we tried
            all three formats without success.  See docstrings on charPrefix() and
            charSandwich() for more info
            '''
            try:
                output = check_output(cmd, stderr=STDOUT, shell=True)
            except CalledProcessError:
                returnChar = char + "1"
                failedChars[stringLeavesList[iteration]] = returnChar
                preCmd = charPrefix(cmd, char)
                try:
                    output = check_output(preCmd, stderr=STDOUT, shell=True)
                except CalledProcessError:
                    returnChar = char + "2"
                    failedChars[stringLeavesList[iteration]] = returnChar
                    swCmd = charSandwich(cmd, char)
                    try:
                        output = check_output(swCmd, stderr=STDOUT, shell=True)
                    except CalledProcessError:
                        returnChar = char + "3"
                        failedChars[stringLeavesList[iteration]] = returnChar

    return failedChars


def specialCharReportSingleLineWrite(module, duringCreateChars, postCreateChars, out):
    '''
    This function is called to write a single line in the outputFilename.csv
    '''

    # initialize csv dictwriter
    fieldnames = ['MODULE::leafName', 'disallowed-chars(CREATE)', 'disallowed-chars(POST-CREATE)']
    writer = csv.DictWriter(out, fieldnames=fieldnames, dialect='singlequote') 
    csvHeaderWrite(writer, fieldnames, out)

    # write the csv line
    writer.writerow({'MODULE::leafName':string.rstrip(module,'\n'), 'disallowed-chars(CREATE)':duringCreateChars, 'disallowed-chars(POST-CREATE)':postCreateChars})

    return


######
# main
######

#misc definitions
csv.register_dialect('singlequote', delimiter='\t', escapechar=None, doublequote=True, quoting=csv.QUOTE_MINIMAL, quotechar="'")
numSpecial = len(string.punctuation)
usage = '''Usage: $ python pycreate.py [agent-IPv4] [outputFilename]'''
numArgs = len(sys.argv)


#command line arguments error checking
if (numArgs == 2) and ((sys.argv[1] == '-h') or (sys.argv[1] == '--help')):
    print(__doc__)
    sys.exit()
elif (numArgs < 3):
    print("ERROR: missing required argument\n%s" %usage)
    sys.exit()

if (len(sys.argv) > 3):
    print("ERROR: unexpected argument %s\n%s" %(sys.argv[3], usage))
    sys.exit()

#check IPv4 address
agentIp = str(sys.argv[1])
try:
    IPy.IP(agentIp)
except:
    print("ERROR: you must use a valid SNMP-agent IPv4\n%s" %usage)
    sys.exit()


#file I/O
#configFilename = "pycreate.conf"
configFilename = "test.conf"
try:
    with open(configFilename) as jsonConfigFile:
        configData = json.load(jsonConfigFile, object_pairs_hook=OrderedDict)
except IOError:
    print("Error: could not find file %s" % (configFilename))
    sys.exit()

outFilename = str(sys.argv[2])
try:
    specialCharReport = open(outFilename, 'w')
except IOError:
    print("Error: %s cannot be opened for writing." % (outFilename))
    sys.exit()


#parse JSON config data
for key, value in configData.iteritems():
    module = key
    children = value #this is an ordered dict
    for k, v in children.iteritems():
        entry = k
        obj = v #this is an ordered dict
        
        flag = False
        print("\n%s::%s" %(module, entry))

        #for each special char
        duringCreateReport = {}
        postCreateReport = {}
        print("exercising special chars DURING table create...")
        for index in range(numSpecial):
            temp = snmpCreateTableEntryHandler(agentIp, module, entry, obj, string.punctuation[index])
            if temp:
                if (flag == False):
                    duringCreateReport = temp.copy()
                    flag = True
                else:    
                    for key, value in duringCreateReport.iteritems():                        
                        duringCreateReport[str(key)] = duringCreateReport[str(key)] + temp[str(key)]

        flag = False
        print("exercising special chars POST create...")
        for index in range(numSpecial):
            temp = snmpPostCreateTableEntryHandler(agentIp, module, entry, obj, string.punctuation[index])
            if temp:
                if (flag == False):
                    postCreateReport = temp.copy()
                    flag = True
                else:    
                    for key, value in postCreateReport.iteritems():                        
                        postCreateReport[str(key)] = postCreateReport[str(key)] + temp[str(key)]
                        
        #write csv report
        for key, value in duringCreateReport.iteritems():
            moduleAndLeaf = "%s::%s" %(module, key)

            if not duringCreateReport[key]:
                disallowedCharsDuringCreate = 'None'
            else:
                disallowedCharsDuringCreate = string.join(value)

            if not postCreateReport[key]:
                disallowedCharsPostCreate = 'None'
            else:
                postCreateData = postCreateReport[key]
                disallowedCharsPostCreate = string.join(postCreateData)

            specialCharReportSingleLineWrite(moduleAndLeaf, disallowedCharsDuringCreate,
                                             disallowedCharsPostCreate, specialCharReport)

jsonConfigFile.close()
specialCharReport.close()
