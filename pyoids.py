#!/usr/bin/python

'''===================================================================================
pyoids.py

Description:
    will parse local MIB trees for read-write and read-create objects

Prerequisites:
    Net-SNMP suite of command-line tools.
    The script here has been tested with version 5.7.2
    It is available from: http://net-snmp.org/

How to use:
    1. place MIBS of interest in the default search path for the net-snmp tools

    2. provide an input .csv with MIB module names and root OID's.
    NOTE: the module names and the .my filenames are usually identical but there
    are exceptions!!!
    Each module listed in the .csv must be available in the net-snmp search path.
    This is usually in /home/username/.snmp/mibs

    3. $ python pyoids.py

Author:
    Jeremy Mattfeld, jmattfel@ciena.com
==================================================================================='''

    
from __future__ import print_function
from subprocess import Popen, PIPE, check_output
from string import split, rstrip
import re
import csv
import sys


class callonce(object):
# this is a decorator for functions we only want to execute once

    def __init__(self, f):
        self.f = f
        self.called = False


    def __call__(self, *args, **kwargs):
        if not self.called:
            self.called = True
            return self.f(*args, **kwargs)
        return


@callonce
def csvHeaderWrite(writer, fieldnames, out):
    writer.writeheader()
    return


def mibTreeParse(entry, out):
    module = entry['moduleName']
    rootOid = str(entry['rootOid'])
    
    p1 = Popen(["snmptranslate -m +" + module + " -Tp " + rootOid + " 2>/dev/null"], 
               shell=True, stdout=PIPE)
    
    # sub-processes to filter for read-create and read-write string type nodes
    p2 = Popen(["egrep 'CR|RW'"], shell=True, stdin=p1.stdout, stdout=PIPE)
    p1.stdout.close()
    p3 = Popen(["grep 'String'"], shell=True, stdin=p2.stdout, stdout=PIPE)
    p2.stdout.close()
    
    output = str.splitlines(p3.communicate()[0])
    
    for row in output:
        csvLineWrite(row, module, out)

    return


def csvLineWrite(line, module, out):
    
    # initialize csv dictwriter
    fieldnames = ['access', 'module', 'leafName', 'oid']
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    csvHeaderWrite(writer, fieldnames, out)

    # field string formatting
    newOutput = split(line)
    l = len(newOutput)
    access = re.sub(r'-','',newOutput[l-3])
    leafName = re.sub(r'(\(\d+\))','',newOutput[l-1])

    # get oid
    p1 = Popen(["snmptranslate -On " + module + "::" + leafName + " 2>/dev/null"],
               shell=True, stdout=PIPE)
    oid = rstrip(p1.communicate()[0], '\n')

    # write the csv line
    writer.writerow({'access':access, 'module':module, 'leafName':leafName , 'oid':oid})

    return
    

# execution starts here

# file I/O
inFilename = raw_input('Enter the input .csv file: ')
rootOidsFile = open(inFilename)
rootOidsDictionary = csv.DictReader(rootOidsFile)
outFilename = 'mibLeaves.csv'
csvOut = open(outFilename, 'w')

print('reading ' + inFilename + '...')
print('parsing local MIB trees...')

# parse the MIB tree for each entry in input csv file
for entry in rootOidsDictionary:
    mibTreeParse(entry, csvOut)

print('done. output written to ' + outFilename)
