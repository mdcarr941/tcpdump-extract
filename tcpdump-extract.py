#!/usr/bin/env python3
'''
Extract all unique hosts from the output of tcpdump.
'''

import re, sys, os

class Endpoint:
    def __init__(self, capture, wasSource):
      parts = capture.rpartition('.')
      self.host = parts[0]
      self.port = parts[2]
      self.src = wasSource
      self.dst = not wasSource

    def toTuple(self):
        return (self.host, self.port, self.src, self.dst)

class EndpointTable:
    def __init__(self, distinguishPorts=False):
        self.distinguishPorts = distinguishPorts
        self.table = {}
        self.header = ('host', 'port', 'appeared as source', 'appeared as destination')
        self.colWidths = list(map(lambda s: len(s), self.header))

    def updateColWidths(self, endpoint):
        hostWidth = len(endpoint.host)
        if hostWidth > self.colWidths[0]:
            self.colWidths[0] = hostWidth
        portWidth = len(endpoint.port)
        if portWidth > self.colWidths[1]:
            self.colWidths[1] = portWidth

    def search(self, capture):
        if self.distinguishPorts:
            return self.table[capture]
        else:
            parts = capture.rpartition('.')
            return self.table[parts[0]]

    def insert(self, capture, wasSource):
        try:
            endpoint = self.search(capture)
            if wasSource:
                endpoint.src = True
            else:
                endpoint.dst = True
        except KeyError:
            endpoint = Endpoint(capture, wasSource)
            if self.distinguishPorts:
                self.table[capture] = endpoint
            else:
                self.table[endpoint.host] = endpoint
            self.updateColWidths(endpoint)

    def printCol(self, colNum, data, file):
        dataStr = str(data)
        dataStrLen = len(dataStr)
        colWidth = self.colWidths[colNum]
        paddingLen = colWidth - dataStrLen if colWidth >= dataStrLen else 0
        print(dataStr + ',' + ' ' * paddingLen, end='', file=file)

    def printRow(self, tup, file):
        for colNum, data in enumerate(tup):
            if not self.distinguishPorts and 1 == colNum:
                continue
            self.printCol(colNum, data, file)
        print(os.linesep, end='', file=file)

    def print(self, file=sys.stdout):
        keys = list(self.table.keys())
        keys.sort()
        self.printRow(self.header, file)
        for key in keys:
            self.printRow(self.table[key].toTuple(), file)
        print('total unique endpoints:', len(keys), file=file)

def extractHosts(inStream=sys.stdin, distinguishPorts=False):
    hosts = EndpointTable(distinguishPorts)
    rgx = re.compile('IP\s+([^\s]+)\s+>\s+([^\s:]+)')
    for line in inStream:
        m = rgx.search(line)
        if None == m:
            continue
        hosts.insert(m.group(1), True)
        hosts.insert(m.group(2), False)
    return hosts

if __name__ == '__main__':
    if len(sys.argv) > 1 and '-p' == sys.argv[1]:
        distinguishPorts = True
    else:
        distinguishPorts = False
    extractHosts(distinguishPorts=distinguishPorts).print()