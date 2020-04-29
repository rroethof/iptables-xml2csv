#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import csv

tree = ET.parse('./xml.xml')
root = tree.getroot()

f = open('./iptables.csv', 'w')
csvwriter = csv.writer(f, delimiter=';')

head = ['chain','source_ip','destination_ip','destination_protocol','connection_state','dport','dport_multi','actions']
csvwriter.writerow(head)

# loop door alle chains (input/output/forward/etc) en print deze
for chain in root.iter('chain'):
    print(chain.attrib)
    chainname = chain.get('name')

    for rule in chain.findall('rule'):
        row = []
        row.append(chainname)

        source = None
        destination = None
        proto = None
        state = None
        port = None
        multiport = None
        actions = None

        for match in rule.findall('.//match'):

            source = match.find('.//s')
            print ('' if source is None else 'source: '+source.text)

            destination = match.find('.//d')
            print ('' if destination is None else 'destination: '+destination.text)

            proto = match.find('.//p')
            print ('' if proto is None else 'protocol: '+proto.text)

        row.append('' if source is None else source.text)
        row.append('' if destination is None else destination.text)
        row.append('' if proto is None else proto.text)

        for state in rule.findall('.//state'):
            state = state.find('state')
            print('' if state is None else 'state: '+state.text)
        row.append('' if state is None else state.text)

        if proto is not None:
            for port in rule.findall('.//'+proto.text):
                port = port.find('.//dport')
                print ('' if port is None else 'port: '+port.text)
        row.append('' if port is None else port.text)

        for multiport in rule.findall('.//multiport'):

            ports = multiport.find('.//dports')
            print ('' if ports is None else 'ports: '+ports.text)
            row.append(' ' if ports is None else ports.text)

        for actions in rule.findall('.//actions'):
            for child in actions:
                print('' if child.tag is None else 'action: '+child.tag)
                row.append(' ' if child.tag is None else child.tag)


        csvwriter.writerow(row)
f.close()
