import json
import requests
import ipaddress
from ipaddress import IPv4Address

with open('csvdata.json') as json_file:
    csvdata = json.load(json_file)

with open('dhcpranges.json') as json_file2:
    dhcpranges = json.load(json_file2)

dhcpranges = dhcpranges['dhcprange']
csvdata = csvdata ['hostrecord']

for host in csvdata:
    for range in dhcpranges:
        if range['network_view'] == host['network_view']: #Only matches on the same IP space are considered
            ipadd = host['addresses'].split(',')
            for addr in ipadd:
                if (IPv4Address(addr) >= IPv4Address(range['start_address'])) and (IPv4Address(addr) < IPv4Address(range['end_address'])):
                    print('Host record with address',addr,'falls into DHCP range',range['start_address'],'-',range['end_address'],'-',host['network_view'],'IP Space')