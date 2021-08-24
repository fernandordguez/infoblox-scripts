#!/usr/bin/python3

# run as: python3 nios2b1ddi-.py -c b1config.ini -d Alldata.csv

from __future__ import print_function
import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
import json
import time
import os
import pandas as pd
import args
import csv
from ipaddress import IPv4Address,IPv4Network

def read_all_spreadsheet_values_from_csv_file(csvfile):
    dictdata = []
    newreader = csv.DictReader(open(csvfile, 'r'), quotechar='"', delimiter=",")
    for line in newreader:
        dictdata.append(line)
    return dictdata

def compareLeasesNIOS_B1DDI(csvfile, CSPleases, NIOSLeases):
    
    # At this point, we have the DHCP leases from the NIOS CSV export
    # and the leases from BloxOne collected through the API
    cidr = ''
    tempLease = {}   
    DHCPleases = {}
    for ipCSP in CSPleases:
        for ipNIOS in NIOSLeases:
            tempLease.clear                 #Initialize temp dictionary that would be the standawrd object of the resulting document (IP Leases)
            if ipCSP.address == ipNIOS['address*']:                                                 #First condition, same IP address in both CSP and NIOS environments                                     
                cidr = ipNIOS['description']
                try:    # Capture the error in case is not a valid IP address
                    if ipaddress.IPv4Address(ipNIOS['address*']) in ipaddress.IPv4Network(cidr):    #Second condition, the IP address belongs to the IP range                                                     
                        if ipCSP.space == ipNIOS['network_view']:                                   #Third, same network view/IP space                    
                            tempLease['active'] += 1
                            tempLease['id'] = ipCSP.client_id
                            tempLease['ha group']
                            tempLease['mac address'] = ipCSP.hardware
                            tempLease['host id'] = ipCSP.host
                            tempLease['hostname'] = ipCSP.hostname
                            tempLease['state'] = ipCSP.state                   
                except ipaddress.AddressValueError:
                    print('IP address format not valid')
                    continue

        if ipNIOS['source_lease_activity'].lower() == 'yes':                                        # Fourth, this DHCP lease record only if source_lease_activity=yes
            DHCPleases[cidr] = tempLease                                                        
    return DHCPleases


# Configure API key authorization: ApiKeyAuth
configuration = bloxonedhcpleases.Configuration()
configuration.api_key['Authorization'] = '79ee2a3d87ac1bdf3c6732c5b281b69d7bc354df2699af79eeb53649e41a6fff'
configuration.api_key_prefix['Authorization'] = 'token'
csvfile = 'DHCP_leases.csv'
#create an instance of the API class
apiKey = '79ee2a3d87ac1bdf3c6732c5b281b69d7bc354df2699af79eeb53649e41a6fff'
api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
try:
    # List Lease objects.
    api_response = api_instance.lease_list()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling LeaseApi->lease_list: %s\n" % e)

CSPleases = api_response.results                                        # All leases in CSP have been collected via B1DDI API interface
NIOSLeases = read_all_spreadsheet_values_from_csv_file(csvfile)         # We use a CSV export of the IP Leases in NIOS. A nice to have: support for REST API data as input

__main__":
    # execute only if run as a script
    main()
    sys.exit()