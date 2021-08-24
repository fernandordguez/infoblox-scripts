#!/usr/bin/python3
# run as: python3 nios2b1ddi-.py -c b1config.ini -d Alldata.csv

from __future__ import print_function
import logging
import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
import json
import time
import os
import pandas as pd
from pprint import isrecursive, pprint
import csv
from ipaddress import IPv4Address,IPv4Network
import gspread 

NIOSleases = {}

def readCSV_writeDict(csvobject):
    dictdata = []
    newreader = csv.DictReader(open(csvobject, 'r'), quotechar='"', delimiter=",")
    for line in newreader:
        dictdata.append(line)
    return dictdata

def compareLeasesNIOS_B1DDI(csvobject, CSPleases, NIOSleases):
    # At this point, we have the DHCP leases from the NIOS CSV export
    # and the leases from BloxOne collected through the API
    cidr = ''
    tempLease = {}   
    DHCPleases = {}
    api_response = {}
    
    for ipCSP in CSPleases:
        for ipNIOS in NIOSleases:
            tempLease.clear()                 #Initialize temp dictionary that would be the standawrd object of the resulting document (IP Leases)
            if ipCSP.address == ipNIOS['address*']:                                                 #First condition, same IP address in both CSP and NIOS environments                                     
                cidr = ipNIOS['description']
                try:    # Capture the error in case is not a valid IP address
                    if IPv4Address(ipNIOS['address*']) in IPv4Network(cidr):                        #Second condition, the IP address belongs to the IP range                                                     
                        if ipCSP.space == ipNIOS['network_view']:                                   #Third, same network view/IP space                    
                            if ipNIOS['source_lease_activity'].lower() == 'yes':                    # Fourth, this DHCP lease record only if source_lease_activity=yes
                                tempLease['address*'] = ipCSP.address,
                                tempLease['active'] += 1
                                tempLease['id'] = ipCSP.client_id,
                                tempLease['haGroup'] = ipCSP.ha_group,
                                tempLease['macAddress'] = ipCSP.hardware,
                                tempLease['hostId'] = ipCSP.host,
                                tempLease['hostname'] = ipCSP.hostname,
                                tempLease['starts'] = ipCSP.starts,
                                tempLease['ends'] = ipCSP.ends,    
                                tempLease['options'] = ipCSP.options,
                                tempLease['state'] = ipCSP.state            ,       
                except IPv4Address.AddressValueError:
                    print('IP address format not valid')
                    continue
            DHCPleases[cidr] = tempLease                                                        
    return DHCPleases

# Configure API key authorization: ApiKeyAuth and initialize some variables
configuration = bloxonedhcpleases.Configuration()
apiKey = '79ee2a3d87ac1bdf3c6732c5b281b69d7bc354df2699af79eeb53649e41a6fff'
#apiKey = input('"Please type your API Key to access CSP \n"')
configuration.api_key_prefix ['Authorization'] = 'token'
configuration.api_key['Authorization'] = apiKey
csvobject = 'NIOSleases.csv'                # NIOSleases do not require more preparation, just an ip lease from NIOS  #TO-DO could consider other sources like WAPI, JSON files or CSV import format
csvtempfile = 'temp.csv'
#create an instance of the API class
#apiKey = '<YOUR SERVICE or USER API KEY HERE>'

api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
try:
    # List Lease objects.
    api_response = api_instance.lease_list()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling LeaseApi->lease_list: %s\n" % e)

CSPleases = api_response.results                                        # All leases in CSP have been collected via B1DDI API interface = readCSV_writeDict(csvobject)         # We use a CSV export of the IP Leases in NIOS. A nice to have: support for REST API data as input
countDHCPleases = compareLeasesNIOS_B1DDI(csvobject, CSPleases, NIOSleases)

sh = importCSVFileToGsheet('Demo BloxOne Gsheet', CSPleases)
if __name__ == "__main__":
    # execute only if run as a script
    main()
    sys.exit()
