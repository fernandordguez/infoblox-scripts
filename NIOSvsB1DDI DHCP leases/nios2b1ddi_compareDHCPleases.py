#!/usr/bin/python3
# run as: python3 nios2b1ddi_compareDHCPleases

import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
import json
#import os
import requests
import getpass

requests.packages.urllib3.disable_warnings()

NIOSleases = {}
CSPleases = {}

def getCSPleases(api_instance, limit):
    all_leases = []
    offset = 0
    leases = api_instance.lease_list(limit=limit)
    all_leases += leases.results
    while isinstance(leases, bloxonedhcpleases.LeasesListLeaseResponse) and (len(leases.results)==limit):
        offset += limit + 1
        leases = api_instance.lease_list(offset=str(offset), limit=str(limit))
        all_leases += leases.results
    return all_leases

def getNIOSleases(gm_ip, auth_usr, auth_pwd, limit):    #DHCP leases from NIOS WAPI. Request network and binding_state extra fields
    all_leases = []                                     #Supports paging (usually big number of results so multiple pages can be necessary)
    url = "https://" + gm_ip + "/wapi/v2.10/lease?_max_results=" + str(limit) + "&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1"
    leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
    all_leases += leases['result']
    while isinstance(leases['result'],list) and len(leases['result'])==limit:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
        all_leases += leases['result']
    return all_leases

def getSpaceNamesbySpaceId (headers):
    spaceNames = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers=headers)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        #tempDict[i['id']] = i['name']
        #spaceNames[i['id']] = tempDict
        spaceNames[i['id']] = i['name']
    return spaceNames

def compareLeasesNIOS_B1DDI(CSPleases, NIOSleases):
    # At this point, we have the DHCP leases from the NIOS CSV export
    # and the leases from BloxOne collected through the API
    spaces = getSpaceNamesbySpaceId(headers)
    cidr = ''
    tempLease = {}   
    countDHCPleases = {}
    for ipNIOS in NIOSleases:
        countDHCPleases.update({ipNIOS['network']: { 'counter' : 0, 'listLeases' : []}})
        
    for ipCSP in CSPleases:
        for ipNIOS in NIOSleases:
            if ipNIOS['binding_state'] in ['ACTIVE', 'STATIC'] :                                       #First condition, lease is active
                tempLease = {}   
                if ipCSP.address == ipNIOS['address']:                                                 #Second condition, same IP address in both CSP and NIOS environments                                     
                    cidr = ipNIOS['network']                
                    if spaces[ipCSP.space] == ipNIOS['network_view']:                                   #Third, same network view/IP space                    
                        tempLease['network'] = cidr
                        tempLease['adddress'] = ipCSP.address
                        tempLease['network_view'] = ipNIOS['network_view']
                        tempLease['id'] = ipCSP.client_id
                        tempLease['haGroup'] = ipCSP.ha_group
                        tempLease['macAddress'] = ipCSP.hardware
                        tempLease['hostId'] = ipCSP.host
                        tempLease['hostname'] = ipCSP.hostname
                        #tempLease['starts'] = ipCSP.starts
                        #tempLease['ends'] = ipCSP.ends
                        #tempLease['options'] = ipCSP.options
                        tempLease['state'] = ipCSP.state
                        countDHCPleases[ipNIOS['network']]['counter'] +=1
                        tempLease['countLeases'] = countDHCPleases[ipNIOS['network']]['counter']
                        countDHCPleases[ipNIOS['network']]['listLeases'].append(tempLease)
                    continue                                                     
    return countDHCPleases#

def AUTH(configfile):
    # Configure API key authorization: ApiKeyAuth and initialize some variables
    b1ddi = bloxone.b1ddi(cfg_file=configfile)
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix ['Authorization'] = 'token'
    configuration.api_key['Authorization'] = apiKey
    api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    return api_instance

def startProcess():
    apiKey = input('Please type your API Key to access CSP \n')
    gm_ip = input('Please type the IP address of the Grid Master \n')
    auth_usr = input('Please enter NIOS admin account \n')
    auth_pwd = getpass.getpass('Please enter your password \n')
    api_instance = AUTH(apiKey)
    headers = {'Authorization': 'Token ' + apiKey}
    CSPlimit = 5000
    NIOSlimit = 10000
    try:
        CSPleases = getCSPleases (api_instance, CSPlimit)                                      # All leases in CSP have been collected via B1DDI API interface
    except ApiException as e:
        print("Exception when calling LeaseApi->lease_list: %s\n" % e) 
    NIOSleases = getNIOSleases(gm_ip, auth_usr, auth_pwd, NIOSlimit)                            #Collect NIOS leases from NIOS WAPI
    countDHCPleases = compareLeasesNIOS_B1DDI( CSPleases, NIOSleases)                           #Compares CSP leases vs NIOS leases --> Identify those networks without leases after the go live
    for l in countDHCPleases.keys():                                                            #Prints networks and their active leases 
        print('Network :',l.ljust(20),'Lease Count :',countDHCPleases[l]['counter'])

startProcess()

if __name__ == "__main__":
    # execute only if run as a script
    main()
    sys.exit()

