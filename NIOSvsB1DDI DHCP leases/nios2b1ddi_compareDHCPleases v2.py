#!/usr/bin/python3
# run as: python3 nios2b1ddi_compareDHCPleases -c config.ini -i wapi|onedb.xml

import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
import json
import requests
import getpass
import xmltodict
import argparse
from argparse import RawDescriptionHelpFormatter
import bloxone
import sys
import ipaddress
from ipaddress import IPv4Address, IPv4Network

requests.packages.urllib3.disable_warnings()

def getSpaceNamesbySpaceId (headers):
    spaceNames = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers=headers)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        spaceNames[i['id']] = i['name']
    return spaceNames

def getSubnets(headers):
    listSubnets = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers=headers)
    listSubn = json.loads(response.content)['results']
    for subn in listSubn:
        cidr = subn['address'] + '/' + str(subn['cidr'])
        listSubnets[cidr] = subn
    return listSubnets

def getCIDR(ip):
    subnets = getSubnets(headers).keys()
    ip = IPv4Address(ip)
    for s in subnets:
        range = IPv4Network(s)
        if ip in range:
            cidr = s
    return cidr

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

def check_tenant(config):
    """ Check Guard Rails """

    class BColors:
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        LINE = '\033[4m'

    b1platform = bloxone.b1platform(cfg_file=config)
    b1user = b1platform.get_current_user().json()['result']['name']
    b1tenant = b1platform.get_current_tenant()

    print(f'{BColors.GREEN}--------------------------------------------------{BColors.ENDC}')
    print(f'{BColors.YELLOW}\t\tW A R N I N G{BColors.ENDC}\n')
    print(f'{BColors.CYAN}\t{b1user.upper()}{BColors.ENDC}')
    print(f'\tIs wanting to access tenant:\n')
    print(f'{BColors.BOLD}\t{BColors.LINE}{b1tenant}{BColors.ENDC}')
    print(f'{BColors.GREEN}--------------------------------------------------{BColors.ENDC}\n')

    print(f'Key in yes to continue')
    answer = input()
    if answer.upper() == 'YES':
        #log.info(f'{b1user} is now accessing {b1tenant}')
        return
    else:
        sys.exit()

def getNIOSleasesWAPI(gm_ip, auth_usr, auth_pwd, limit):    #DHCP leases from NIOS WAPI. Request network and binding_state extra fields
    all_leases = []                                     #Supports paging (usually big number of results so multiple pages can be necessary)
    url = "https://" + gm_ip + "/wapi/v2.10/lease?_max_results=" + str(limit) + "&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1"
    leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
    all_leases += leases['result']
    while isinstance(leases['result'],list) and len(leases['result'])==limit:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
        all_leases += leases['result']
    return all_leases

def getNIOSleasesNIOSDB (xmlfile):
    leasesNIOSdb = []
    listObjects = []            
    dictObject = {}
    
    fxmml = open(xmlfile,'r')
    xml_content= fxmml.read()
    objects = xmltodict.parse(xml_content)
    objects = objects['DATABASE']['OBJECT']
    
    for obj in objects:
        dictObject = {}
        for item in (obj['PROPERTY']): 
            dictObject[item['@NAME']] = item['@VALUE']
        listObjects.append(dictObject)
        
    for ob in listObjects:
        tempObject = {}
        if ob['__type'] == '.com.infoblox.dns.lease':
            if ob['binding_state'].lower() in ['active','static','backup']:
                tempObject['address'] = ob['ip_address']
                cidr = getCIDR(tempObject['address'])
                tempObject['network'] = cidr
                if ob['network_view'] == '0':
                    tempObject['network_view'] = 'default'
                else:
                    tempObject['network_view'] = ob['network_view']
                tempObject['binding_state'] = ob['binding_state']
                tempObject['starts'] = ob['starts']
                tempObject['ends'] = ob['ends']
                leasesNIOSdb.append(tempObject)
    return leasesNIOSdb

def compareLeasesNIOS_B1DDI(CSPleases, NIOSleases, headers):
    # At this point, we have the DHCP leases from the NIOS CSV export
    # and the leases from BloxOne collected through the API or a Grid Backup
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
                        tempLease['network'] = ipNIOS['network']
                        tempLease['adddress'] = ipCSP.address
                        tempLease['network_view'] = ipNIOS['network_view']
                        tempLease['id'] = ipCSP.client_id
                        tempLease['haGroup'] = ipCSP.ha_group
                        tempLease['macAddress'] = ipCSP.hardware
                        tempLease['hostId'] = ipCSP.host
                        tempLease['hostname'] = ipCSP.hostname
                        tempLease['state'] = ipCSP.state
                        countDHCPleases[cidr]['counter'] +=1
                        tempLease['countLeases'] = countDHCPleases[cidr]['counter']
                        #countDHCPleases[cidr['listLeases'].append(tempLease)
                    continue                                                     
    return countDHCPleases #

def AUTH(apiKey):
    # Configure API key authorization: ApiKeyAuth and initialize some variables
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix ['Authorization'] = 'token'
    configuration.api_key['Authorization'] = apiKey
    api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    return api_instance

def get_args():
    # Parse arguments
    usage = ' -c b1config.ini [ -i IP_WAPI | xml ] [ --delimiter x ] [ --yaml <yaml file> ] [ --help ]'
    description = 'This is a NIOS CSV to Infoblox BloxOne DDI migration tool'
    epilog = '''
    sample b1config.ini
        [BloxOne]
        url = 'https://csp.infoblox.com'
        api_version = 'v1'
        api_key = 'API_KEY'
        '''
    par = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter,description=description,add_help=False,usage='%(prog)s' + usage,epilog=epilog)
    # Required Argument(s)
    required = par.add_argument_group('Required Arguments')
    req_grp = required.add_argument
    req_grp('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    req_grp('-i', '--interface', action="store", dest="interface", help="source from where NIOS data will be imported (WAPI | XML) ", required=True, default='onedb.xml')
    # Optional Arguments(s)
    optional = par.add_argument_group('Optional Arguments')
    opt_grp = optional.add_argument
    opt_grp('--delimiter', action="store", dest="csvdelimiter", help="Delimiter used in CSV data file", required=False)
    opt_grp('--yaml', action="store", help="Alternate yaml file for supported objects", default='objects.yaml')
    opt_grp('--debug', action='store_true', help=argparse.SUPPRESS, dest='debug', required=False)
    #opt_grp('--version', action='version', version='%(prog)s ' + __version__)
    opt_grp('-h', '--help', action='help', help='show this help message and exit')
    return par.parse_args(args=None if sys.argv[1:] else ['-h'])

##########################################################

args = get_args()
CSPleases = {}
CSPlimit = 5000
NIOSlimit = 10000
check_tenant(args.config)

b1ddi = bloxone.b1ddi(cfg_file=args.config)
apiKey = b1ddi.api_key
headers = {'Authorization': 'Token ' + apiKey}
api_instance = AUTH(apiKey)

if args.interface.lower() == 'wapi':
    gm_ip = input('Please type the IP address of the Grid Master \n')
    auth_usr = input('Please enter NIOS admin account \n')
    auth_pwd = getpass.getpass('Please enter your password \n')
    NIOSleases = {}
    NIOSleases = getNIOSleasesWAPI(gm_ip, auth_usr, auth_pwd, NIOSlimit)                            #Collect NIOS leases from NIOS WAPI
else:
    NIOSleases = []
    NIOSleases = getNIOSleasesNIOSDB(args.interface)                                                #Leases from NIOS will be obtained from a Grid backup (default onedb.xml)

try:
    CSPleases = getCSPleases (api_instance, CSPlimit)                                      # All leases in CSP have been collected via B1DDI API interface
except ApiException as e:
    print("Exception when calling LeaseApi->lease_list: %s\n" % e) 

countDHCPleases = compareLeasesNIOS_B1DDI(CSPleases, NIOSleases, headers)                           #Compares CSP leases vs NIOS leases --> Identify those networks without leases after the go live
for l in countDHCPleases.keys():                                                            #Prints networks and their active leases 
    print('Network :',l.ljust(20),'Lease Count :',countDHCPleases[l]['counter'])

if __name__ == "__main__":
# execute only if run as a script
    main()
    sys.exit()