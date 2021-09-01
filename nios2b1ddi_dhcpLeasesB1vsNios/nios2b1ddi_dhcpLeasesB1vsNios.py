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
from sty import fg, bg, ef, rs
import logging as log

requests.packages.urllib3.disable_warnings()

def getBloxOneLeases(LeasesApiInstance, CSPlimit, IPSpaces):
    tempLeases = []
    tempDict = {}
    CSPleases = {} 
    offset = 0
    leases = LeasesApiInstance.lease_list(limit=CSPlimit)
    tempLeases += leases.results
    while isinstance(leases, bloxonedhcpleases.LeasesListLeaseResponse) and (len(leases.results)==CSPlimit):
        offset += CSPlimit + 1
        leases = LeasesApiInstance.lease_list(offset=str(offset), limit=str(CSPlimit))
        tempLeases += leases.results
    for l in tempLeases:
        if (l.state.lower()) in ['active','backup','static','used']:
            tempDict['network_view'] = IPSpaces[l.space]
            CSPleases.update({l.address : tempDict})
    return CSPleases

def getSpaceNamesbySpaceId (B1Token):
    spaceNames = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers=B1Token)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        spaceNames[i['id']] = i['name']
    return spaceNames

def getSubnets(B1Token):
    spaceNames = getSpaceNamesbySpaceId(B1Token)
    listSubnetsCSP = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers=B1Token)
    listSubn = json.loads(response.content)['results']
    for subn in listSubn:
        cidr = subn['address'] + '/' + str(subn.pop('cidr'))
        subn.update({'network_view': spaceNames[subn.pop('space')]})
        listSubnetsCSP[cidr] = subn
    return listSubnetsCSP

def getCIDR(ip):
    subnets = getSubnets(B1Token).keys()
    ip = IPv4Address(ip)
    for s in subnets:
        range = IPv4Network(s)
        if ip in range:
            cidr = s
            return cidr


def comparesLeasesWAPI_BloxOne(CSPlimit, LeasesApiInstance, NIOSleases,listSubnets):                         # Receives NIOS leases as input
    CSPleases = [] # Collects BloxOne leases from REST API
    offset = 0                                                                              # Returns list of networks with NIOS and B1 leases compared
    leases = LeasesApiInstance.lease_list(limit=CSPlimit)
    CSPleases += leases.results
    while isinstance(leases, bloxonedhcpleases.LeasesListLeaseResponse) and (len(leases.results)==CSPlimit):
        offset += CSPlimit + 1
        leases = LeasesApiInstance.lease_list(offset=str(offset), limit=str(CSPlimit))
        CSPleases += leases.results
    for l in CSPleases:
        for subnet in listSubnets:
            if (IPv4Address(l.address) in IPv4Network(subnet)):
                if IPSpaces[l.space] == listSubnets[subnet]['network_view']:
                    listSubnets[subnet]['countCSP'] += 1 
                    listSubnets[subnet]['addressesCSP'].append(l.address)
                    listSubnets[subnet].update({'countCSP': listSubnets[subnet]['countCSP'], 'addressesCSP': listSubnets[subnet]['addressesCSP']})
                    reportLeases[subnet] = listSubnets[subnet]
            break
    return reportLeases

  



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

''' def getNIOSleasesWAPI(gm_ip, auth_usr, auth_pwd, NIOSlimit, listSubnets, IPSpaces):    #DHCP leases from NIOS WAPI. Request network and binding_state extra fields
    leases = {}
    tempObject = {}
    listSubnets = {}
    NIOSleases = []
    #Supports paging (usually big number of results so multiple pages can be necessary)
    url = "https://" + gm_ip + "/wapi/v2.10/lease?_max_results=" + str(NIOSlimit) + "&_paging=1&_return_as_object=1"
    leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
    NIOSleases += leases['result']
    while isinstance(leases['result'],list) and len(leases['result'])==NIOSlimit:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
        NIOSleases += leases['result']
    for l in NIOSleases:
        for ntwrk in listSubnets:
            if (IPv4Address(l['address']) in IPv4Network(ntwrk)):
                viewId = listSubnets[ntwrk]['network_view']
                if l['network_view'] == IPSpaces[listSubnets[ntwrk]['space']]:
                    counter = listSubnets[ntwrk]['countNIOS'] + 1
                    ipsNIOS = []
                    #if (l not in listSubnets[ntwrk]['addressesNIOS']): #Avoid duplicates when a FOA has two leases for the same address (1 per node)
                    if (listSubnets[ntwrk]['addressesNIOS'] is not None):
                        ipsNIOS = (listSubnets[ntwrk]['addressesNIOS']).append(l)
                    else:
                        listSubnets[ntwrk]['addressesNIOS'] = l
                    listSubnets[ntwrk].update({'countNIOS': counter,'addressesNIOS': ipsNIOS})
    for i in range(len(listSubnets)):
        tempObject['countNIOS'] = 0
        tempObject['countCSP'] = 0
        tempObject['network_view'] = listSubnets[i]['network_view']
        NIOSleases[listSubnets[i]['address']] = tempObject
    return NIOSleases '''

def getNIOSleasesWAPI(gm_ip, auth_usr, auth_pwd,NIOSlimit):    #DHCP leases from NIOS WAPI. Request network and binding_state extra fields
    leases = {}
    NIOSleases = []                                             #Supports paging (usually big number of results so multiple pages can be necessary)
    url = "https://" + gm_ip + "/wapi/v2.10/lease?_max_results=" + str(NIOSlimit) + "&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1"
    leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
    NIOSleases += leases['result']
    while isinstance(leases['result'],list) and len(leases['result'])==NIOSlimit:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
        NIOSleases += leases['result']
    return NIOSleases   # Returns NIOSleases --> ['_ref', 'address', 'binding_state', 'network', 'network_view']

def getNIOSleasesGridBackup (xmlfile):          # Returns NIOSleases extracted from Grid Backup file --> ['_ref', 'address', 'binding_state', 'network', 'network_view']
    listObjects = []            
    dictObject = {}
    listLeases = {}
    listSubnets = {}
    netViews = {}
    fxmml = open(xmlfile,'r')
    xml_content= fxmml.read()
    objects = xmltodict.parse(xml_content)
    objects = objects['DATABASE']['OBJECT']
    for obj in objects:
        dictObject = {}
        for item in (obj['PROPERTY']):
            dictObject[item['@NAME']] = item['@VALUE']
        listObjects.append(dictObject)
        # Separator
    for ob in listObjects:
        if ob['__type'] == '.com.infoblox.dns.network_view':
            netViews[ob['id']] = ob['name']
        # Separator       
    for ob in listObjects:
        if (ob['__type'] == '.com.infoblox.dns.lease') and (ob['binding_state'].lower() in ['active','static','backup','used']):
                tempObject = {}
                #tempObject['address'] = ob['ip_address']
                tempObject['network_view'] = netViews[ob['network_view']]
                tempObject['binding_state'] = ob['binding_state']
                listLeases[ob['ip_address']] = tempObject
        ''' elif ob['__type'] == '.com.infoblox.dns.network':
            cidr =  + '/' + ob['cidr']
            listSubnets[ob['address']] = {'address': ob['address'],'leasesNIOS': 0, 'network_view' : netViews[ob['network_view']], 'leasesBloxOne': 0} '''
    return listLeases


def compareLeasesNIOS_B1DDI(CSPleases, NIOSleases, B1token):
    # At this point, we have the DHCP leases from the NIOS CSV export
    # and the leases from BloxOne collected through the API or a Grid Backup
    spaces = getSpaceNamesbySpaceId(CSPtoken)
    
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

def printReport(reportLeases):
    countNIOSLeases = 0
    countCSPLeases = 0
    for l in reportLeases:
        countNIOSLeases = countNIOSLeases + reportLeases[l]['leasesNIOS']
        countCSPLeases = countCSPLeases + reportLeases[l]['leasesBloxOne']
        if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']!=0:                #Filter from the output those networks that didn´t have any leases in NIOS
            if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']==0:
                warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs
            elif reportLeases[l]['leasesNIOS'] >= (reportLeases[l]['leasesBloxOne']*5):
                warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs
            else:
                warning = 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne'])
            print('Network :',l.ljust(18),'NIOS Lease Count :',str(reportLeases[l]['leasesNIOS']).ljust(8),warning,' ---> Review low number of leases')
    print('Total number of leases in NIOS :',countNIOSLeases)
    print('Total number of leases in BloxOne :',countCSPLeases)
    return

def comparesLeasesWAPI_BloxOne(CSPleases, listSubnets, NIOSleases):                         # Receives NIOS leases as input
    for subnet in listSubnets:
        counterNIOS = 0
        counterBloxOne = 0
        for b1 in CSPleases:
            if (IPv4Address(b1) in IPv4Network(subnet)):
                if listSubnets[subnet]['network_view'] == CSPleases[b1]['network_view']:
                    counterBloxOne += 1
                    break
        for lease in NIOSleases:
            if (IPv4Address(lease['address']) in IPv4Network(subnet)):
                if listSubnets[subnet]['network_view'] == lease['network_view']:
                    counterNIOS += 1
                    break
            listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
    return listSubnets


def comparesLeasesWAPI_BloxOne(CSPleases, listSubnets, NIOSleases):                         # Receives NIOS leases as input
    for subnet in listSubnets:
        counterNIOS = 0
        counterBloxOne = 0
        for b1 in CSPleases:
            if (IPv4Address(b1) in IPv4Network(subnet)):
                if (subnet in list(listSubnets.keys())):
                    if listSubnets[subnet]['network_view'] == CSPleases[b1]['network_view']:
                        counterBloxOne += 1
        for lease in NIOSleases:
            if (IPv4Address(lease) in IPv4Network(subnet)):
                if listSubnets[subnet]['network_view'] == NIOSleases[lease]['network_view']:
                    counterNIOS += 1
        listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
    return listSubnets

##########################################################
def main():
    NIOSleases  = {}
    reportLeases = {}
    CSPleases = []
    CSPlimit = 5000
    NIOSlimit = 10000
    args = get_args()
    check_tenant(args.config)    
    b1ddi = bloxone.b1ddi(cfg_file=args.config)
    apiKey = b1ddi.api_key
    LeasesApiInstance = AUTH(apiKey)
    B1Token = {'Authorization': 'Token ' + apiKey}  
    IPSpaces = getSpaceNamesbySpaceId (B1Token)                                                             # Used to convert Space IDs into Space names --> Must match with the network_view in NIOS
    listSubnets = getSubnets(B1Token)                                                                       # List of all subnets in B1             --> ['network']{['address', 'network_view']}                         
    CSPleases = getBloxOneLeases(LeasesApiInstance, CSPlimit, IPSpaces)                                     # Collect BloxOne leases from B1DDI API  --> ['address']{['network_view',}
    
    if args.interface.lower() == 'wapi':                                    # if WAPI --> it will get NIOS leases from the Grid WAPI interface
        gm_ip = input('Please type the IP address of the Grid Master \n')
        auth_usr = input('Please enter NIOS admin account \n')
        auth_pwd = getpass.getpass('Please enter your password \n')
        try:
            NIOSleases = getNIOSleasesWAPI(gm_ip, auth_usr, auth_pwd, NIOSlimit)                                # Collect NIOS leases from NIOS WAPI     --> ['_ref', 'address', 'binding_state', 'network', 'network_view']
            reportLeases = comparesLeasesWAPI_BloxOne(CSPleases, listSubnets, NIOSleases)      # All leases in CSP have been collected via B1DDI API interface
        except ApiException as e:
            print("Exception when calling LeaseApi->lease_list: %s\n" % e) 
    elif args.interface.lower() == 'xml':                                   # if XML --> it will get NIOS leases from the Grid Backup (onedb.xml file)
        xmlfile = input('Please type full path + name of the Grid backup file \n')
        try:                                     
            NIOSleases = getNIOSleasesGridBackup(xmlfile)                                           # Leases from NIOS will be obtained from a Grid backup (default onedb.xml) ---> 'address': {'leasesNIOS', 'network_view', 'leasesBloxOne'}            
            reportLeases = comparesLeasesWAPI_BloxOne(CSPleases, listSubnets, NIOSleases)          # All leases in CSP have been collected via B1DDI API interface
        except ApiException as e:
            print("Exception when calling LeaseApi->lease_list: %s\n" % e) 
    else:
        print('Invalid option, please select XML or WAPI')
    printReport(reportLeases)

    
if __name__ == "__main__":
# execute only if run as a script
    main()
    sys.exit()