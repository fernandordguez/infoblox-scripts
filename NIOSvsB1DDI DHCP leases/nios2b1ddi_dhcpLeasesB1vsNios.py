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
import pygsheets, json, gspread, gl, datetime
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2.service_account import Credentials
from csv import reader,writer
import csv
from configparser import ConfigParser

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

def creates_spreadsheet_if_doesnt_exist(SheetName):
    
    ib_service_account = input ('Enter your service account gor Gsheet')
    gc = pygsheets.authorize(service_account_file=ib_service_account)
    new = False
    try:
        sh = gc.open(SheetName)
        new = False
    except pygsheets.SpreadsheetNotFound as error:
        sh = gc.create(SheetName)
        sh.share(gl.mail_ib_serv_account, role='writer', type='user')
        sh.share(gl.myibmail, role='writer', type='user')
        sh.share('', role='reader', type='anyone')
        new = True

    return sh,new

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
        for lease in NIOSleases:
            NIOSleases[lease].pop('_ref')
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

def AUTH(apiKey,configfile,secret):
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
    with open('output.csv', 'w', newline='') as csvfile:
        #spamwriter = csv.writer(csvfile, delimiter='', quotechar=',', quoting=csv.QUOTE_MINIMAL)
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(['Network','NIOS Lease Count','BloxOne Lease Count'])
        #with open('output.csv', 'w', newline='') as f:
        #writer = csv.writer(f, delimiter=' ')
        #spamwriter = csv.writer(f, delimiter='"')
        #spamwriter = csv.writer(f)
        #spamwriter = csv.writer(f, delimiter=' ',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for l in reportLeases:
            countNIOSLeases = countNIOSLeases + reportLeases[l]['leasesNIOS']
            countCSPLeases = countCSPLeases + reportLeases[l]['leasesBloxOne']
            tempstr = ''
            warning = ''
            if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']!=0:                #Filter from the output those networks that didn´t have any leases in NIOS
                if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']==0:
                    warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs
                elif reportLeases[l]['leasesNIOS'] >= (reportLeases[l]['leasesBloxOne']*5):
                    warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs
                else:
                    warning = 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne'])
                
                print('Network :',l.ljust(18),'NIOS Lease Count :',str(reportLeases[l]['leasesNIOS']).ljust(8),warning,' ---> Review low number of leases')
            spamwriter.writerow([l,str(reportLeases[l]['leasesNIOS']),str(reportLeases[l]['leasesBloxOne'])])
        print('Total number of leases in NIOS :',countNIOSLeases)
        print('Total number of leases in BloxOne :',countCSPLeases)
    return None

printReport(reportLeases)

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

def comparesLeasesGridBackup_BloxOne(CSPleases, listSubnets, NIOSleases):                         # Receives NIOS leases as input
    for subnet in listSubnets:
        counterNIOS = 0
        counterBloxOne = 0
        for ipadd in CSPleases:
            if (IPv4Address(ipadd) in IPv4Network(subnet)):
                if (subnet in list(listSubnets.keys())):
                    if listSubnets[subnet]['network_view'] == CSPleases[ipadd]['network_view']:
                        counterBloxOne += 1
        for ipadd in NIOSleases:
            if (IPv4Address(ipadd) in IPv4Network(subnet)):
                if listSubnets[subnet]['network_view'] == NIOSleases[ipadd]['network_view']:
                    counterNIOS += 1
        listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
    return listSubnets


def creates_spreadsheet_if_doesnt_exist(SheetName):
    gc = pygsheets.authorize(service_account_file=gl.ib_service_account)
    new = False
    try:
        sh = gc.open(SheetName)
        new = False
    except pygsheets.SpreadsheetNotFound as error:
        sh = gc.create(SheetName)
        sh.share(gl.mail_ib_serv_account, role='writer', type='user')
        sh.share(gl.myibmail, role='writer', type='user')
        sh.share('', role='reader', type='anyone')
        new = True
    return sh,new


##########################################################
def main():
NIOSleases  = {}
reportLeases = {}
CSPleases = []
CSPlimit = 5000
NIOSlimit = 10000
args = get_args()
print(api_key)
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
    xmlfile = input('Please enter full path + filename of the Grid backup file \n')
    try:                                     
        NIOSleases = getNIOSleasesGridBackup(xmlfile)                                           # Leases from NIOS will be obtained from a Grid backup (default onedb.xml) ---> 'address': {'leasesNIOS', 'network_view', 'leasesBloxOne'}            
        reportLeases = comparesLeasesGridBackup_BloxOne(CSPleases, listSubnets, NIOSleases)          # All leases in CSP have been collected via B1DDI API interface
    except ApiException as e:
        print("Exception when calling LeaseApi->lease_list: %s\n" % e) 
else:
    print('Invalid option, please select XML or WAPI')

if args.output.lower() == 'log': 
    printReport(reportLeases)
elif args.output.lower() == 'gsheet':
    sheetname = input('Please enter name for the Gsheet')
else:
with open(args.csvfilbane, "wb") as csv_file:
    writer = csv.dictwriter(csv_file, delimiter=',')
    for line in reportLeases:
        writer.writerow(line)

if __name__ == "__main__":
# execute only if run as a script
    main()
    sys.exit()