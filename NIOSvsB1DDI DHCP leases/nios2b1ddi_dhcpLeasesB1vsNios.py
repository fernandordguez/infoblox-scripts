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
import sty
from sty import fg, bg, ef, rs
import logging as log
import json, gspread, datetime
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2.service_account import Credentials
from csv import reader,writer
import csv

requests.packages.urllib3.disable_warnings()

def AUTH(apiKey):
    # Configure API key authorization: ApiKeyAuth and initialize some variables
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix ['Authorization'] = 'token'
    configuration.api_key['Authorization'] = apiKey
    api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    return api_instance

def check_tenant(config):                           # It diesplays the CSP tenant we´re accessing and will validate our API key. Useful to avoid accessing the wrong tenant by mistake
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
        return b1tenant
    else:
        sys.exit()


def getBloxOneLeases(LeasesApiInstance, CSPlimit, IPSpaces):
    templeases = []
    tempDict = {}
    CSPleases = {} 
    offset = 0
    leases = LeasesApiInstance.lease_list(limit=CSPlimit)
    templeases += leases.results
    while isinstance(leases, bloxonedhcpleases.LeasesListLeaseResponse) and (len(leases.results)==CSPlimit):
        offset += CSPlimit + 1
        leases = LeasesApiInstance.lease_list(offset=str(offset), limit=str(CSPlimit))
        templeases += leases.results
    for l in templeases:
        tempDict = {}
        if l.state.lower() in ['issued','used']:    #  --->   In BloxOne LEases States are Issued, Used or Freed
            tempDict['network_view'] = IPSpaces[l.space]
        CSPleases.update({l.address : tempDict})
    return CSPleases

def getGridBackupleases (xmlfile):          # Returns NIOSleases extracted from Grid Backup file --> ['_ref', 'address', 'binding_state', 'network', 'network_view']
    listObjects = []            
    dictObject = {}
    NIOSleases = {}
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
        if (ob['__type'] == '.com.infoblox.dns.lease') and (ob['binding_state'].lower() in ['active','static']):
            tempObject = {}
            tempObject['network_view'] = netViews[ob['network_view']]
            NIOSleases.update({ob['ip_address']: tempObject})
    return NIOSleases

def getSpaceNamesbySpaceId (B1Token):               # It gets the name of the IP Spaces from the Space Id. Grid DB uses integers to identify the network views which is not helpful (ID for 'default' = 0)
    spaceNames = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers=B1Token)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        spaceNames[i['id']] = i['name']
    return spaceNames

def getSubnets(B1Token):                            #It will get all the networks available in CSP for this tenant
    spaceNames = getSpaceNamesbySpaceId(B1Token)
    listSubnetsCSP = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers=B1Token)
    listSubn = json.loads(response.content)['results']
    for subn in listSubn:
        cidr = subn['address'] + '/' + str(subn.pop('cidr'))
        subn.update({'network_view': spaceNames[subn.pop('space')]})
        listSubnetsCSP[cidr] = subn
    return listSubnetsCSP                           #Output is a dictonary with the networks as indexes. This objects will be the basis for the comparson between NIOS and BloxOne DHCP leases.
                                                    #MLeases will be assigned to their correponding subnet (within the correct ip space / network view) where every leases will increase the counters
                                                    # This process will be performed both for NIOS and BloxOne to get clear picture of the leases being handled by CSP after the migration from NIOS
                                                    # Which might facilitate the detection of potential issues after the go live

def CSVtoGsheet(SheetName,csvfilename):
    ib_service_account = input ('Path + Filename of your service account for Google Sheets service \n')
    gc = gspread.service_account(ib_service_account)
    mail_ib_serv_account = "vodafone-serviceaccount@vodafone-securen-1601572791755.iam.gserviceaccount.com"
    myibmail = "frodriguez@infoblox.com"
    content = open(csvfilename,'r').read()
    try:
        sh = gc.open(SheetName)
    except gspread.exceptions.SpreadsheetNotFound as error:
        sh = gc.create(SheetName)
        sh.share(mail_ib_serv_account, role='writer', perm_type='user')
        sh.share(myibmail, role='writer', perm_type='user')
        sh.share('', role='reader', perm_type='anyone')
    gc.import_csv(sh.id, content)
    print ("Gsheet available on the URL", sh.url)
    return

def getLeasesWAPI(gm_ip, auth_usr, auth_pwd,NIOSlimit):    #DHCP leases from NIOS WAPI. Request network and binding_state extra fields
    leases = {}
    tempDict = {}
    NIOSleases = {}
    templeases = []                                            #Supports paging (usually big number of results so multiple pages can be necessary)
    url = "https://" + gm_ip + "/wapi/v2.10/lease?_max_results=" + str(NIOSlimit) + "&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1"
    leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
    templeases = leases['result']
    while isinstance(leases['result'],list) and len(leases['result'])==NIOSlimit:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
        templeases += leases['result']
        #Supports
    for l in templeases:
        if (l['state'].lower()) in ['active','static']:
            tempDict = {}
            tempDict['network_view'] = IPSpaces[l['space']]
            NIOSleases.update({l['address'] : tempDict})
    return NIOSleases   # Returns NIOSleases --> ['_ref', 'address', 'binding_state', 'network', 'network_view']

''' def printReport(reportLeases,repType):
    countNIOSLeases = 0
    countCSPLeases = 0
    if repType != "log":    # With log option, we don´t need to created the CSV file so this lines are not required in that case
        with open('output.csv', 'w', newline='') as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=',')
            spamwriter.writerow(['Network','NIOS Lease Count','BloxOne Lease Count'])
            for l in reportLeases:
                countNIOSLeases = countNIOSLeases + reportLeases[l]['leasesNIOS']
                countCSPLeases = countCSPLeases + reportLeases[l]['leasesBloxOne']
                warning = ''
                if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']!=0:                #Filter from the output those networks that didn´t have any leases in NIOS
                    if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']==0:
                        warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs + ' ---> Review low number of leases'
                    elif reportLeases[l]['leasesNIOS'] >= (reportLeases[l]['leasesBloxOne'])*4:
                        warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs + ' ---> Review low number of leases'
                    else:
                        warning = 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne'])
                    print('Network :',l.ljust(18),'NIOS Lease Count :',str(reportLeases[l]['leasesNIOS']).ljust(8),warning)
                if repType != "log": 
                    spamwriter.writerow([l,str(reportLeases[l]['leasesNIOS']),str(reportLeases[l]['leasesBloxOne'])])
    print('Total number of leases in NIOS :',countNIOSLeases)
    print('Total number of leases in BloxOne :',countCSPLeases)
    return None '''

def printReport(reportLeases,repType,SheetName):
    countNIOSLeases = 0
    countCSPLeases = 0
    csvfilename = 'output.csv'
    if repType != "log":    # With log option, we don´t need to created the CSV file so this lines are not required in that case
        csvfile = open('output.csv', 'w', newline='')
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(['Network','NIOS Lease Count','BloxOne Lease Count','Comments'])
    for l in reportLeases:
        review = ''
        countNIOSLeases = countNIOSLeases + reportLeases[l]['leasesNIOS']
        countCSPLeases = countCSPLeases + reportLeases[l]['leasesBloxOne']
        warning = ''
        if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']!=0:                #Filter from the output those networks that didn´t have any leases in NIOS
            if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']==0:
                warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs + ' ---> Review low number of leases'
                review = 'Review BloxOne number of leases'
            elif reportLeases[l]['leasesNIOS'] >= (reportLeases[l]['leasesBloxOne'])*2:
                warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs + ' ---> Review low number of leases'
                review = 'Review BloxOne number of leases'
            else:
                warning = 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne'])
            print('Network :',l.ljust(18),'NIOS Lease Count :',str(reportLeases[l]['leasesNIOS']).ljust(8),warning)
        if repType != "log": 
            spamwriter.writerow([l,str(reportLeases[l]['leasesNIOS']),str(reportLeases[l]['leasesBloxOne']),review])
    if repType == "gsheet":    # With log option, we don´t need to created the CSV file so this lines are not required in that case
        CSVtoGsheet(SheetName,csvfilename)
    print('Total number of leases in NIOS :',countNIOSLeases)
    print('Total number of leases in BloxOne :',countCSPLeases)
    
    csvfile.close()
    return None


#printReport(reportLeases, "xml")

## TO-DO: The following functions comparesLeasesWAPI_BloxOne and comparesLeasesGridBackup_BloxOne are nearly identical but there are some key 
## differences on the estructure of the objects that causes data compatibility issues (mainly because the data is extracted from the DB and fromm the WAPI which is used to
# a considerable difference. The aim is to standardize the data estructures used to collect NIOS leases to eventually consolidate these two functions into one 

def comparesLeasesWAPI_BloxOne(CSPleases, listSubnets, NIOSleases):                             # Receives NIOS leases as input (obtained via WAPI from the GM)
    for subnet in listSubnets:                                                                   # It also receives a list of the Subnets/Networks to use it as basis for the classification 
        counterNIOS = 0
        counterBloxOne = 0
        for ipadd in CSPleases:
            if (IPv4Address(ipadd) in IPv4Network(subnet)):                                         # With the ipaddress library, we can validate that the IP address of the leases belongs to a network
                if (subnet in list(listSubnets.keys()) and CSPleases[ipadd] != {}):
                    if listSubnets[subnet]['network_view'] == CSPleases[ipadd]['network_view']:
                        counterBloxOne += 1                             # If both conditions are met, the counter for that network is increased    --> BloxOne leases
        for lease in NIOSleases:
            if (IPv4Address(lease) in IPv4Network(subnet)):
                if listSubnets[subnet]['network_view'] == NIOSleases[lease]['network_view']:
                    counterNIOS += 1                                    # If both conditions are met, the counter for that network is increased    ---> NIOS leases
            listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
    return listSubnets

def comparesLeasesGridBackup_BloxOne(CSPleases, listSubnets, NIOSleases):                         # Receives NIOS and BloxOne DHCP leases as input
    for subnet in listSubnets:                                                                     # It also receives a list of the Subnets/Networks to use it as basis for the classification 
        counterNIOS = 0
        counterBloxOne = 0
        for ipadd in CSPleases:
            if (IPv4Address(ipadd) in IPv4Network(subnet)):                                         # With the ipaddress library, we can validate that the IP address of the leases belongs to a network
                if (subnet in list(listSubnets.keys())):
                    if listSubnets[subnet]['network_view'] == CSPleases[ipadd]['network_view']:     # The network view / IP space must also match to ensure that the leases has been correctly classified (of course, it could be the same network on a different view)
                        counterBloxOne += 1                              # If both conditions are met, the counter for that network is increased    --> BloxOne leases
        for ipadd in NIOSleases:
            if (IPv4Address(ipadd) in IPv4Network(subnet)):
                if listSubnets[subnet]['network_view'] == NIOSleases[ipadd]['network_view']:
                    counterNIOS += 1                                     # If both conditions are met, the counter for that network is increased    ---> NIOS leases
        listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
    return listSubnets

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
    opt_grp('--report', action="store", help="Defines the type of reporting that will be produced (LOG | CSV | GSHEET)", dest="report", required=False, default='log')
    #opt_grp('--version', action='version', version='%(prog)s ' + __version__)
    opt_grp('-h', '--help', action='help', help='show this help message and exit')
    return par.parse_args(args=None if sys.argv[1:] else ['-h'])


##########################################################

def main():
    NIOSleases  = {}
    reportLeases = {}
    CSPleases =  {}
    CSPlimit = 5000
    NIOSlimit = 10000
    args = get_args()
    b1tenant = check_tenant(args.config) 
    b1ddi = bloxone.b1ddi(cfg_file='/Users/fernandorguez/scripts/testrun/Completed/Syntegon/2021_06_24_production/syntegon_n2b1_config.ini')
    SheetName = 'NIOS vs BloxOne DHCP leases - ' + b1tenant
    #b1ddi = bloxone.b1ddi(cfg_file=args.config)
    apiKey = b1ddi.api_key
    LeasesApiInstance = AUTH(apiKey)
    B1Token = {'Authorization': 'Token ' + apiKey}
    IPSpaces = getSpaceNamesbySpaceId (B1Token)                                                             # Used to convert Space IDs into Space names --> Must match with the network_view in NIOS
    listSubnets = getSubnets(B1Token)                                                                       # List of all subnets in B1             --> ['network']{['address', 'network_view']}                         
    CSPleases = getBloxOneLeases(LeasesApiInstance, CSPlimit, IPSpaces)                                     # Collect BloxOne leases from B1DDI API  --> ['address']{['network_view',}
    #interface = "wapi"
    if (args.interface == 'wapi'):               # if WAPI --> it will get NIOS leases from the Grid WAPI interface
        gm_ip = input('Please type the IP address of the Grid Master \n')       
        auth_usr = input('Please enter NIOS admin account \n')
        auth_pwd = getpass.getpass('Please enter your password \n')
        try:
            NIOSleases = getLeasesWAPI(gm_ip, auth_usr, auth_pwd, NIOSlimit)               # Collect NIOS leases from NIOS WAPI     --> ['_ref', 'address', 'binding_state', 'network', 'network_view']
            reportLeases = comparesLeasesWAPI_BloxOne(CSPleases, listSubnets, NIOSleases)      # All leases in CSP have been collected via B1DDI API interface
        except ApiException as e:
            print("Exception when calling LeaseApi->lease_list: %s\n" % e)
    elif (args.interface == 'xml'):               
                                        # if XML --> it will get the DHCP leases from the Grid Backup (onedb.xml file)
        try:
            xmlfile = input('Please enter full path + filename of the Grid backup file \n')                                     
            NIOSleases = getGridBackupleases(xmlfile)                                           # Leases from NIOS will be obtained from a Grid backup (default onedb.xml) ---> 'address': {'leasesNIOS', 'network_view', 'leasesBloxOne'}            
            reportLeases = comparesLeasesGridBackup_BloxOne(CSPleases, listSubnets, NIOSleases)          # All leases in CSP have been collected via B1DDI API interface
        except ApiException as e:
            print("Exception when calling LeaseApi->lease_list: %s\n" % e) 
    else:
        print('Invalid option, please select XML or WAPI')
    
    #printReport(reportLeases,args.output.lower())
    if  args.output.lower() == 'log':            # It will display the results of the analysis directly on the terminal
        printReport(reportLeases,'log',SheetName)
    elif args.output.lower() == 'csv':
        printReport(reportLeases,'csv',SheetName)
    elif args.output.lower() == 'gsheet':       # It will gather all the data and - with the help a CSV file - will present it on a Google Spreadsheet that will be available for Infoblox employees (within Infoblox domain)
        #SheetName = input('Please enter name for the Gsheet')
        printReport(reportLeases,'gsheet',SheetName)
        

if __name__ == "__main__":
# execute only if run as a script
    main()
    sys.exit()