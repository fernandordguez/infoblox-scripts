#!/usr/bin/python3
# run as: python3 nios2b1ddi_compareDHCPleases -c config.ini -i wapi|onedb.xml -r log|csv|gsheet [ --yaml <yaml file> ] [ --help ] [ --delimiter x ]

"""
Copyright (C) Infoblox Inc. All rights reserved.

License: Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY INFOBLOX AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL INFOBLOX OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are
those of the authors and should not be interpreted as representing official
policies, either expressed or implied, of Infoblox.

# DESCRIPTION

This script takes a NIOS
IBCSV file and imports it into a BloxOne DDI
instance.

# SYNOPSIS

nios2b1ddi.py -c b1config.ini [ -i wapi | xml ] -r log | csv | gsheet] [ --delimiter x ] [ --yaml <yaml file> ] [ --help ]'

# PARAMETERS

The script requires the following command-line arguments.

    -c : path to configuration file for the bloxone python package. Here is a sample of this file:

[BloxOne]
url = 'https://csp.infoblox.com'
api_version = 'v1'
api_key = 'API_KEY'

    -i : interface to be used to collect NIOS leases (WAPI or Grid Backup)
    
    -r : method to be used to present the results of the script (log to terminal, csv file or Google sheet)
# INPUT

The script takes collects the required input from three sources: 

* NIOS:         - REST API (WAPI), requires reachability with the Grid (or VM running locally)
                - GRID BACKUP:      Gets the information from a local backup file of the NIOS DB (onedb.xml)    --> TO-DO Add support for .bak files
                (+ NIOS source can be selected with the two values available for option -i (wapi, xml))
* BloxOne:      - BloxOne API (hosted on the Infoblox Cloud Services Portal)


# OUTPUT

The output can be currently presented in one of the following three formats (can be selected with -r option):

* LOG       - Data is just presented via terminal
* CSV       - Data is exported to a local CSV file
* GSHEET    - Results are exported to a Google Sheet document. This option requires a service account or api key presented on a JSON file (+INFO here https://developers.google.com/sheets/api/guides/authorizing)
              The path to this file is configured on a environment variable to avoid its exposure outside Infoblox. This value must be updated to the local path + filename of the local json file containing the
              service account or api key that allows access to the Google Sheet and Drive services (as an example, it can be done by defining the variable as follows: ib_service_account = "/tmp/service_account.json")
"""
__version__ = '0.1.0'
__author__ = 'Fernando Rodriguez'
__author_email__ = 'frodriguez@infoblox.com'

import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
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
import json
import gspread
import os
from gspread_formatting import cellFormat,color,textFormat,format_cell_ranges,set_frozen
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2.service_account import Credentials
from csv import reader,writer
import csv
import threading
from threading import BoundedSemaphore
import urllib3
import concurrent.futures
import urllib.request

#requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def validate_ip(ip):                                                                                    ## It is used to confirm that the leases are valid IP addresses
    try:
        ipaddress.ip_address(ip)
        result = True
    except ValueError:
        result = False
    return result

def authAPI(apiKey):                                                                                    ## Configure API key authorization: ApiKeyAuth and initialize some variables
    B1Token = {}                                                                                            
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix ['Authorization'] = 'token'
    configuration.api_key['Authorization'] = apiKey
    api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    B1Token = {'Authorization': 'Token ' + apiKey}
    return api_instance, B1Token

def checksCSPTenant(config):                                                                            ## It displays the CSP tenant we´re accessing and will validate our API key. Useful to avoid accessing the wrong tenant by mistake
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

def getIPSpaceNamesFromId (B1Token):                                                                    ## It gets the name of the IP Spaces from the Space Id. Grid DB uses integers to identify the network views which is not helpful (ID for 'default' = 0)
    spaceNames = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers=B1Token)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        spaceNames[i['id']] = i['name']
    return spaceNames

def getSubnets(B1Token):                                                                                ## It will get all the networks available in CSP for this tenant
    spaceNames = getIPSpaceNamesFromId(B1Token)
    listSubnetsCSP = {}
    listSubn = {}
    netview = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers=B1Token).json()
    listSubn = response['results']
    for l in range(len(listSubn)):
        subnet = listSubn[l]['address'] + '/' + str(listSubn[l]['cidr'])
        netview = {'network_view': spaceNames[listSubn[l]['space']], 'leasesBloxOne': 0, 'leasesNIOS': 0}
        #if subnet in listSubnetsCSP.keys():
        listSubnetsCSP[subnet] = netview
    return listSubnetsCSP                                                                       #Output is a dictonary with the networks as indexes. This objects will be the basis for the comparson between NIOS and BloxOne DHCP leases.
                                                                                                #MLeases will be assigned to their correponding subnet (within the correct ip space / network view) where every leases will increase the counters
                                                                                                # This process will be performed both for NIOS and BloxOne to get clear picture of the leases being handled by CSP after the migration from NIOS
                                                                                                # Which might facilitate the detection of potential issues after the go live

## The following functions will collect the leases from the supported platforms (currently 3: )
    #  - NIOS WAPI
    #  - Grid Backup file
    #  - BloxOne API
def getBloxOneLeases(LeasesApiInstance, maxResultsB1API, IPSpaces):
    templeases = []
    tempDict = {}
    B1leases = {} 
    offset = 0
    leases = LeasesApiInstance.lease_list(limit=maxResultsB1API)
    templeases += leases.results
    while isinstance(leases, bloxonedhcpleases.LeasesListLeaseResponse) and (len(leases.results)==maxResultsB1API):
        offset += maxResultsB1API + 1
        leases = LeasesApiInstance.lease_list(offset=str(offset), limit=str(maxResultsB1API))
        templeases += leases.results
    for l in templeases:
        tempDict = {}
        if l.state.lower() in ['issued','used']:                                                        #  --->   In BloxOne LEases States are Issued, Used or Freed (NIOS: Active, Static)
            tempDict['network_view'] = IPSpaces[l.space]
        B1leases.update({l.address : tempDict})
    return B1leases

def getGridBackupleases (xmlfile):                                                                      ## Returns NIOSleases extracted from Grid Backup file --> ['_ref', 'address', 'binding_state', 'network', 'network_view']
    listObjects = []            
    dictObject = {}
    NIOSleases = {}
    netViews = {}
    try:
        fxmml = open(xmlfile,'r')
    except (FileNotFoundError, IOError):
        print('File not found')
        sys.exit()
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

def getLeasesWAPI(gm_ip, auth_usr, auth_pwd, maxResultsWAPI):                                           ## DHCP leases from NIOS WAPI. Request network and binding_state extra fields
    leases = {}
    tempDict = {}
    NIOSleases = {}
    templeases = []                                                                                 ## Supports paging (usually big number of results so multiple pages can be necessary)
    url = 'https://' + gm_ip + '/wapi/v2.10/lease?_max_results=' + str(maxResultsWAPI) + '&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1'
    try:
        leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
        templeases = leases['result']
    except json.decoder.JSONDecodeError as e:
        print('API call error, review username and password and confirm WAPI IP is reachable')
        return
    while isinstance(leases['result'],list) and len(leases['result'])==maxResultsWAPI:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        try:
            leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
            templeases += leases['result']
        except json.decoder.JSONDecodeError as e:
            print('API call error, review username and password and confirm WAPI IP is reachable')
            return
    for l in templeases:
        if (l['binding_state'].lower()) in ['active','static']:                              ## Leases with status of FREE are not considered
            tempDict = {}
            tempDict['network_view'] = l['network_view']
            NIOSleases.update({l['address'] : tempDict})
    with open('NIOSleases.json', 'w') as file:
        json_string = json.dumps(NIOSleases, indent=4)
        file.write(json_string)
    return NIOSleases                                                                                  ## Returns NIOSleases --> ['_ref', 'address', 'binding_state', 'network', 'network_view']

## Next function will compare the leases previously collected from NIOS and BloxOne. 3 types of Reports are available:
    # - Display the output on the terminal
    # - Export the results to a CSV file
    # - Export the results to a Google Sheet (requires a service account or API key - JSON file - for authentication)

def comparesLeasesNIOS_BloxOne(B1leases, listSubnets, NIOSleases):                                      ## Receives NIOS leases as input (obtained via WAPI from the GM)
    for subnet in listSubnets:                                                                          # It also receives a list of the Subnets/Networks to use it as basis for the classification 
        counterNIOS = 0
        counterBloxOne = 0
        for ipadd in B1leases:
            if (IPv4Address(ipadd) in IPv4Network(subnet)):                                             # With the ipaddress library, we can validate that the IP address of the leases belongs to a network
                if (subnet in list(listSubnets.keys()) and B1leases[ipadd] != {}):
                    if listSubnets[subnet]['network_view'] == B1leases[ipadd]['network_view']:
                        counterBloxOne += 1                                                             # If both conditions are met, the counter for that network is increased    --> BloxOne leases
        for lease in NIOSleases:
            if (IPv4Address(lease) in IPv4Network(subnet)):
                if listSubnets[subnet]['network_view'] == NIOSleases[lease]['network_view']:
                    counterNIOS += 1                                                                    # If both conditions are met, the counter for that network is increased    ---> NIOS leases
        listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
    return listSubnets

def countBloxOneLeases(listparams, dictSubnets):                                       ## Receives NIOS leases as input (obtained via WAPI from the GM)                                                                                                    ## It also receives a list of the Subnets/Networks to use it as basis for the classification 
    #lease = listparams[0]
    #subnet = listparams[1]
    #dictB1leases = listparams[2]
    #dictSubnets = listparams[3]
    #keysSubnets = listparams[4]
    if (IPv4Address(listparams[0]) in IPv4Network(listparams[1])):                                             ## With the ipaddress library, we can validate that the IP address of the leases belongs to a network
        if (listparams[1] in listparams[4]) and (listparams[2] != {}):
            if listparams[3]['network_view'] == listparams[2]['network_view']:
                listparams[3].update({'leasesBloxOne': listparams[3]['leasesBloxOne']+1})
    return listparams[3]                                                                   ## If both conditions are met, the counter for that network is increased    --> BloxOne leases
                                                                                                ## If both conditions are met, the counter for that network is increased    ---> NIOS leases '''

def countsNIOS(listparams, dictSubnets):                                       ## Receives NIOS leases as input (obtained via WAPI from the GM)                                                                                               ## It also receives a list of the Subnets/Networks to use it as basis for the classification 
    #lease = listparams[0]
    #subnet = listparams[1]
    #dictNIOSleases = listparams[2]
    if (IPv4Address(listparams[0]) in IPv4Network(listparams[1])):
        if listparams[3]['network_view'] == listparams[2]['network_view']:
            #counterNIOS = 
            listparams[3].update({'leasesNIOS': listparams[3]['leasesNIOS']+1})
            dictSubnets = listparams[3]
    return dictSubnets
                                                                                ## If both conditions are met, the counter for that network is increased    ---> NIOS leases '''

def processB1Leases_old(listSubnets,B1leases):
    threads = list()
    dictSubnets = {}
    
    listparams = []
    for subnet in listSubnets:
        for lease in B1leases:
            dictSubnets = listSubnets[subnet]
            dictB1leases = B1leases[lease]
            keySubnets = list(listSubnets.keys())
            listparams = [lease, subnet, dictB1leases, dictSubnets, keySubnets]
            t = threading.Thread(target=countBloxOneLeases, args=(listparams, listSubnets[subnet]))
            listSubnets[subnet] = dictSubnets
            t.name = subnet
            t.start()
            print(t.name)
            threads.append(t)
    for t in threads:
        t.join()
    return listSubnets

def processB1Leases_old(subnet,listparams):
    threads = list()
    dictSubnets = {}
    
    for lease in listparams[1]:
        dictSubnets = listparams[0][subnet]
        dictB1leases = listparams[1][lease]
        keySubnets = list(listparams[0].keys())
        listparams = [lease, subnet, dictB1leases, dictSubnets, keySubnets]
        t = threading.Thread(target=countBloxOneLeases, args=(listparams, listparams[0][subnet]))
        listparams[0][subnet] = dictSubnets
        t.name = subnet
        t.start()
        print(t.name)
        threads.append(t)
    for t in threads:
        t.join()
    return listparams[0]


def processB1Leases(listSubnets,B1leases):
    threads = list()
    listparams = []
    for subnet in listSubnets:
        for lease in B1leases:
            listparams = [lease, subnet, B1leases[lease], listSubnets[subnet], list(listSubnets.keys())]
            t = threading.Thread(target=countBloxOneLeases, args=(listparams, listSubnets[subnet]))
            #t.name = subnet
            t.start()
            #print(t.name)
            threads.append(t)
    #for t in threads:
    #    t.join()
    return listSubnets

listparams = [listSubnets, B1leases]
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    future_to_processB1Leases = {executor.submit(processB1Leases,subnet,listparams) : subnet for subnet in listSubnets}
    for future in concurrent.futures.as_completed(future_to_processB1Leases):
        subnet = future_to_processB1Leases[future]
        try:
            data = future.result()
        except Exception as exc:
            print('%r generated an exception: %s' % (subnet, exc))
        else:
            print('%r page is %d bytes' % (subnet, len(data)))
        
def processNIOSLeases(listSubnets,NIOSleases):
    threads = list()
    dictSubnets = {}
    listparams = []
    for subnet in listSubnets:
        for lease in NIOSleases:
            dictSubnets = listSubnets[subnet]
            dictNIOSleases = NIOSleases[lease]
            listparams = [lease,subnet,NIOSleases[lease],dictNIOSleases]
            t = threading.Thread(target=countsNIOS, args=(listparams, dictSubnets))
            listSubnets[subnet] = dictSubnets
            t.name = subnet
            t.start()
            threads.append(t)
            #Separatator
    for t in threads:
        t.join()
    return listSubnets

        ''' for niosl in NIOSleases:
            dictSubnets = listSubnets[subnet]
            dictNIOSleases = NIOSleases[niosl]
            listparams2 = [niosl,subnet,NIOSleases[niosl],dictNIOSleases]
            t = threading.Thread(target=countsNIOS, args=(listparams2, dictSubnets))
            listSubnets[subnet] = dictSubnets
            t.name = subnet
            t.start()
            threads.append(t)
            #Separatator '''
    for t in threads:
        t.join()
    return listSubnets

def formatGsheet(wks):                                                                                  ## Applies a bit of formatting to the Google Sheet document created
    body = {"requests": [{"autoResizeDimensions": {"dimensions": {"sheetId": wks.id,"dimension": "COLUMNS","startIndex": 0,"endIndex": 8}}}]}
            #{"autoResizeDimensions": {"dimensions": {"sheetId": sh._properties['id'],"dimension": "COLUMNS","startIndex": 0,"endIndex": 8},}}]}
    wks.spreadsheet.batch_update(body)
    set_frozen(wks, rows=1)
    fmt = cellFormat(textFormat=textFormat(bold=True, foregroundColor=color(1, 1, 1)), horizontalAlignment='CENTER', backgroundColor=color(0, 0, 1))
    format_cell_ranges(wks, [('A1:D1', fmt)])
    return

def CSVtoGsheet(SheetName,csvfilename):                                                                 ## Opens (if exists) or Creates (if doesn´t) a Gsheet with name SheetName and imports the CSV output file
    #ib_service_account = input ('Path + Filename of the JSON file with Google service account Sheets service [or press enter for ./ib_service_account.json] \n') or "./ib_service_account.json"
    ib_service_account = ''
    ib_service_account = os.environ['HOME']+'/ib_service_account.json'
    gc = gspread.service_account(ib_service_account)
    myibmail = "frodriguez@infoblox.com"
    content = open(csvfilename,'r').read()
    try:
        sh = gc.open(SheetName)
    except gspread.exceptions.SpreadsheetNotFound as error:
        sh = gc.create(SheetName)
        sh.share(gc.auth.service_account_email , role='writer', perm_type='user')
        sh.share(myibmail, role='writer', perm_type='user')
        sh.share('', role='reader', perm_type='anyone')
    gc.import_csv(sh.id, content)
    wks = sh.sheet1
    formatGsheet(wks)
    print ("Gsheet available on the URL", sh.url)                                               #Returns the URL to the Gsheet
    return

def printReport(reportLeases,repType,SheetName):                                                        ## Generates the corresponding Report based on the option specified with -r [log,csv,gsheet]
    countNIOSLeases = 0
    countCSPLeases = 0
    if repType != "log":                                                                            # With log option, we don´t need to created the CSV file so these lines will not be required in that case
        csvfilename = input('Path + Filename of CSV file to export the results to [or enter for "./output.csv" \n') or './output.csv'
        csvfile = open(csvfilename, 'w', newline='')
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(['Network','NIOS Lease Count','BloxOne Lease Count','Comments'])
    for l in reportLeases:
        review = ''
        warning = ''
        countNIOSLeases = countNIOSLeases + reportLeases[l]['leasesNIOS']
        countCSPLeases = countCSPLeases + reportLeases[l]['leasesBloxOne']
        if reportLeases[l]['leasesNIOS']!=0 or reportLeases[l]['leasesBloxOne']!=0:                                                                #Filter from the output those networks that didn´t have any leases in NIOS
            if reportLeases[l]['leasesNIOS']!=0 and reportLeases[l]['leasesBloxOne']==0:                                                            #There were leases in NIOS but there are none in BloxOne --> Review 
                warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs + ' ---> Review low number of leases'    
                review = 'Review BloxOne number of leases'
            elif (reportLeases[l]['leasesNIOS'] >= (reportLeases[l]['leasesBloxOne'])*5) and (reportLeases[l]['leasesNIOS'] > 10):                  #Leases in NIOS were more than 5 times the current leases in BloxOne --> Review 
                warning = fg.red + 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne']) + fg.rs + ' ---> Review low number of leases'    
                review = 'Review BloxOne number of leases'
            else:
                warning = 'BloxOne Lease Count :' + str(reportLeases[l]['leasesBloxOne'])
            print('Network :',l.ljust(18),'NIOS Lease Count :',str(reportLeases[l]['leasesNIOS']).ljust(8),warning)
        if repType != "log": 
            spamwriter.writerow([l,str(reportLeases[l]['leasesNIOS']),str(reportLeases[l]['leasesBloxOne']),review])
    if repType == "gsheet":                                                                                                                         # With log option, we don´t need to created the CSV file so this lines are not required in that case
        CSVtoGsheet(SheetName,csvfilename)
    print('Total number of leases in NIOS :',countNIOSLeases)
    print('Total number of leases in BloxOne :',countCSPLeases)
    if repType != "log": 
        spamwriter.writerow(['Total number of leases in NIOS :',countNIOSLeases])
        spamwriter.writerow(['Total number of leases in BloxOne :',countCSPLeases])
        csvfile.close()
        if repType == "csv":
            print('Results have been exported to the CSV file',csvfilename) 
    return None

def get_args():                                                                                         ## Handles the arguments passed to the script from the command line
    # Parse arguments
    usage = ' -c b1config.ini -i {"wapi", "xml"} -r {"log","csv","gsheet"} [ --delimiter {",",";"} ] [ --yaml <yaml file> ] [ --help ]'
    description = 'This script gets DHCP leases from NIOS (via WAPI or from a Grid Backup), collects BloxOne DHCP leases from B1DDI API and compares network by network the number of leases on each platform'
    epilog = ''' sample b1config.ini
                [BloxOne]
                url = 'https://csp.infoblox.com'
                api_version = 'v1'
                api_key = 'API_KEY'''
    par = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter,description=description,add_help=False,usage='%(prog)s' + usage,epilog=epilog)
    # Required Argument(s)
    required = par.add_argument_group('Required Arguments')
    req_grp = required.add_argument
    req_grp('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    req_grp('-i', '--interface', action="store", dest="interface", help="source from where NIOS data will be imported", choices=['wapi','xml'], required=True)
    req_grp('-r', action="store", dest="report", help="Defines the type of reporting that will be produced", choices = ['log','csv','gsheet'], required=True, default='log')
    # Optional Arguments(s)
    optional = par.add_argument_group('Optional Arguments')
    opt_grp = optional.add_argument
    opt_grp('--delimiter', action="store", dest="csvdelimiter", help="Delimiter used in CSV data file", choices=[',',';'])
    opt_grp('--yaml', action="store", help="Alternate yaml file for supported objects", default='objects.yaml')
    opt_grp('--debug', action='store_true', help=argparse.SUPPRESS, dest='debug')
    #opt_grp('--version', action='version', version='%(prog)s ' + __version__)
    opt_grp('-h', '--help', action='help', help='show this help message and exit')
    return par.parse_args(args=None if sys.argv[1:] else ['-h'])

##########################################################

def main():
    threadLimiter = threading.BoundedSemaphore(20)
    NIOSleases  = {}
    reportLeases = {}
    B1leases =  {}
    listSubnets = {}
    SheetName = ''
    maxResultsB1API = 5000                                                                              ## This value limits the amount of results received for an API call through BloxOne API. Used in combination with paging
    maxResultsWAPI = 10000                                                                              ## This value limits the amount of results received for an API call performed through NIOS WAPI. Used in combination with paging
    args = get_args()
    b1tenant = checksCSPTenant(args.config)
    b1ddi = bloxone.b1ddi(cfg_file=args.config)
    leasesApi, B1Token = authAPI(b1ddi.api_key)
    IPSpaces = getIPSpaceNamesFromId(B1Token)                                                           ## Used to convert Space IDs into Space names --> Must match with the network_view in NIOS
    listSubnets = getSubnets(B1Token)                                                                   ## List of all subnets in B1             --> ['network']{['address', 'network_view']}                         
    B1leases = getBloxOneLeases(leasesApi, maxResultsB1API, IPSpaces)                                           ## Collect BloxOne leases from B1DDI API  --> ['address']{['network_view',}
    
    if (args.interface == 'wapi'):                                                                      ## if WAPI --> it will get NIOS leases from the Grid WAPI interface
        gm_ip = input('Please type the IP address of the Grid Master [or press enter for 192.168.1.2]\n') or '192.168.1.2'
        while not validate_ip(gm_ip):
            print('IP address not valid')
            gm_ip = input('Please type the IP address of the Grid Master [or press enter for 192.168.1.2]\n') or '192.168.1.2' 
        
        # Exit the loop when IP entered is valid
        auth_usr = input('Please enter NIOS admin account [or press enter for admin]\n') or 'admin'
        auth_pwd = getpass.getpass('Please enter your password\n')
        NIOSleases = getLeasesWAPI(gm_ip, auth_usr, auth_pwd, maxResultsWAPI)                               # Collect NIOS leases from NIOS WAPI     --> ['_ref', 'address', 'binding_state', 'network', 'network_view']
        
    elif (args.interface == 'xml'):                                                                         ## if XML --> it will get the DHCP leases from the Grid Backup (onedb.xml file)
        try:
            xmlfile = input('Please enter full path + filename of the Grid backup file [or press enter for ./onedb.xml] \n') or "./onedb.xml"
            NIOSleases = getGridBackupleases(xmlfile)                                                       ## Leases from NIOS will be obtained from a Grid backup (default onedb.xml) ---> 'address': {'leasesNIOS', 'network_view', 'leasesBloxOne'}            
        except (FileNotFoundError) as e:
            print('Exception when collecting Grid Backup Leases: %s\n' % e)
    
    if (args.report == 'gsheet'):
        SheetName = input('Name of the Gsheet where the results will be exported [or press enter for "NIOS vs BloxOne DHCP leases - <TENANT NAME>"]\n') or ('NIOS vs BloxOne DHCP leases - ' + b1tenant)    
    
    #After collecting all leases from NIOS and BloxOne, it compares both sets and creates a report with the differences
    reportLeases = comparesLeasesNIOS_BloxOne(B1leases, listSubnets, NIOSleases)  
    reportLeases = comparesLeases(listSubnets,B1leases,NIOSleases)
    printReport(reportLeases,args.report.lower(),SheetName)                                                 ## It will display the results of the analysis: - directly on the terminal (log)
                                                                                                                                                        #  - export to a CSV file (csv)
                                                                                                                                                        #  - export to a Google Sheet (gsheet) **(requires service_account)

if __name__ == "__main__":
# execute only if run as a script
    main()
    sys.exit()
    
    
f = open ('NIOSleases.json','w') 