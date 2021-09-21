#!/usr/bin/python3
# run as: python3 nios2b1ddi_compareDHCPleases -c config.ini -i wapi | onedb.xml -r log|csv|gsheet
# --> [ --yaml <yaml file> ] [ --help ] [ --delimiter x ]

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

nios2b1ddi.py -c b1config.ini [ -i wapi | xml ] -r log|csv|gsheet] [ --delimiter x ] [ --yaml <yamlfile> ] [--help]'

# PARAMETERS

The script requires the following command-line arguments.

    -c : path to configuration file for the bloxone python package. Here is a sample of this file:

[BloxOne]
url = 'https://csp.infoblox.com'
api_version = 'v1'
api_key = 'API_KEY'

    -i : interface to be used to collect NIOS leases (WAPI or Grid Backup)
    -r : method to be used to present the results of the script (log to terminal, csv file or Google sheet)
    -f : if present, networks without any leases will be ignored on the report (better readibility)


# INPUT

The script takes collects the required input from three sources:

* NIOS:         - REST API (WAPI), requires reachability with the Grid (or VM running locally)
                - GRID BACKUP:      Gets the information from a local backup file of the NIOS DB (onedb.xml)

                (+ NIOS source can be selected with the two values available for option -i (wapi, xml))
* BloxOne:      - BloxOne API (hosted on the Infoblox Cloud Services Portal)


# OUTPUT

The output can be currently presented in one of the following three formats (can be selected with -r option):

* LOG       - Data is just presented via terminal
* CSV       - Data is exported to a local CSV file
* GSHEET    - Results are exported to a Google Sheet document. This option requires a service account or api key
              presented on a JSON file (+INFO here https://developers.google.com/sheets/api/guides/authorizing)
              The path to this file is configured on a environment variable to avoid its exposure outside Infoblox.
              This value must be updated to the local path + filename of the local json file containing the
              service account or api key that allows access to the Google Sheet and Drive services (as an example,
              it can be done by defining the variable as follows: ib_service_account = "/tmp/service_account.json")
# UPDATES

* 0.1.0     First complete version, supports WAPI and Grid Backup for NIOS (BloxOne API is obvisouly through the API)
* 0.2.0     Added support for 3 different output options (it can be defined with -r when running the script
* 0.2.1     When exporting to Google spreadsheets, report will be created always a new worksheet which. Worksheets names
            have a timestamp so this could be used as references to different moments in time when leases were captured
* 0.2.2     Minor code optimizations

# TECHNICAL REFERENCE

* NIOS
        BINDING_STATES: (IN NIOS)

        ABANDONED: The Infoblox appliance cannot lease this IP address because the appliance received a response when it pinged the address.
        ACTIVE: The lease is currently in use by a DHCP client.
        EXPIRED: The lease was in use, but the DHCP client never renewed it, so it is no longer valid.
        FREE: The lease is available for clients to use.
        RELEASED: The DHCP client returned the lease to the appliance.

        TYPES:

        Valid values are:
        ABANDONED, ACTIVE, BACKUP,DECLINED.EXPIRED,FREE,OFFERED,RELEASED,RESET,STATIC

"""
__version__ = '0.2.1'
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
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from sty import fg, bg, ef, rs
import json
import gspread
import os
from gspread_formatting import *
import csv
import time
import pandas as pd

requests.packages.urllib3.disable_warnings()
t = time.perf_counter()
dateTime = time.strftime('%Y-%m-%d:%H:%M')
t1 = time.perf_counter()


def validate_ip(ip):  # It is used to confirm that the leases are valid IP addresses
    try:
        ipaddress.ip_address(ip)
        result = True
    except ValueError:
        result = False
    return result


def checkscspttenant(config):  # It displays the CSP tenant we´re accessing and will validate our API key
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
        # log.info(f'{b1user} is now accessing {b1tenant}')
        return b1tenant
    else:
        sys.exit()


def getipspacenamesfromid(tokenb1):  # It gets the name of the IP Spaces from the Space Id. Grid DB uses integers to
    # identify the network views which is not helpful (ID for 'default' = 0)
    IPSpaces = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers=tokenb1)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        IPSpaces[i['id']] = i['name']
    return IPSpaces


def getSubnets(tokenb1, IPSpaces):  # It will get all the networks available in CSP for this tenant
    listSubnets = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers=tokenb1)
    subnets = response.json()['results']
    for net in subnets:
        cidr = str(net.pop('address'))+ '/' + str(net.pop('cidr'))
        net.update({'network_view': IPSpaces[net.pop('space')]})
        listSubnets[cidr] = net
    return listSubnets  # Output is a dictonary with the networks as indexes. This objects will be the basis for the comparson between NIOS and BloxOne DHCP leases.
    # MLeases will be assigned to their correponding subnet (within the correct ip space / network view) where every leases will increase the counters
    # This process will be performed both for NIOS and BloxOne to get clear picture of the leases being handled by CSP after the migration from NIOS
    # Which might facilitate the detection of potential issues after the go live


def getleaseswapi(maxresultswapi):
    niosleases = {}
    templeases = []
    gm_ip = input('Please type the IP address of the Grid Master [or press enter for 192.168.1.2]\n') or '192.168.1.2'
    while not validate_ip(gm_ip):
        print('IP address not valid')
        gm_ip = input('Please type the IP address of the Grid Master [or press enter for 192.168.1.2]\n') or '192.168.1.2'
    # Exit the loop when IP entered is valid
    auth_usr = input('Please enter NIOS admin account [or press enter for admin]\n') or 'admin'
    auth_pwd = getpass.getpass('Please enter your password\n')
    url = 'https://' + gm_ip + '/wapi/v2.10/lease?_max_results=' + str(maxresultswapi) + '&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1'
    try:
        leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
        templeases = leases['result']
    except json.decoder.JSONDecodeError:
        print('API call error, review username and password and confirm WAPI IP is reachable')
    while isinstance(leases['result'],list) and len(leases['result']) == maxresultswapi:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        try:
            leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
            templeases += leases['result']
        except json.decoder.JSONDecodeError:
            print('API call error, review username and password and confirm WAPI IP is reachable')
            return
    for ipadd in templeases:  # Leases with status of FREE are not considered
        tempDict = {}
        if ipadd['binding_state'].lower() in ['active', 'static']:
            tempDict = {'network_view' : ipadd['network_view']}
            niosleases.update({ipadd['address']: tempDict})
    return niosleases


def getleasesbloxone(apiKey, maxresultsb1api):
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix['Authorization'] = 'Token'
    configuration.api_key['Authorization'] = apiKey
    leasesApiInstance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    tokenb1 = {'Authorization': 'Token ' + apiKey}
    IPSpaces = getipspacenamesfromid(tokenb1)
    templeases = []
    b1leases = {}
    offset = 0
    listleases = leasesApiInstance.lease_list(limit=maxresultsb1api)
    templeases += listleases.results
    while isinstance(listleases, bloxonedhcpleases.LeasesListLeaseResponse) and (len(listleases.results) == maxresultsb1api):
        offset += maxresultsb1api + 1
        try:
            listleases = leasesApiInstance.lease_list(offset=str(offset), limit=str(maxresultsb1api))
            templeases += listleases.results
        except ApiException as e:
            print("Exception when calling LeaseApi->lease_list: %s\n" % e)
    for lease in templeases:
        tempDict = {}
        if lease.state.lower() in ['issued', 'used']:  # In BloxOne LEases States are Issued, Used or Freed
            # (NIOS: Active, Static)
            tempDict = {'network_view': IPSpaces[lease.space]}
            #b1leases.update({lease.address: tempDict})
            b1leases[lease.address] = tempDict
    return b1leases


def getleasesgridbackup(xmlfile):  # Returns niosleases extracted from Grid Backup file
    # ['_ref', 'address', 'binding_state', 'network', 'network_view']
    listObjects = []
    niosleases = {}
    netViews = {}
    try:
        fxmml = open(xmlfile, 'r')
        xml_content = fxmml.read()
        objects = xmltodict.parse(xml_content)
        objects = objects['DATABASE']['OBJECT']
        for obj in objects:
            dictObject = {}
            for item in (obj['PROPERTY']):
                dictObject[item['@NAME']] = item['@VALUE']
                listObjects.append(dictObject)
        for ob in listObjects:
            if ob['__type'] == '.com.infoblox.dns.network_view':
                netViews[ob['id']] = ob['name']
        for ob in listObjects:
            tempObject = {}
            if (ob['__type'] == '.com.infoblox.dns.lease') and (ob['binding_state'].lower() in ['active', 'static', 'backup']):
                tempObject = {'network_view': netViews[ob['network_view']]}
                #niosleases.update({ob['ip_address']: tempObject})
                niosleases[ob['ip_address']] = tempObject
    except (FileNotFoundError, IOError):
        print('File not found')
        sys.exit()
    return niosleases


def comparesleasesniosbloxone(b1leases, listSubnets, niosleases):  ## Receives NIOS leases as input (obtained via WAPI from the GM)
    t = time.perf_counter()
    t1 = time.perf_counter()
    for subnet in listSubnets:  # It also receives a list of the Subnets/Networks to use it as basis for the classification
        counterNIOS = 0
        counterBloxOne = 0
        for ipadd in b1leases:
            if IPv4Address(ipadd) in IPv4Network(subnet):  # With the ipaddress library, we can validate that the IP address of the leases belongs to a network
                 if b1leases[ipadd] !={}:
                    if listSubnets[subnet]['network_view'] == b1leases[ipadd]['network_view']:
                        counterBloxOne += 1  # If both conditions are met, the counter for that network is increased    --> BloxOne leases
        for lease in niosleases:
            if IPv4Address(lease) in IPv4Network(subnet):
                if listSubnets[subnet]['network_view'] == niosleases[lease]['network_view']:
                    counterNIOS += 1  # If both conditions are met, the counter for that network is increased    ---> NIOS leases
        listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
    t2 = time.perf_counter() - t1
    print(f' Process completed. Execution time : {t2:0.2f}s ')
    return listSubnets


def formatGsheet(wks):  ## Applies a bit of formatting to the Google Sheet document created
    body = {"requests": [{"autoResizeDimensions": {
        "dimensions": {"sheetId": wks.id, "dimension": "COLUMNS", "startIndex": 0, "endIndex": 8}}}]}
    # {"autoResizeDimensions": {"dimensions": {"sheetId": sh._properties['id'],"dimension": "COLUMNS","startIndex": 0,"endIndex": 8},}}]}
    wks.spreadsheet.batch_update(body)
    set_frozen(wks, rows=1)
    fmt = cellFormat(textFormat=textFormat(bold=True, foregroundColor=color(1, 1, 1)), horizontalAlignment='CENTER',
                     backgroundColor=color(0, 0, 1))
    format_cell_ranges(wks, [('A1:D1', fmt)])
    return wks


def pastecsv(csvfilename, sh, cell):
    if '!' in cell:
        (tabName, cell) = cell.split('!')
        wks = sh.add_worksheet(tabName,100,30)
    else:
        wks = sh.sheet1
    (firstRow, firstColumn) = gspread.utils.a1_to_rowcol(cell)
    with open(csvfilename, 'r') as f:
        csvContents = f.read()
    body = {'requests': [{
        'pasteData': {
            'coordinate': {
                'sheetId': wks.id,
                'rowIndex': firstRow-1,
                'columnIndex': firstColumn-1},
            'data': csvContents,
            'type': 'PASTE_NORMAL',
            'delimiter': ','}}]}
    sh.batch_update(body)
    return wks


def csvtogsheet(SheetName,csvfilename):  ## Opens (if exists) or Creates (if doesn´t) a Gsheet with name SheetName and imports the CSV output file
    # ib_service_account = input ('Path + Filename of the JSON file with Google service account Sheets service [or press enter for ./ib_service_account.json] \n') or "./ib_service_account.json"
    ib_service_account = os.environ['HOME'] + '/ib_service_account.json'
    gc = gspread.service_account(ib_service_account)
    myibmail = input ('Enter the email address linked to the Google account that will be used to access Gsheets \n')
    #Email account is important, otherwise user will not be allowed to access or update the gsheet (it's created by a service account')
    try:    #Sheet exists, we just open the document. We cannot import the CSV because it will delete all other wksheets
        sh = gc.open(SheetName)
        timenow = time.strftime('%Y/%m/%d - %H:%M')
        wksname = 'Leases ' + timenow + '!A1'
        wks = pastecsv(csvfilename, sh, wksname)      # This function does not delete any existing worksheets
        wks = formatGsheet(wks)
    except gspread.exceptions.SpreadsheetNotFound:  #Sheet does not exists --> New sheet, we can just import the csv
        sh = gc.create(SheetName)
        # Adapt as required. By default, it will share the document with the service account email (mandatory) and with
        # the email address introduced previously with read/write permission. Anyone with the link can access in R/O
        with open(csvfilename, 'r') as f:
            csvContents = f.read()
        timenow = time.strftime('%Y/%m/%d - %H:%M')
        wksname = 'Leases ' + timenow + '!A1'
        sh.share(gc.auth.service_account_email, role='writer', perm_type='user')
        sh.share(myibmail, role='writer', perm_type='user')
        sh.share('', role='reader', perm_type='anyone')
        gc.import_csv(sh.id, csvContents)   ## import_csv deletes any existing worksheets and imports the data in sh.sheet1
    sh = gc.open_by_key(sh.id)      # We use import_csv method only with new gsheets (to keep history record)
    wks = sh.sheet1
    wks.update_title(wksname)
    wks = formatGsheet(wks)
    print("Gsheet available on the URL", sh.url)  # Returns the URL to the Gsheet
    print('Filter option was enabled so output is reduced to networks with any leases \n')
    return None


def printReport(reportleases, repType, filteroption, b1name):
    # Generates the corresponding Report based on the option specified with -r [log,csv,gsheet]
    totalniosleases = 0
    totalCSPLeases = 0
    if repType != "log":  # With log option, we don´t need to created the CSV file so these lines will not be required in that case
        csvfilename = input('Path + Filename of CSV file to export the results to [or enter for "./output.csv" \n') or 'output.csv'
        csvfile = open(csvfilename, 'w', newline='')
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(['Network', 'NIOS Lease Count', 'BloxOne Lease Count', 'Comments'])
    for lease in reportleases:
        review = ''
        countb1leases = reportleases[lease]['leasesBloxOne']
        countniosleases = reportleases[lease]['leasesNIOS']
        totalniosleases = totalniosleases + countniosleases
        totalCSPLeases = totalCSPLeases + countb1leases
        if (countniosleases != 0 or countb1leases != 0) and filteroption:
            # Filter from the output those networks that didn´t have any leases in NIOS
            if (countniosleases != 0 and countb1leases == 0) or (countniosleases >= (countb1leases * 5)):
                # There were leases in NIOS but there are none in BloxOne --> Review
                warning = fg.red + 'BloxOne Lease Count :' + str(countb1leases) + fg.rs + ' ---> Review low number of leases'
                review = 'Review BloxOne number of leases'
            else:
                warning = 'BloxOne Lease Count :' + str(countb1leases)
            print('Network :', lease.ljust(18), 'NIOS Lease Count :', str(countniosleases).ljust(8), warning)
        if repType != "log":
            spamwriter.writerow([lease, str(countniosleases), str(countb1leases), review])
    if repType == "gsheet":  # With log option, we don´t need to created the CSV file so this lines are not required in that case
        SheetName = input('Name of the Gsheet for output [or press enter for "nios2b1ddi leases - <CUSTOMER NAME>"\n') or ('nios2b1ddi leases - ' + b1name)
        csvtogsheet(SheetName, csvfilename)
    print('Total number of leases in NIOS :', totalniosleases)
    print('Total number of leases in BloxOne :', totalCSPLeases)
    if repType != "log":
        spamwriter.writerow(['Total number of leases in NIOS :', totalniosleases])
        spamwriter.writerow(['Total number of leases in BloxOne :', totalCSPLeases])
        csvfile.close()
        if repType == "csv":
            print('Results have been exported to the CSV file', csvfilename)
    return None


def get_args():  ## Handles the arguments passed to the script from the command line
    # Parse arguments
    usage = ' -c b1config.ini -i {"wapi", "xml"} -r {"log","csv","gsheet"} [ --delimiter {",",";"} ] [ --yaml <yaml file> ] [ --help ]'
    description = 'This script gets DHCP leases from NIOS (via WAPI or from a Grid Backup), collects BloxOne DHCP leases from B1DDI API and compares network by network the number of leases on each platform'
    epilog = ''' sample b1config.ini 
                [BloxOne]
                url = 'https://csp.infoblox.com'
                api_version = 'v1'
                api_key = 'API_KEY'''
    par = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=description, add_help=False, usage='%(prog)s' + usage, epilog=epilog)
    # Required Argument(s)
    required = par.add_argument_group('Required Arguments')
    req_grp = required.add_argument
    req_grp('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    req_grp('-i', '--interface', action="store", dest="interface", help="source from where NIOS data will be imported", choices=['wapi', 'xml'], required=True)
    req_grp('-r', action="store", dest="report", help="Defines the type of reporting that will be produced", choices=['log', 'csv', 'gsheet'], required=True, default='log')
    # Optional Arguments(s)
    optional = par.add_argument_group('Optional Arguments')
    opt_grp = optional.add_argument
    opt_grp('--delimiter', action="store", dest="csvdelimiter", help="Delimiter used in CSV data file",choices=[',', ';'])
    opt_grp('--yaml', action="store", help="Alternate yaml file for supported objects", default='objects.yaml')
    opt_grp('--debug', action='store_true', help=argparse.SUPPRESS, dest='debug')
    opt_grp('-f', '--filter', action='store_true', help='Excludes networks with 0 leases from the report', dest='filter')
    # opt_grp('--version', action='version', version='%(prog)s ' + __version__)
    opt_grp('-h', '--help', action='help', help='show this help message and exit')
    return par.parse_args(args=None if sys.argv[1:] else ['-h'])

##########################################################


def main():
    niosleases = {}
    tokenb1 = {}
    maxresultsb1api = 5000  # This value limits the amount of results received for an API call through BloxOne API
    maxresultswapi = 10000  # This value limits the amount of results received API call performed through NIOS WAPI
    args = get_args()
    b1tenant = checkscspttenant(args.config)
    b1name = b1tenant.split(' ')[0]
    try:
        b1ddi = bloxone.b1ddi(cfg_file=args.config)
    except bloxone.APIKeyFormatError as e:
        print('Exception when connecting to BloxOne DDI : %s\n' % e)
    tokenb1 = {'Authorization': 'Token ' + b1ddi.api_key}
    IPSpaces = getipspacenamesfromid(tokenb1)
    b1leases = getleasesbloxone(b1ddi.api_key, maxresultsb1api)
    listSubnets = getSubnets(tokenb1, IPSpaces)  # List of all subnets in B1
    if args.interface.lower() == 'wapi':  # if WAPI --> it will get NIOS leases from the Grid WAPI interface
        niosleases = getleaseswapi(maxresultswapi)
        # Collect NIOS leases from NIOS WAPI
    if args.interface.lower() == 'xml':
        # NIOS leases will be obtained from a Grid backup file (default onedb.xml)
        xmlfile = input('Enter path + filename for Grid backup [or press enter for ./onedb.xml] \n') or "./onedb.xml"
        try:
            niosleases = getleasesgridbackup(xmlfile)
        except FileNotFoundError as e:
            print('Exception when collecting Grid Backup Leases: %s\n' % e)
    # After collecting all leases from NIOS and BloxOne, it compares both sets and creates a report with the differences
    reportleases = comparesleasesniosbloxone(b1leases, listSubnets, niosleases)
    printReport(reportleases, args.report.lower(), args.filter, b1name)
    # It will display the results of the analysis: - directly on the terminal (log)
    #  - export to a CSV file (csv)
    #  - export to a Google Sheet (gsheet) **(requires service_account)

if __name__ == "__main__":
    # execute only if run as a script
    main()
    sys.exit()

