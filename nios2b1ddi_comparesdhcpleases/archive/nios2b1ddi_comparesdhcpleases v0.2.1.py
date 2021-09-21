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

# SYNOPSIS

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
from gspread_formatting import cellFormat, color, textFormat, format_cell_ranges, set_frozen
import csv
import time

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


def checksCSPTenant(config):  # It displays the CSP tenant we´re accessing and will validate our API key
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


def getIPSpaceNamesFromId(tokenB1):  # It gets the name of the IP Spaces from the Space Id. Grid DB uses integers to
    # identify the network views which is not helpful (ID for 'default' = 0)
    IPSpaces = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers=tokenB1)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        IPSpaces[i['id']] = i['name']
    return IPSpaces


def getSubnets(tokenB1, IPSpaces):  # It will get all the networks available in CSP for this tenant
    listSubnets = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers=tokenB1)
    subnets = response.json()['results']
    for net in subnets:
        cidr = net['address'] + '/' + str(net.pop('cidr'))
        net.update({'network_view': IPSpaces[net.pop('space')]})
        listSubnets[cidr] = net
    return listSubnets  # Output is a dictonary with the networks as indexes. This objects will be the basis for the comparson between NIOS and BloxOne DHCP leases.
    # MLeases will be assigned to their correponding subnet (within the correct ip space / network view) where every leases will increase the counters
    # This process will be performed both for NIOS and BloxOne to get clear picture of the leases being handled by CSP after the migration from NIOS
    # Which might facilitate the detection of potential issues after the go live

## The following functions will collect the leases from the supported platforms (currently 3: )
#  - NIOS WAPI
#  - Grid Backup file
#  - BloxOne API


def getBloxOneLeases(apiKey, maxResultsB1API):
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix['Authorization'] = 'Token'
    configuration.api_key['Authorization'] = apiKey
    leasesApiInstance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    tokenB1 = {'Authorization': 'Token ' + apiKey}
    IPSpaces = getIPSpaceNamesFromId(tokenB1)
    templeases = []
    B1leases = {}
    offset = 0
    listleases = leasesApiInstance.lease_list(limit=maxResultsB1API)
    templeases += listleases.results
    while isinstance(listleases, bloxonedhcpleases.LeasesListLeaseResponse) and (len(listleases.results) == maxResultsB1API):
        offset += maxResultsB1API + 1
        try:
            listleases = leasesApiInstance.lease_list(offset=str(offset), limit=str(maxResultsB1API))
            templeases += listleases.results
        except ApiException as e:
            print("Exception when calling LeaseApi->lease_list: %s\n" % e)
    for lease in templeases:
        tempDict = {}
        if lease.state.lower() in ['issued', 'used']:  # In BloxOne LEases States are Issued, Used or Freed
            # (NIOS: Active, Static)
            tempDict = {'network_view': IPSpaces[lease.space]}
        B1leases.update({lease.address: tempDict})
    return B1leases


def getGridBackupleases(xmlfile):  # Returns NIOSleases extracted from Grid Backup file
    # ['_ref', 'address', 'binding_state', 'network', 'network_view']
    listObjects = []
    NIOSleases = {}
    netViews = {}
    try:
        fxmml = open(xmlfile, 'r')
    except (FileNotFoundError, IOError):
        print('File not found')
        sys.exit()
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
        if (ob['__type'] == '.com.infoblox.dns.lease') and (
                ob['binding_state'].lower() in ['active', 'static', 'backup']):
            tempObject = {'network_view': netViews[ob['network_view']]}
            NIOSleases.update({ob['ip_address']: tempObject})
    return NIOSleases


# DHCP leases from NIOS WAPI. Request network and binding_state extra fields
# Supports paging (usually big number of results so multiple pages can be necessary)


def getLeasesWAPI(gm_ip, auth_usr, auth_pwd, maxResultsWAPI):
    NIOSleases = {}
    gm_ip = input('Please type the IP address of the Grid Master [or press enter for 192.168.1.2]\n') or '192.168.1.2'
    while not validate_ip(gm_ip):
        print('IP address not valid')
        gm_ip = input('Please type the IP address of the Grid Master [or press enter for 192.168.1.2]\n') or '192.168.1.2'
        # Exit the loop when IP entered is valid
    auth_usr = input('Please enter NIOS admin account [or press enter for admin]\n') or 'admin'
    auth_pwd = getpass.getpass('Please enter your password\n')

    url = 'https://' + gm_ip + '/wapi/v2.10/lease?_max_results=' + str(maxResultsWAPI) + '&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1'
    try:
        leases = requests.request("GET", url, verify=False, auth=(auth_usr, auth_pwd)).json()
        templeases = leases['result']
    except json.decoder.JSONDecodeError:
        print('API call error, review username and password and confirm WAPI IP is reachable')
        return
    while isinstance(leases['result'], list) and len(leases['result']) == maxResultsWAPI:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        try:
            leases = requests.request("GET", urlpaging, verify=False, auth=(auth_usr, auth_pwd)).json()
            templeases += leases['result']
        except json.decoder.JSONDecodeError:
            print('API call error, review username and password and confirm WAPI IP is reachable')
            return
    for lease in templeases:  # Leases with status of FREE are not considered
        if (lease['binding_state'].lower()) in ['active', 'static', 'backup']:
            tempDict = {'network_view': lease['network_view']}
            NIOSleases.update({lease['address']: tempDict})
    return NIOSleases  # Returns NIOSleases --> ['_ref', 'address', 'binding_state', 'network', 'network_view']


## Next function will compare the leases previously collected from NIOS and BloxOne. 3 types of Reports are available:
# - Display the output on the terminal
# - Export the results to a CSV file
# - Export the results to a Google Sheet (requires a service account or API key - JSON file - for authentication)

def comparesLeasesNIOS_BloxOne(B1leases, listSubnets, NIOSleases):  ## Receives NIOS leases as input (obtained via WAPI from the GM)
    for subnet in listSubnets:  # It also receives a list of the Subnets/Networks to use it as basis for the classification
        counterNIOS = 0
        counterBloxOne = 0
        for ipadd in B1leases:
            if (IPv4Address(ipadd) in IPv4Network(
                    subnet)):  # With the ipaddress library, we can validate that the IP address of the leases belongs to a network
                if subnet in list(listSubnets.keys()) and B1leases[ipadd] != {}:
                    if listSubnets[subnet]['network_view'] == B1leases[ipadd]['network_view']:
                        counterBloxOne += 1  # If both conditions are met, the counter for that network is increased    --> BloxOne leases
        for lease in NIOSleases:
            if IPv4Address(lease) in IPv4Network(subnet):
                if listSubnets[subnet]['network_view'] == NIOSleases[lease]['network_view']:
                    counterNIOS += 1  # If both conditions are met, the counter for that network is increased    ---> NIOS leases
        listSubnets[subnet].update({'leasesNIOS': counterNIOS, 'leasesBloxOne': counterBloxOne})
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


def pasteCsv(csvFile, sh, cell):
    if '!' in cell:
        (tabName, cell) = cell.split('!')
        wks = sh.add_worksheet(tabName,100,30)
    else:
        wks = sh.sheet1
    (firstRow, firstColumn) = gspread.utils.a1_to_rowcol(cell)
    with open(csvFile, 'r') as f:
        csvContents = f.read()
    body = {
        'requests': [{
            'pasteData': {
                'coordinate': {
                    'sheetId': wks.id,
                    'rowIndex': firstRow-1,
                    'columnIndex': firstColumn-1},
                'data': csvContents,
                'type': 'PASTE_NORMAL',
                'delimiter': ','}
        }]}
    return sh.batch_update(body)


def CSVtoGsheet(SheetName,csvfilename):  ## Opens (if exists) or Creates (if doesn´t) a Gsheet with name SheetName and imports the CSV output file
    # ib_service_account = input ('Path + Filename of the JSON file with Google service account Sheets service [or press enter for ./ib_service_account.json] \n') or "./ib_service_account.json"
    ib_service_account = os.environ['HOME'] + '/ib_service_account.json'
    gc = gspread.service_account(ib_service_account)
    myibmail = input ('Enter the email address linked to the Google account that will be used to access Gsheets \n')
    #Email account is important, otherwise user will not be allowed to access or update the gsheet (it's created by a service account')
    #dateTime = time.strftime('%Y/%m/%d - %H:%M')
    #wksname = 'Leases ' + dateTime
    #cell = wksname + '!A1'
    content = open(csvfilename, 'r').read()
    try:    #Sheet exists, we just open the document. We cannot import the CSV because it will delete all other wksheets
        sh = gc.open(SheetName)
        dateTime = time.strftime('%Y/%m/%d - %H:%M')
        wksname = 'Leases ' + dateTime + '!A1'
        pasteCsv(csvfilename, sh, wksname)      # This function does not delete any existing worksheets
    except gspread.exceptions.SpreadsheetNotFound:  #Sheet does not exists --> New sheet, we can just import the csv
        sh = gc.create(SheetName)
        # Adapt as required. By default, it will share the document with the service account email (mandatory) and with
        # the email address introduced previously with read/write permission. Anyone with the link can access in R/O
        sh.share(gc.auth.service_account_email, role='writer', perm_type='user')
        sh.share(myibmail, role='writer', perm_type='user')
        sh.share('', role='reader', perm_type='anyone')
        gc.import_csv(sh.id, content)   ## import_csv imports the CSV doc but also deletes any other existing worksheets
        sh = gc.open_by_key(sh.id)      # We use import_csv method only with new gsheets (to keep history record)
        wks = sh.sheet1
        wks.update_title(wksname)
    print("Gsheet available on the URL", sh.url)  # Returns the URL to the Gsheet
    return


def printReport(reportLeases, repType, SheetName, filteroption):
    # Generates the corresponding Report based on the option specified with -r [log,csv,gsheet]
    totalNIOSLeases = 0
    totalCSPLeases = 0
    if repType != "log":  # With log option, we don´t need to created the CSV file so these lines will not be required in that case
        csvfilename = input('Path + Filename of CSV file to export the results to [or enter for "./output.csv" \n') or 'output.csv'
        csvfile = open(csvfilename, 'w', newline='')
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(['Network', 'NIOS Lease Count', 'BloxOne Lease Count', 'Comments'])
    for lease in reportLeases:
        review = ''
        countB1leases = reportLeases[lease]['leasesBloxOne']
        countNIOSleases = reportLeases[lease]['leasesNIOS']
        totalNIOSLeases = totalNIOSLeases + countNIOSleases
        totalCSPLeases = totalCSPLeases + countB1leases
        if countNIOSleases != 0 and countB1leases != 0:
            continue
        elif countNIOSleases != 0 or countB1leases != 0:
            # Filter from the output those networks that didn´t have any leases in NIOS
            if countNIOSleases != 0 and countB1leases == 0:
                # There were leases in NIOS but there are none in BloxOne --> Review
                warning = fg.red + 'BloxOne Lease Count :' + str(countB1leases) + fg.rs + ' ---> Review low number of leases'
                review = 'Review BloxOne number of leases'
            elif countNIOSleases >= (countB1leases * 5) and (countNIOSleases > 10):
                # Leases in NIOS were more than 5 times the current leases in BloxOne --> Review
                warning = fg.red + 'BloxOne Lease Count :' + str(countB1leases) + fg.rs + ' ---> Review low number of leases'
                review = 'Review BloxOne number of leases'
            else:
                warning = 'BloxOne Lease Count :' + str(countB1leases)
            print('Network :', lease.ljust(18), 'NIOS Lease Count :', str(countNIOSleases).ljust(8), warning)
        if repType != "log":
            spamwriter.writerow([lease, str(countNIOSleases), str(countB1leases), review])
    if repType == "gsheet":  # With log option, we don´t need to created the CSV file so this lines are not required in that case
        CSVtoGsheet(SheetName, csvfilename)
    print('Total number of leases in NIOS :', totalNIOSLeases)
    print('Total number of leases in BloxOne :', totalCSPLeases)
    if repType != "log":
        spamwriter.writerow(['Total number of leases in NIOS :', totalNIOSLeases])
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
    # NIOSleases = {}
    # tokenB1 = {}
    SheetName = ''
    maxResultsB1API = 5000  # This value limits the amount of results received for an API call through BloxOne API
    maxResultsWAPI = 10000  # This value limits the amount of results received API call performed through NIOS WAPI
    args = get_args()
    b1tenant = checksCSPTenant(args.config)
    b1name = b1tenant.split(' ')[0]
    b1ddi = bloxone.b1ddi(cfg_file=args.config)
    tokenB1 = {'Authorization': 'Token ' + b1ddi.api_key}
    IPSpaces = getIPSpaceNamesFromId(tokenB1)
    B1leases = getBloxOneLeases(b1ddi.api_key, maxResultsB1API)
    listSubnets = getSubnets(tokenB1, IPSpaces)  # List of all subnets in B1 --> ['network']{['address', 'network_view']}

    # Collect BloxOne leases from B1DDI API  --> ['address']{['network_view',}
    if args.interface.lower() == 'wapi':  # if WAPI --> it will get NIOS leases from the Grid WAPI interface

        # With "-i wapi",  we will collect the leases from the WAPI interface in NIOS
        NIOSleases = getLeasesWAPI(gm_ip, auth_usr, auth_pwd, maxResultsWAPI)
        # Collect NIOS leases from NIOS WAPI     --> ['_ref', 'address', 'binding_state', 'network', 'network_view']
    elif args.interface.lower() == 'xml':  # if XML --> it will get the DHCP leases from the Grid Backup (onedb.xml file)
        try:
            xmlfile = input('Please enter full path + filename of the Grid backup file [or press enter for ./onedb.xml] \n') or "./onedb.xml"
            # Leases from NIOS will be obtained from a Grid backup (default onedb.xml)
            # ---> 'address': {'leasesNIOS', 'network_view', 'leasesBloxOne'}
            NIOSleases = getGridBackupleases(xmlfile)

        except FileNotFoundError as e:
            print('Exception when collecting Grid Backup Leases: %s\n' % e)

    if args.report.lower() == 'gsheet':
        SheetName = input('Name of the Gsheet for output [or press enter for "nios2b1ddi leases - <CUSTOMER NAME>"\n') or ('nios2b1ddi leases - ' + b1name)

    # After collecting all leases from NIOS and BloxOne, it compares both sets and creates a report with the differences
    reportLeases = comparesLeasesNIOS_BloxOne(B1leases, listSubnets, NIOSleases)
    printReport(reportLeases, args.report.lower(), SheetName, args.filter)
    t2 = time.perf_counter() - t1
    print(f' Process completed. Execution time : {t2:0.2f}s ')
    # It will display the results of the analysis: - directly on the terminal (log)
    #  - export to a CSV file (csv)
    #  - export to a Google Sheet (gsheet) **(requires service_account)

if __name__ == "__main__":
    # execute only if run as a script
    main()
    sys.exit()
