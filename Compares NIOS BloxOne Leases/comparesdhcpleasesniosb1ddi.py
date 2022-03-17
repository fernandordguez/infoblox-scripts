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
* 0.2.4     Code optimizations to improve performance of some of the fucntions used to process the leases
            Added configuration with multiple to avoid terminal input requiring user action
* 0.2.4     Added  inputoption XML with Grid Backup file (.bak or .tar.gz)
* 0.3.0     Added support for Grid Backup files as input
            Added option to only gather the active leases in NIOS (ignores BloxOne)
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
__version__ = '0.3'
__author__ = 'Fernando Rodriguez'
__author_email__ = 'frodriguez@infoblox.com'

import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
import requests
import xmltodict
import argparse
from argparse import RawDescriptionHelpFormatter
import bloxone
import sys
import ipaddress
from ipaddress import IPv4Address, IPv4Network
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
from sty import fg, bg, ef, rs
import json
import gspread
from gspread_formatting import *
import csv
import time
from mod import read_b1_ini
import tarfile

requests.packages.urllib3.disable_warnings()
lenghtreport = 0
t1 = time.perf_counter()

def validate_ip(ip):  # It is used to confirm that the leases are valid IP addresses
    try:
        ipaddress.ip_address(ip)
        result = True
    except ValueError:
        result = False
    return result


def checks_csp_tenant(config):  # It displays the CSP tenant we´re accessing and will validate our API key
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


def find_space_name_from_id( token_b1):  # It gets the name of the IP Spaces from the Space Id. Grid DB uses integers to
    # identify the network views which is not helpful (ID for 'default' = 0)
    ip_spaces = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers= token_b1)
    spaces = json.loads(response.content)['results']
    for i in spaces:
        ip_spaces[i['id']] = i['name']
    return ip_spaces


def get_subnets( token_b1, ip_spaces):  # It will get all the networks available in CSP for this tenant
    list_subnets = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers= token_b1)
    subnets = response.json()['results']
    for net in subnets:
        cidr = str(net.pop('address')) + '/' + str(net.pop('cidr'))
        net.update({'network_view': ip_spaces[net.pop('space')], 'leases NIOS': 0, 'leases BloxOne': 0})
        list_subnets[cidr] = net
    return list_subnets  # Output is a dictonary with the networks as indexes. This objects will be the basis for the comparson between NIOS and BloxOne DHCP leases.
    # MLeases will be assigned to their correponding subnet (within the correct ip space / network view) where every leases will increase the counters
    # This process will be performed both for NIOS and BloxOne to get clear picture of the leases being handled by CSP after the migration from NIOS
    # Which might facilitate the detection of potential issues after the go live


def  get_leases_wapi(max_results_wapi, conf):
    nios_leases = {}
    temp_leases = []
    gm_ip = conf['gm_ip']
    gm_usr = conf['gm_usr']
    gm_pwd = conf['gm_pwd']
    if not validate_ip(gm_ip):
        print('IP address not valid, please review the configuration file')

    url = 'https://' + gm_ip + '/wapi/v2.10/lease?_max_results=' + str(
        max_results_wapi) + '&_return_fields%2B=network,binding_state&_paging=1&_return_as_object=1'
    try:
        leases = requests.request("GET", url, verify=False, auth=(gm_usr, gm_pwd)).json()
        temp_leases = leases['result']
    except json.decoder.JSONDecodeError:
        print('API call error, review username and password and confirm WAPI IP is reachable')
    while isinstance(leases['result'], list) and len(leases['result']) == max_results_wapi:
        urlpaging = url + "&_page_id=" + str(leases['next_page_id'])
        try:
            leases = requests.request("GET", urlpaging, verify=False, auth=(gm_usr, gm_pwd)).json()
            temp_leases += leases['result']
        except json.decoder.JSONDecodeError:
            print('API call error, review username and password and confirm WAPI IP is reachable')
            return
    for ipadd in  temp_leases:  # Leases with status of FREE are not considered
        if ipadd['binding_state'].lower() in ['active', 'static']:
            nios_leases[ipadd['address']] = {'network_view': ipadd['network_view']}
    return nios_leases


def get_leases_bloxone(apiKey, max_results_b1_api):
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix['Authorization'] = 'Token'
    configuration.api_key['Authorization'] = apiKey
    leases_api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    token_b1 = {'Authorization': 'Token ' + apiKey}
    ip_spaces = find_space_name_from_id( token_b1)
    temp_leases = []
    b1_leases = {}
    offset = 0
    list_leases =  leases_api_instance.lease_list(limit=max_results_b1_api)
    temp_leases +=  list_leases.results
    while isinstance( list_leases, bloxonedhcpleases.LeasesListLeaseResponse) and (
            len( list_leases.results) == max_results_b1_api):
        offset += max_results_b1_api + 1
        try:
            list_leases =  leases_api_instance.lease_list(offset=str(offset), limit=str(max_results_b1_api))
            temp_leases +=  list_leases.results
        except ApiException as e:
            print("Exception when calling LeaseApi->lease_list: %s\n" % e)
    for lease in  temp_leases:
        if lease.state.lower() in ['issued', 'used']:   # In BloxOne Leases States are Issued, Used or Freed
                                                        # (NIOS: Active, Static)
            b1_leases.update({lease.address: {'network_view': ip_spaces[lease.space]}})
    return b1_leases


def get_leases_grid_backup( backup_file):  # Returns nios_leases extracted from Grid Backup file
    # ['_ref', 'address', 'binding_state', 'network', 'network_view']
    list_objects = []
    netviews = {}
    nios_leases = {}

    if tarfile.is_tarfile( backup_file):
        print('Extracting DB from Grid Backup')
        tar = tarfile.open( backup_file, "r:gz")
        xml_file = tar.extractfile('onedb.xml')
    else:
        print('Not a Grid Backup file, trying onedb.xml')
        xml_file = open( backup_file, 'r')
    try:
        xml_content =  xml_file.read()
        objects = xmltodict.parse(xml_content)
        objects = objects['DATABASE']['OBJECT']
        for obj in objects:
            anobject = {}
            for item in (obj['PROPERTY']):
                anobject[item['@NAME']] = item['@VALUE']
            list_objects.append(anobject)
        for ob in  list_objects:
            if ob['__type'] == '.com.infoblox.dns.network_view':
                netviews[ob['id']] = ob['name']
        for ob in  list_objects:
            if (ob['__type'] == '.com.infoblox.dns.lease') and (
                    ob['binding_state'].lower() in ['active', 'static']):
                tempobject = {}
                tempobject = {'network_view': netviews[ob['network_view']]}
                nios_leases[ob['ip_address']] = tempobject
    except (FileNotFoundError, IOError):
        print('File not found')
        sys.exit()
    return nios_leases

def  compares_leases_nios_bloxone( b1_leases,list_subnets,nios_leases):  ## Receives NIOS leases as input (obtained via WAPI from the GM)
    for subnet in list_subnets:  # It also receives a list of the Subnets/Networks to use it as basis for the classification
        counter_nios = 0
        counter_bloxone = 0
        for ipadd in b1_leases:
            if IPv4Address(ipadd) in IPv4Network(subnet):   #IF IP within subnet
                if list_subnets[subnet]['network_view'] == b1_leases[ipadd]['network_view']:
                    counter_bloxone += 1  # If both conditions=TRUE, counter for that network increased ---> B1 leases
        for lease in nios_leases:
            if IPv4Address(lease) in IPv4Network(subnet):
                if list_subnets[subnet]['network_view'] == nios_leases[lease]['network_view']:
                    counter_nios += 1       # If both conditions=TRUE, counter for that network increased ---> NIOS leases
        list_subnets[subnet].update({'leasesNIOS':  counter_nios, 'leasesBloxOne':  counter_bloxone})
    return list_subnets


# noinspection PyUnresolvedReferences
def format_gsheet(wks):  ## Applies a bit of formatting to the Google Sheet document created
    body = {"requests": [{"autoResizeDimensions": {
        "dimensions": {"sheetId": wks.id, "dimension": "COLUMNS", "startIndex": 0, "endIndex": 8}}}]}
    wks.spreadsheet.batch_update(body)
    set_frozen(wks, rows=1)
    fmt = cellFormat(textFormat=textFormat(bold=True, foregroundColor=color(1, 1, 1)), horizontalAlignment='CENTER', backgroundColor=color(0, 0, 1))
    format_cell_ranges(wks, [('A1:D1', fmt)])
    return


def  paste_csv(csvcontent, gsheet, wksname):      #When gsheet exists, this function is used to import data without
                                                # deleting all the existing worksheets (unlike import_csv function)
    global lenghtreport
    gsheet.add_worksheet(wksname, lenghtreport + 20, 30)
    wksheet = gsheet.worksheet(wksname)
    body = {'requests': [{'pasteData': {'coordinate': {'sheetId': wksheet.id,'rowIndex': 0,'columnIndex': 0},
            'data': csvcontent,'type': 'PASTE_NORMAL','delimiter': ','}}]}
    gsheet.batch_update(body)
    return wksheet

def  csv_to_gsheet( gsheet_name,conf):  # Opens (if exists) or Creates (if doesn´t) a Gsheet
    myibmail = conf['ib_email']
    gc = gspread.service_account(conf['ib_service_acc'])
    timenow = time.strftime('%Y/%m/%d - %H:%M')
    wksname = 'Leases ' + timenow
    with open(conf['csvfile'], 'r') as f:
        csv_contents = f.read()
    # Email account is important, otherwise user will not be allowed to access or update the gsheet (it's created by a service account')
    try:  # Sheet exists, we just open the document. We cannot import the CSV because it will delete all other wksheets
        sheet = gc.open( gsheet_name)
        wks =  paste_csv( csv_contents, sheet, wksname)  # This function does not delete any existing worksheets
        format_gsheet(wks)
    except gspread.exceptions.SpreadsheetNotFound:  # Sheet does not exists --> New sheet, we can just import the csv
        try:
            sheet = gc.create( gsheet_name)
            # Adapt as required. By default, it will share the document with the service account email (mandatory) and with
            # the email address introduced previously with read/write permission. Anyone with the link can access in R/O
            sheet.share(gc.auth.service_account_email, role='writer', perm_type='user')
            sheet.share(myibmail, role='writer', perm_type='user')
            sheet.share('', role='reader', perm_type='anyone')
            gc.import_csv(sheet.id, csv_contents)  # deletes any existing worksheets & imports the data in sh.sheet1
            sheet = gc.open_by_key(sheet.id)  # use import_csv method only with new gsheets (to keep history record)
            wks = sheet.sheet1
            wks.update_title(wksname)
            format_gsheet(wks)
        except gspread.exceptions.GSpreadException:
            print("error while creating the Gsheet")
    print("Gsheet available on the URL", sheet.url)  # Returns the URL to the Gsheet
    print('Filter option was enabled so output is reduced to networks with any leases \n')
    return None


def print_report(report_leases, repType, filteroption, b1name, conf):
    # Generates the corresponding Report based on the option specified with -r [log,csv,gsheet]
    total_nios_leases = 0
    total_csp_leases = 0
    if repType != "log":  # With log option, we don´t need to created the CSV file so these lines will not be required in that case
        csvfile = open(conf['csvfile'], 'w', newline='')
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(['Network', 'NIOS Lease Count', 'BloxOne Lease Count', 'Comments'])
    for lease in report_leases:
        message = comment = ''
        count_b1_leases = report_leases[lease]['leases BloxOne']
        count_nios_leases = report_leases[lease]['leases NIOS']
        total_nios_leases = total_nios_leases + count_nios_leases
        total_csp_leases = total_csp_leases + count_b1_leases
        print_b1_leases = 'BloxOne Lease Count :' + str( count_b1_leases)
        warning = fg.red + print_b1_leases + fg.rs + comment
        if filteroption:    # If True, report networks with no leases are not included in the report
            if count_nios_leases == 0 and count_b1_leases == 0:
                continue
            elif count_nios_leases != 0 or count_b1_leases != 0:
                # Filter from the output those networks that didn´t have any leases in NIOS
                if ( count_nios_leases != 0 and count_b1_leases == 0) or ( count_nios_leases >= ( count_b1_leases * 5)):
                    # There were leases in NIOS but there are none in BloxOne --> Review
                    message = warning
                    comment = ' BloxOne potential issue: review number of leases'
                else:
                    message = print_b1_leases
                    comment = ''
        elif not filteroption:           # If filteroption = False, all networks are included in the report
            if count_nios_leases == 0 and count_b1_leases == 0:
                message = print_b1_leases
                comment = ''
            elif ( count_nios_leases != 0 and count_b1_leases == 0) or ( count_nios_leases >= ( count_b1_leases * 5)):
                message = warning
                comment = ' BloxOne potential issue: review number of leases'
            else:
                message = print_b1_leases
                comment = ''
        print('Network :', lease.ljust(18), 'NIOS Lease Count :', str( count_nios_leases).ljust(8), message)
        if repType != "log":
            spamwriter.writerow([lease, str( count_nios_leases), str( count_b1_leases),comment])
    print('Total number of leases in NIOS :', total_nios_leases)
    print('Total number of leases in BloxOne :', total_csp_leases)
    if repType != "log":
        spamwriter.writerow('')
        spamwriter.writerow(['Total number of leases in NIOS :', total_nios_leases])
        spamwriter.writerow(['Total number of leases in BloxOne :','', total_csp_leases])
        csvfile.close()
        t2 = time.perf_counter() - t1
        print(f' Process completed. Execution time : {t2:0.2f}s ')
        if repType == "csv":
                print('Results have been exported to the CSV file', conf['csvfile'])
        elif repType == "gsheet":  # With log option, we don´t need to created the CSV file so this lines are not required in that case
            gsheet_name = input('Name of the Gsheet for output [or press enter for "leases - <CUSTOMER NAME>"\n') or ('nios2b1ddi leases - ' + b1name)
            csv_to_gsheet( gsheet_name,conf)
    return None


def get_args():  ## Handles the arguments passed to the script from the command line
    # Parse arguments
    usage = ' -c b1config.ini -i {"wapi", "db"} [-r {"log","csv","gsheet"}] [ --delimiter {",",";"} ] [ --yaml <yaml file> ] [ --help ] [ -f ] [ -n ]'
    description = 'This script gets DHCP leases from NIOS (via WAPI or from a Grid Backup), collects BloxOne DHCP leases from B1DDI API and compares network by network the number of leases on each platform'
    epilog = ''' sample b1config.ini 
            [BloxOne]
            url = 'https://csp.infoblox.com'
            api_version = 'v1'
            api_key = 'CSP API KEY '
            ib_email = 'email address used to access Google Sheets user@example.com'
            dbfile = 'path to Grid backup file or Grid DB (onedb.xml)'
            csvfile = 'temp csv file used to generate the report'
            gm_ip = 'IP address of the Grid Master'	
            gm_usr = 'username'
            gm_pwd = 'password'
            ib_service_acc = 'JSON file with the Google Sheets service account details' '''
    par = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=description, add_help=False, usage='%(prog)s' + usage, epilog=epilog)
    # Required Argument(s)
    required = par.add_argument_group('Required Arguments')
    req_grp = required.add_argument
    req_grp('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    req_grp('-i', '--interface', action="store", dest="interface", help="source from where NIOS data will be imported", choices=['wapi', 'db'], required=True)
    # Optional Arguments(s)
    optional = par.add_argument_group('Optional Arguments')
    opt_grp = optional.add_argument
    req_grp('-r', action="store", dest="report", help="Defines the type of reporting that will be produced", choices=['log', 'csv', 'gsheet'], default='log')
    opt_grp('-f', '--filter', action='store_true', help='Excludes networks with 0 leases from the report', dest='filter')
    opt_grp('-n', '--niosonly', action='store_true', help='Only captures the DHCP leases from NIOS', dest='niosonly')
    opt_grp('--delimiter', action="store", dest="csvdelimiter", help="Delimiter used in CSV data file", choices=[',', ';'])
    opt_grp('--yaml', action="store", help="Alternate yaml file for supported objects", default='objects.yaml')
    # Informational Arguments(s)
    opt_grp('--version', action='version', version='%(prog)s ' + __version__)
    opt_grp('--debug', action='store_true', help=argparse.SUPPRESS, dest='debug')
    opt_grp('-h', '--help', action='help', help='show this help message and exit')
    
    return par.parse_args(args=None if sys.argv[1:] else ['-h'])


##########################################################


def main():
    b1_leases = {}
    max_results_b1_api = 5000  # This value limits the amount of results received for an API call through BloxOne API
    max_results_wapi = 10000  # This value limits the amount of results received API call performed through NIOS WAPI
    args = get_args()
    if not args.niosonly:
        b1name = checks_csp_tenant(args.config).split(' ')[0]
    conf = read_b1_ini(args.config)
    token_b1 = {'Authorization': 'Token ' + conf['api_key']}
    ip_spaces = find_space_name_from_id( token_b1)
    if not args.niosonly: 
        b1_leases = get_leases_bloxone(conf['api_key'], max_results_b1_api)
    else:
        print('Option -n selected: Ignoring BloxOne leases')
        args.filter = True
    list_subnets = get_subnets( token_b1, ip_spaces)  # List of all subnets in B1
    #lengthreport = len(list_subnets)
    if args.interface == 'wapi':  # It will get NIOS leases from the Grid WAPI interface
        nios_leases =  get_leases_wapi(max_results_wapi,conf)
    elif args.interface == 'db':  # NIOS leases will be obtained from a Grid backup file or database file in XML format (default onedb.xml)
        try:
            xml_file = conf['dbfile']
            nios_leases = get_leases_grid_backup( xml_file)
        except FileNotFoundError as e:
            print('Exception when collecting Grid Backup Leases: %s\n' % e)
    # After collecting all leases from NIOS and BloxOne, it compares both sets and creates a report with the differences
    report_leases =  compares_leases_nios_bloxone( b1_leases, list_subnets, nios_leases)
    print_report(report_leases, args.report, args.filter, b1name, conf)
    # It will display the results of the analysis: - directly on the terminal (log)
    #  - export to a CSV file (csv)
    #  - export to a Google Sheet (gsheet) **(requires service_account)


if __name__ == "__main__":
    # execute only if run as a script
    main()
    sys.exit()
