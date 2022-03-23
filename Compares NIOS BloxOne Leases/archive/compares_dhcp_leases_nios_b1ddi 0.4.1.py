#!/usr/local/bin/python3
# run as: python3 compares_dhcp_leases_nios_b1ddi.py -c config.ini [ -i wapi | db ] [ -r log|csv|gsheet ] [ -n ] [ -f ] [ --yaml <yaml file> ] [ --help ] [ --delimiter x ]

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

This script gets the DHCP leases from NIOS Grid and compares with BloxOne leases
within the context of a NIOS to BloxOne DDI data migration (data validation)

compares_dhcp_leases_nios_b1ddi.py -c b1config.ini [ -r log|csv|gsheet] [ -f ][ -n ][ --delimiter x ] [ --yaml <yamlfile> ] [--help]]'

# PARAMETERS

The script requires the following command-line arguments.

    -c : path to configuration file for the bloxone python package. Here is a sample of this file:

    [BloxOne]
    url = 'https://csp.infoblox.com'
    api_version = 'v1'
    api_key = 'CSP API KEY '
    ib_email = 'email address used to access Google Sheets user@example.com'
    dbfile = 'path to onedb.xml or grid backup'
    csvfile = 'temp csv file used to generate a CSV report with the results'
    ib_service_acc = 'JSON file with the Google Sheets service account details '
        
    -r : method to be used to present the results of the script (log to terminal, csv file or Google sheet)
    -f : if present, networks with no leases will be ignored on the report (better readibility)
    -n : if present, Only NIOS leases are captured. BloxOne leases will be ignored

# INPUT

The script takes collects the required input from three sources:

* NIOS:         - GRID BACKUP:      Gets the information from a Grid backup file (XXX.bak) or the NIOS DB itself (onedb.xml)
* BloxOne:      - BloxOne API (hosted on the Infoblox Cloud Services Portal)

# OUTPUT

The output can be currently presented in one of the following three formats (can be selected with -r option):

* LOG       - Results are only presented on the local console / terminal
* CSV       - Results are exported to a local CSV file
* GSHEET    - Results are exported to a Google Sheet document. Requires JSON configuration file with Gsheet service account 
                (+INFO here https://developers.google.com/sheets/api/guides/authorizing)

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
* 0.3.1     Added option to only gather the active leases in NIOS (ignores BloxOne)            
* 0.3.2     Integrated functions (verify_api_key, read_b1_ini) from external custom module mod.py into the main script, mod.py has been removed from the repository               
* 0.3.3     Removed support for NIOS WAPI as a source for NIOS leases --> Inefficient and slow, replaced with DB or Grid Backup instead which should be always available
* 0.4.0     Added logging to local file. Simplified the function to print the output report

# TECHNICAL REFERENCE

* NIOS
        BINDING_STATES IN NIOS: ABANDONED, ACTIVE, BACKUP,DECLINED.EXPIRED,FREE,OFFERED,RELEASED,RESET,STATIC

        ABANDONED: The Infoblox appliance cannot lease this IP address because the appliance received a response when it pinged the address.
        ACTIVE: The lease is currently in use by a DHCP client.
        EXPIRED: The lease was in use, but the DHCP client never renewed it, so it is no longer valid.
        FREE: The lease is available for clients to use.
        RELEASED: The DHCP client returned the lease to the appliance.     
"""
__version__ = '0.4'
__author__ = 'Fernando Rodriguez'
__author_email__ = 'frodriguez@infoblox.com'

import bloxone
import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
import argparse
from argparse import RawDescriptionHelpFormatter
from ipaddress import IPv4Address, IPv4Network
from sty import fg
import requests
import xmltodict
import sys
import ipaddress
import json
import gspread
from gspread_formatting import *
import logging as log
import csv
import time
import tarfile
import re
import configparser
import os

requests.packages.urllib3.disable_warnings()
lenghtreport = 0
t1 = time.perf_counter()
dateTime = time.strftime("%Y%m%d%H%M%S")

# Custom Exceptions

class IniFileSectionError(Exception):
    '''
    Exception for missing section in ini file
    '''
    pass


class IniFileKeyError(Exception):
    '''
    Exception for missing key in ini file
    '''
    pass


class APIKeyFormatError(Exception):
    '''
    Exception for API key format mismatch
    '''
    pass


def validate_ip(ip):                                                        # Confirm that an IP address is valid
    try:
        ipaddress.ip_address(ip)
        result = True
    except ValueError:
        result = False
    return result


def read_b1_ini(ini_filename):
    '''
    Open and parse ini file
    Parameters:
        ini_filename (str): name of inifile
    Returns:
        config (dict): Dictionary of BloxOne configuration elements
    Raises:
        IniFileSectionError
        IniFileKeyError
        APIKeyFormatError
        FileNotFoundError
    '''
    # Local Variables
    cfg = configparser.ConfigParser()
    config = {}
    ini_keys = ['url', 'api_version', 'api_key', 'ib_email', 'dbfile', 'csvfile', 'ib_service_acc']
    # Check for inifile and raise exception if not found
    if os.path.isfile(ini_filename):
        # Attempt to read api_key from ini file
        try:
            cfg.read(ini_filename)
        except configparser.Error as err:
            log.error(err)
        # Look for BloxOne section
        if 'BloxOne' in cfg:
            for key in ini_keys:
                # Check for key in BloxOne section
                if key in cfg['BloxOne']:
                    config[key] = cfg['BloxOne'][key].strip("'\"")
                    log.debug('Key {} found in {}: {}'.format(key, ini_filename, config[key]))
                else:
                    log.error('Key {} not found in BloxOne section.'.format(key))
                    raise IniFileKeyError('Key "' + key + '" not found within [BloxOne] section of ini file {}'.format(ini_filename))
        else:
            log.error('No BloxOne Section in config file: {}'.format(ini_filename))
            raise IniFileSectionError('No [BloxOne] section found in ini file {}'.format(ini_filename))
        # Verify format of API Key
        if verify_api_key(config['api_key']):
            log.debug('API Key passed format verification')
        else:
            log.debug('API Key {} failed format verification'.format(config['api_key']))
            raise APIKeyFormatError('API Key {} failed format verification'.format(config['api_key']))
    else:
        raise FileNotFoundError('ini file "{}" not found.'.format(ini_filename))
    return config


def initialize_logger(is_debug):
    """ Initialize Logger """
    logger = log.getLogger()
    logger.setLevel(log.DEBUG)

    # Send to STDOUT
    handler = log.StreamHandler()
    if is_debug:
        handler.setLevel(log.DEBUG)
    else:
        handler.setLevel(log.INFO)
    formatter = log.Formatter("%(asctime)s  %(levelname)s - %(message)s", datefmt='%Y-%m-%d:%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    log_file = os.path.basename(__file__)
    log_file = os.path.splitext(log_file)[0]

    # Send to file
    # noinspection PyCompatibility
    handler = log.FileHandler(f'{log_file}-import-{dateTime}.log')
    if is_debug:
        handler.setLevel(log.DEBUG)
    else:
        handler.setLevel(log.INFO)
    formatter = log.Formatter("%(asctime)s %(levelname)s - %(message)s",datefmt='%Y-%m-%d:%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def verify_api_key(apikey):
    '''
    Verify format of API Key
    Parameters: 
    apikey (str): api key
    
    Returns:
        bool: True is apikey passes format validation
    '''
    if re.fullmatch('[a-z0-9]{32}|[a-z0-9]{64}', apikey, re.IGNORECASE):
        status = True
    else:
        status = False

    return status


def checks_csp_tenant(config):                                              # Displays the CSP tenant we´re accessing and will validate our API key
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
        log.info(f'{b1user} is now accessing {b1tenant}')
        return b1tenant
    else:
        sys.exit()


def find_space_name_from_id(token_b1):                                      # Get the name of the IP Spaces from the Space Id. Grid DB uses integers to
                                                                            # identify the network views which is not helpful (ID for 'default' = 0)
    ip_spaces = {}
    url = "https://csp.infoblox.com/api/ddi/v1//ipam/ip_space?_fields=id,name"
    response = requests.request("GET", url, headers= token_b1)
    try:
        spaces = json.loads(response.content)['results']
        for i in spaces:
            ip_spaces[i['id']] = i['name']
    except FileNotFoundError:
        log.error('Error: JSON File not found')     
    except json.decoder.JSONDecodeError:
        log.error('Error: Invalid JSON file')     
    return ip_spaces


def get_subnets(token_b1, ip_spaces):                                       # Get all the networks available in BloxOne for this tenant
    list_subnets = {}
    url = "https://csp.infoblox.com/api/ddi/v1/ipam/subnet?_fields=address,cidr,space"
    response = requests.request("GET", url, headers= token_b1)
    subnets = response.json()['results']
    for net in subnets:
        cidr = str(net.pop('address')) + '/' + str(net.pop('cidr'))
        net.update({'network_view': ip_spaces[net.pop('space')], 'leasesNIOS': 0, 'leasesBloxOne': 0})
        list_subnets[cidr] = net
    return list_subnets  # Output is a dictonary with the networks as indexes. This objects will be the basis for the comparson between NIOS and BloxOne DHCP leases.
    # Leases will be assigned to their correponding subnet (within the correct ip space / network view) where every leases will increase the counters
    # This process will be performed both for NIOS and BloxOne to get clear picture of the leases being handled by CSP after the migration from NIOS
    # Which might facilitate the detection of potential issues after the go live

def get_leases_bloxone(apiKey, max_results_b1_api):
    
    configuration = bloxonedhcpleases.Configuration()
    configuration.api_key_prefix['Authorization'] = 'Token'
    configuration.api_key['Authorization'] = apiKey
    leases_api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
    token_b1 = {'Authorization': 'Token ' + apiKey}
    ip_spaces = find_space_name_from_id(token_b1)
    temp_leases = []
    b1_leases = []
    offset = 0
    log.info('Obtaining leases from BloxOne API')
    list_leases =  leases_api_instance.lease_list(limit=max_results_b1_api)
    temp_leases +=  list_leases.results
    while isinstance(list_leases, bloxonedhcpleases.LeasesListLeaseResponse) and (
            len(list_leases.results) == max_results_b1_api):
        offset += max_results_b1_api + 1
        try:
            list_leases =  leases_api_instance.lease_list(offset=str(offset), limit=str(max_results_b1_api))
            temp_leases +=  list_leases.results
        except ApiException as e:
            log.error('Exception when calling LeaseApi->lease_list: %s\n" % e')
    for lease in temp_leases:
        if lease.state.lower() in ['issued', 'used']:   # In BloxOne Leases States are Issued, Used or Freed
                                                        # (NIOS: Active, Static)
            b1_leases.append({'ip_address': lease.address, 'network_view': ip_spaces[lease.space]})
    print(b1_leases)
    return b1_leases


def get_leases_grid_backup( backup_file):                                   # Returns nios_leases extracted from Grid Backup file
                                                                            # ['_ref', 'address', 'binding_state', 'network', 'network_view']
    list_objects = []
    netviews = {}
    nios_leases = []
    list_nios_subnets = {}
    
    if tarfile.is_tarfile( backup_file):
        log.info('Extracting NIOS database from Grid Backup')
        tar = tarfile.open( backup_file, "r:gz")
        xml_file = tar.extractfile('onedb.xml')
    else:
        print('Not a Grid Backup file, trying onedb.xml')
        xml_file = open( backup_file, 'r')
        
    try:
        log.info('Obtaining leases from NIOS database')
        xml_content =  xml_file.read()
        objects = xmltodict.parse(xml_content)
        objects = objects['DATABASE']['OBJECT']
        for obj in objects:
            anobject = {}
            for item in (obj['PROPERTY']):
                anobject[item['@NAME']] = item['@VALUE']
            list_objects.append(anobject)
            
        for ob in list_objects:

            if ob['__type'] == '.com.infoblox.dns.network_view':
                netviews[ob['id']] = ob['name']
        
        for view in netviews:
            list_nios_subnets[netviews[view]] = {}
            for ob in list_objects:
                if ob['__type'] == '.com.infoblox.dns.network':
                    cidr = ob['address'] + "/" + ob['cidr']
                    list_nios_subnets[netviews[view]][cidr] = {'leasesNIOS': 0}
                                
        for ob in  list_objects:
            if (ob['__type'] == '.com.infoblox.dns.lease') and (
                    ob['binding_state'].lower() in ['active', 'static']):
                nios_leases.append({'ip_address': ob['ip_address'], 'network_view': netviews[ob['network_view']]})
        print(nios_leases)
    except (FileNotFoundError, IOError):
        log.error('File not found')
        sys.exit()
    return nios_leases, list_nios_subnets


def compares_leases_nios_bloxone(b1_leases,list_b1_subnets,nios_leases, list_nios_subnets):
    total_leases_nios = 0

    log.info('Comparing NIOS and BloxOne DHCP leases per network')
    for subnet in list_subnets:                                             # It also receives a list of the Subnets/Networks to use it as basis for the classification
        counter_nios = 0
        counter_bloxone = 0
        
        for ipadd in b1_leases:
            if IPv4Address(ipadd) in IPv4Network(subnet):                   # If valid IP within subnet
                if list_subnets[subnet]['network_view'] == b1_leases[ipadd]['network_view']:
                    counter_bloxone += 1                                    # If both conditions=TRUE, counter for that network increased ---> B1 leases
                    
        for lease in nios_leases:
            if IPv4Address(lease) in IPv4Network(subnet):
                if list_subnets[subnet]['network_view'] == nios_leases[lease]['network_view']:
                    counter_nios += 1                                       # If both conditions=TRUE, counter for that network increased ---> NIOS leases
                    
        list_subnets[subnet].update({'leasesNIOS':  counter_nios, 'leasesBloxOne':  counter_bloxone})
        total_leases_nios += counter_nios
    log.info('Analysis completed. Printing report')
    return list_subnets, total_leases_nios


def format_gsheet(wks):                                                     # Applies a bit of formatting to the Google Sheet document created
    body = {"requests": [{"autoResizeDimensions": {
        "dimensions": {"sheetId": wks.id, "dimension": "COLUMNS", "startIndex": 0, "endIndex": 8}}}]}
    wks.spreadsheet.batch_update(body)
    set_frozen(wks, rows=1)
    fmt = cellFormat(textFormat=textFormat(bold=True, foregroundColor=color(1, 1, 1)), horizontalAlignment='CENTER', backgroundColor=color(0, 0, 1))
    format_cell_ranges(wks, [('A1:D1', fmt)])
    return


def  paste_csv(csvcontent, gsheet, wksname):                                # When gsheet exists, this function is used to import data without
                                                                            # deleting all the existing worksheets (unlike import_csv function)
    global lenghtreport
    gsheet.add_worksheet(wksname, lenghtreport + 20, 30)
    wksheet = gsheet.worksheet(wksname)
    body = {'requests': [{'pasteData': {'coordinate': {'sheetId': wksheet.id,'rowIndex': 0,'columnIndex': 0},
            'data': csvcontent,'type': 'PASTE_NORMAL','delimiter': ','}}]}
    gsheet.batch_update(body)
    return wksheet


def csv_to_gsheet( gsheet_name,conf):                                       # Opens (if exists) or Creates (if doesn´t) a Gsheet
    myibmail = conf['ib_email']
    try:
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
                log.error("error while creating the Gsheet")
        log.info(f'Gsheet available on the URL {sheet.url}')  # Returns the URL to the Gsheet
        log.info('Filter option was enabled so output is reduced to networks with any leases \n')
    except FileNotFoundError:
        log.error("Error: JSON File not found")        
    except json.decoder.JSONDecodeError:
        log.error("Error: Invalid JSON file")
    return None


def print_report(report_leases, repType, filteroption, b1_name, conf):
    # Generates the corresponding Report based on the option specified with -r [log,csv,gsheet]
    total_nios_leases = 0
    total_csp_leases = 0
    if repType != "log":  # With log option, we don´t need to created the CSV file so these lines will not be required in that case
        csvfile = open(conf['csvfile'], 'w', newline='')
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(['Network', 'NIOS Lease Count', 'BloxOne Lease Count', 'Comments'])
    for lease in report_leases:
        comment = ''
        count_b1_leases = report_leases[lease]['leasesBloxOne']
        count_nios_leases = report_leases[lease]['leasesNIOS']
        total_nios_leases = total_nios_leases + count_nios_leases
        total_csp_leases = total_csp_leases + count_b1_leases
        
        if filteroption:                    # If True, report networks with no leases are not included in the report
            if count_nios_leases == 0 and count_b1_leases == 0:
                continue                                                # Filter from the output those networks that didn´t have any leases in NIOS
            elif (count_nios_leases != 0 and count_b1_leases == 0) or (count_nios_leases >= (count_b1_leases * 5)):
                    comment = ' --> Review'               # Networks to review (no leases in B1 but there were leases in NIOS)
        else:                               # If filteroption = False, all networks are included in the report
            if count_nios_leases == 0 and count_b1_leases == 0:
                comment = ''
            elif (count_nios_leases != 0 and count_b1_leases == 0) or ( count_nios_leases >= ( count_b1_leases * 5)):
                comment = ' --> Review'                  # Networks to review (no leases in B1 but there were leases in NIOS)
                
        log.info(f'Network : {lease.ljust(18)} NIOS Lease Count : {str(count_nios_leases).ljust(8)} BloxOne Leases Count : {count_b1_leases} {comment}')
        if repType != "log":
            spamwriter.writerow([lease, str(count_nios_leases), str(count_b1_leases), comment])
    log.info(f'Total number of leases in NIOS : {total_nios_leases}')
    log.info(f'Total number of leases in BloxOne : {total_csp_leases}')
    if repType != "log":
        spamwriter.writerow('')
        spamwriter.writerow(['Total number of leases in NIOS :', total_nios_leases])
        spamwriter.writerow(['Total number of leases in BloxOne :','', total_csp_leases])
        csvfile.close()
        t2 = time.perf_counter() - t1
        log.info(f'Process completed. Execution time : {t2:0.2f}s ')
        if repType == "csv":
            log.info(f'Results have been exported to the CSV file  {conf["csvfile"]}')
        elif repType == "gsheet":  # With log option, we don´t need to created the CSV file so this lines are not required in that case
            gsheet_name = input('Name of the Gsheet for output [or press enter for "leases - <CUSTOMER NAME>"\n') or ('nios2b1ddi leases - ' + b1_name)
            csv_to_gsheet( gsheet_name,conf)
    return None


def get_args():                                                             # Handles the arguments passed to the script from the command line
    # Parse arguments
    usage = ' -c b1config.ini [-r {"log","csv","gsheet"}] [ --delimiter {",",";"} ] [ --yaml <yaml file> ] [ --help ] [ -f ] [ -n ]'
    description = 'This script gets DHCP leases from NIOS Grid Backup or XML file, collects BloxOne DHCP leases from B1DDI API and compares network by network the number of leases on each platform'
    epilog = ''' sample b1config.ini 
            [BloxOne]
            url = 'https://csp.infoblox.com'
            api_version = 'v1'
            api_key = 'CSP API KEY '
            ib_email = 'email address used to access Google Sheets user@example.com'
            dbfile = 'path to Grid backup file or Grid DB (onedb.xml)'
            csvfile = 'temp csv file used to generate the report'
            ib_service_acc = 'JSON file with the Google Sheets service account details' ''' # This option might not be available for most people
    par = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=description, add_help=False, usage='%(prog)s' + usage, epilog=epilog)
    
    # Required Argument(s)
    required = par.add_argument_group('Required Arguments')
    req_grp = required.add_argument
    req_grp('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
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


def main():
    b1_leases = {}
    nios_leases = {}
    max_results_b1_api = 5000  # This value limits the amount of results received for an API call through BloxOne API
    args = get_args()
    initialize_logger(args.debug)
    conf = read_b1_ini(args.config)
    token_b1 = {'Authorization': 'Token ' + conf['api_key']}
    ip_spaces = find_space_name_from_id( token_b1)

    try:                                                # NIOS leases will be obtained from a Grid backup file or database file in XML format (default onedb.xml)
        grid_bk_file = conf['dbfile']                   # Grid Backup/DB filename: .bak, .tar.gz or onedb.xml 
        nios_leases, list_nios_subnets = get_leases_grid_backup(grid_bk_file)
    except FileNotFoundError as e:
        log.error('Exception when collecting Grid Backup Leases: %s\n' % e)
        
    if not args.niosonly:       # When option -n is used, only NIOS leases are requested so it is not necessary to get BloxOne lease information
        b1_name = checks_csp_tenant(args.config).split(' ')[0]
        b1_leases = get_leases_bloxone(conf['api_key'], max_results_b1_api)
    else:
        log.info('Option -n selected: Ignoring BloxOne leases')
        
    list_b1_subnets = get_subnets( token_b1, ip_spaces)    # List of all subnets in B1
    lengthreport = len(list_b1_subnets)

    # After collecting all leases from NIOS and BloxOne, it compares both sets and creates a report with the differences
    report_leases, total_nios_leases =  compares_leases_nios_bloxone(b1_leases, list_b1_subnets, nios_leases, list_nios_subnets)
    
    if args.niosonly:
        t2 = time.perf_counter() - t1
        log.info(f'Active DHCP leases in NIOS:  {total_nios_leases}')
        log.info(f'Process completed. Execution time : {t2:0.2f}s ')
    else:
        print_report(report_leases, args.report, args.filter, b1_name, conf)    # It will display the results: - directly on the terminal (log)
                                                                                #  - export to a CSV file (csv)
                                                                                #  - export to a Google Sheet (gsheet) **(requires service_account)


if __name__ == "__main__":
    # execute only if run as a script
    main()
    sys.exit()