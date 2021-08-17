#!/usr/bin/env python3
# This script receives as input a CSV file with at least a column named "mac_address" with a list of valid MAC addresses. It will then create an IPv4 Harware Filter with those MACs

import csv
import bloxone
import json
import logging as log
import argparse
from argparse import RawDescriptionHelpFormatter
import sys

list_macs = []

def get_args():
    # Parse arguments
    usage = ' -c b1config.ini -d nios_csv_data.csv [ --delimiter x ] [ --help ]'

    description = 'This is a NIOS CSV to Infoblox BloxOne DDI migration tool'

    epilog = '''
    sample b1config.ini
    
        [BloxOne]
        url = 'https://csp.infoblox.com'
        api_version = 'v1'
        api_key = 'API_KEY'
        
    # INPUT
    This script receives as input a CSV file with at least a column named "mac_address"
    with a list of valid MAC addresses. It will then create an IPv4 Harware Filter with
    with those MACs
    
    # OUTPUT

    Logging actions to standard out:
     '''

    par = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                                  description=description,
                                  add_help=False,
                                  usage='%(prog)s' + usage,
                                  epilog=epilog)

    # Required Argument(s)
    required = par.add_argument_group('Required Arguments')
    req_grp = required.add_argument
    req_grp('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    req_grp('-d', '--csvfile', action="store", dest="csvfilename", help="Path to CSV data file", required=True)

    # Optional Arguments(s)
    optional = par.add_argument_group('Optional Arguments')
    opt_grp = optional.add_argument
    opt_grp('--delimiter', action="store", dest="csvdelimiter", help="Delimiter used in CSV data file", required=False)
    opt_grp('--yaml', action="store", help="Alternate yaml file for supported objects", default='objects.yaml')
    opt_grp('--debug', action='store_true', help=argparse.SUPPRESS, dest='debug', required=False)
    opt_grp('-h', '--help', action='help', help='show this help message and exit')

    return par.parse_args(args=None if sys.argv[1:] else ['-h'])

def get_error(error_response):
    message = eval(error_response)
    return message['error'][0]['message']

def initialize_logger(is_debug):
    logger = log.getLogger()
    logger.setLevel(log.DEBUG)
    # Send to STDOUT
    handler = log.StreamHandler()
    if is_debug:
        handler.setLevel(log.DEBUG)
    else:
        handler.setLevel(log.INFO)
    formatter = log.Formatter("%(asctime)s  %(levelname)s - %(message)s",datefmt='%Y-%m-%d:%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    formatter = log.Formatter("%(asctime)s %(levelname)s - %(message)s",datefmt='%Y-%m-%d:%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return

def createsHwFilter (nameHwFilter, csvfilename, b1ddi): #Receives the name of the HW filter, the CSV file where the MACs are listed and the b1ddi object
    with open(csvfilename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            list_macs.append(row['mac_address']) #Creates a list of MAC addresses the HW Filter will consist of
    
    optFilterBody = {
        "name": nameHwFilter,
        "addresses": list_macs,
    }
    json_body = json.dumps(optFilterBody)
    response = b1ddi.create('/dhcp/hardware_filter', body=json_body)
    if response.status_code in b1ddi.return_codes_ok:
        json_response = json.loads(response.content)
        object_id = json_response["result"]["id"]
        log.info(f'Created Harware Filter {nameHwFilter} : {object_id}')
    else:
        message = get_error(response.text)

args = get_args()

b1ddi = bloxone.b1ddi(cfg_file= args.config)
initialize_logger(args.debug)
nameHwFilter = input('Please enter name for the Hardware Filter\n')
createsHwFilter (nameHwFilter, args.csvfilename, b1ddi)






