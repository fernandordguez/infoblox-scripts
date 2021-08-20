#!/usr/local/bin/python3

from __future__ import print_function
import time
import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
from pprint import pprint
import json
from argparse import RawDescriptionHelpFormatter
import argparse
import sys
from collections import defaultdict
from ipaddress import *
import ipaddress

def get_args():
    usage = ' -c b1config.ini -d nios_csv_data.csv [ --delimiter x ] [ --yaml <yaml file> ] [ --help ]'
    description = 'This is a NIOS CSV to Infoblox BloxOne DDI migration tool'
    epilog = ''
    # Parse arguments
    description = 'This is a NIOS CSV to Infoblox BloxOne DDI migration tool'
    par = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter,description=description,add_help=False,usage='%(prog)s' + usage,epilog=epilog)
    # Required Argument(s)
    required = par.add_argument_group('Required Arguments')
    req_grp = required.add_argument
    req_grp('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    req_grp('-d', '--csvfile', action="store", dest="csvfilename", help="Path to CSV data file", required=True)
    # Optional Arguments(s)
    optional = par.add_argument_group('Optional Arguments')
    opt_grp = optional.add_argument
    opt_grp('--hr', action="store_true", dest="hostaddr_to_reserved",help="Add reservations for host addresses defined within DHCP Ranges", required=False)
    opt_grp('--delimiter', action="store", dest="csvdelimiter", help="Delimiter used in CSV data file", required=False)
    opt_grp('--yaml', action="store", help="Alternate yaml file for supported objects", default='objects.yaml')
    opt_grp('--debug', action='store_true', help=argparse.SUPPRESS, dest='debug', required=False)
    #opt_grp('--version', action='version', version='%(prog)s ' + __version__)
    opt_grp('-h', '--help', action='help', help='show this help message and exit')
    opt_grp('-l --leases', action="store_true", dest="countleases", help="If included, it will compare the leases between NIOS and B1", default=False)
    return par.parse_args(args=None if sys.argv[1:] else ['-h'])


# Configure API key authorization: ApiKeyAuth
args = get_args()
configuration = bloxonedhcpleases.Configuration()
configuration.api_key['Authorization'] = args.config

# create an instance of the API class
api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
#filter = 'filter_example' # str |   A collection of response resources can be filtered by a logical expression string that includes JSON tag references to values in each resource, literal values, and logical operators. If a resource does not have the specified tag, its value is assumed to be null.  Literal values include numbers (integer and floating-point), and quoted (both single- or double-quoted) literal strings, and 'null'. The following operators are commonly used in filter expressions:  |  Op   |  Description               |  |  --   |  -----------               |  |  ==   |  Equal                     |  |  !=   |  Not Equal                 |  |  >    |  Greater Than              |  |   >=  |  Greater Than or Equal To  |  |  <    |  Less Than                 |  |  <=   |  Less Than or Equal To     |  |  and  |  Logical AND               |  |  ~    |  Matches Regex             |  |  !~   |  Does Not Match Regex      |  |  or   |  Logical OR                |  |  not  |  Logical NOT               |  |  ()   |  Groupping Operators       |         (optional)
#order_by = 'order_by_example' # str |   A collection of response resources can be sorted by their JSON tags. For a 'flat' resource, the tag name is straightforward. If sorting is allowed on non-flat hierarchical resources, the service should implement a qualified naming scheme such as dot-qualification to reference data down the hierarchy. If a resource does not have the specified tag, its value is assumed to be null.)  Specify this parameter as a comma-separated list of JSON tag names. The sort direction can be specified by a suffix separated by whitespace before the tag name. The suffix 'asc' sorts the data in ascending order. The suffix 'desc' sorts the data in descending order. If no suffix is specified the data is sorted in ascending order.         (optional)
#fields = 'fields_example' # str |   A collection of response resources can be transformed by specifying a set of JSON tags to be returned. For a “flat” resource, the tag name is straightforward. If field selection is allowed on non-flat hierarchical resources, the service should implement a qualified naming scheme such as dot-qualification to reference data down the hierarchy. If a resource does not have the specified tag, the tag does not appear in the output resource.  Specify this parameter as a comma-separated list of JSON tag names.         (optional)
#offset = 56 # int |   The integer index (zero-origin) of the offset into a collection of resources. If omitted or null the value is assumed to be '0'.          (optional)
#limit = 56 # int |   The integer number of resources to be returned in the response. The service may impose maximum value. If omitted the service may impose a default value.          (optional)
#page_token = 'page_token_example' # str |   The service-defined string used to identify a page of resources. A null value indicates the first page.          (optional)

try:
    # List Lease objects.
    #api_response = api_instance.lease_list(filter=filter, order_by=order_by, fields=fields, offset=offset, limit=limit, page_token=page_token)
    api_response = api_instance.lease_list()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling LeaseApi->lease_list: %s\n" % e)

# Load JSON test file with 50+ fake leases to test if the counters are updating correctly
with open('testleases.json', 'r') as ft:
    DHCPLeasesDict = json.load(ft)

with open(args.csvcountleases) as csv_file2:
    # The CSV file with the leases was delimited with ;. It might require to update to delimiter=',' if the input
    # CSV has different format
    csv_reader = csv.reader(csv_file2, delimiter=';')
    cidr = ''
    # Use a boolean to capture the header (row = 0)
    firstround = True
    for row in csv_reader:
        if firstround:
            csvheader = row
            firstround = False
            continue
        # temp_dict is a temp var that will be reset each iteration. Each record will capture the relevant fields
        # of that iteration and will be written only if source_lease_activity = yes
        temp_dict = {}
        for i in range(len(csvheader)):
            # Reset active value, which is the current lease count for any network.
            temp_dict['active'] = 0
            # description has already a CIDR network address that we will use to classify the leases
            if csvheader[i].lower() == 'description':
                cidr = row[i]
            elif csvheader[i].lower() == 'source_lease_activity':
                temp_dict['source_lease_activity'] = row[i]
            elif csvheader[i].lower() == 'network_view':
                temp_dict['network_view'] = row[i]
            elif csvheader[i].lower() == 'dhcp_members':
                temp_dict['dhcp_members'] = row[i]
            elif csvheader[i].lower() == 'dest_lease_activity':
                # if network present in past iteration, copy the old current leases into the dest_least field (to
                # compare past with present results)
                if cidr in last_pass_dict.keys():
                    temp_dict['dest_lease_activity'] = last_pass_dict[cidr]['active']
        # Update the field 
        for x in range(len(DHCPLeasesDict)):
            # Capture the error in case is not a valid IP address
            try:
                # If the lease IP address is contained in the IP network and the network_view
                #  also matches, then we know the IP can only belong to the current network/address block
                if ipaddress.IPv4Address(DHCPLeasesDict[x]['address']) in ipaddress.IPv4Network(cidr):
                    if DHCPLeasesDict[x]['space'] == temp_dict['network_view']:
                        temp_dict['active'] += 1
            except ipaddress.AddressValueError:
                print('IP address format not valid')
                continue
                # Record is added to the dictionary only if source_lease_activity=yes
        if temp_dict['source_lease_activity'].lower() == 'yes':
            leaseCountDict[cidr] = temp_dict
    # store the dictionary (JSON object) in a file to be used as reference in next iteration:
    with open(args.lastpass, 'w') as flast:
        json.dump(leaseCountDict, flast)
        # store a copy of the same dictionary to keep historical records
    with open(f"dhcpLeases-{dateTime}.json", 'w') as fhist:
        json.dump(leaseCountDict, fhist)
