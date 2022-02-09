#!/usr/bin/env python3


__version__ = '0.0.2'
__author__ = 'Brian Alaimo'
__author_email__ = 'balaimo@infoblox.com'

import argparse
import concurrent.futures
import csv

import json
import logging as log
import re
import sys
import time
from collections import defaultdict
import ipaddress
from ipaddress import ip_address
import bloxone
import yaml

# Start my timer
t = time.perf_counter()

# log events to the log file and to stdout
dateTime = time.strftime("%Y%m%d%H%M%S")
file_handler = log.FileHandler(filename=f'b1ddi-import-{dateTime}.log')
stdout_handler = log.StreamHandler(sys.stdout)
handlers = [file_handler, stdout_handler]

log.basicConfig(
    level=log.INFO,
    format='[%(asctime)s] %(levelname)s : %(message)s',
)

log.info(f"IBCSV Processing Started.")

# define some global variables
headerdict = {}
csvdata = defaultdict(list)
ipSpaceDict = {}
optionSpaceDict = {}
optionDict = {}
dhcphostDict = {}
dhcpGroupDict = {}
dnsHostDict = {}
dnsViewDict = {}
nsGroupDict = {}
slaveGroupDict = {}
fwdGroupDict = {}
tsigKeysDict = {}
namedACLDict = {}
stats = {}
b1ddi = ''
csv_error = ''
fieldmap = {}

# define some static structs
overrideTTL = {
    "ttl": {
        "action": "override"
    }
}

overrideLeasetime = {
    "lease_time": {
        "action": "override"
    }
}

# pre-compile some regexs for speed and readability
headerRegex = re.compile(r"^[\"']?header-", flags=re.IGNORECASE)
trailingDotRE = re.compile(r"\.$")
unsupportedTXTre = re.compile(r"[\"\'\\;]")  # "currently" TXT records do not support these.
isTrueRE = re.compile(r"^true$", flags=re.IGNORECASE)
isFalseRE = re.compile(r"^false$", flags=re.IGNORECASE)
isAnyRE = re.compile(r"^any$", flags=re.IGNORECASE)
isExtAttrRE = re.compile(r"^EA\-", flags=re.IGNORECASE)
isDhcpOptionRE = re.compile(r"^OPTION\-", flags=re.IGNORECASE)
extractTSIGfieldsRE = re.compile(r"(.+?)/(.+)/HMAC.(.+)/.+", flags=re.IGNORECASE)


def output_json(results):
    """ Pretty JSON to STDOUT for debugging """
    json_formatted_str = json.dumps(results, indent=4)
    print(json_formatted_str)


def build_global_dicts():
    """ This function stores IDs for various objects in global vars
        Create and populate dictionary containing DNS views """
    log.info("Getting IP spaces")
    json_results = b1ddi.get('/ipam/ip_space', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        ipSpaceDict[name] = obj_id

    # Create and populate dictionary containing DHCP Option Spaces
    log.info("Getting DHCP option spaces")
    json_results = b1ddi.get('/dhcp/option_space', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        # options spaces need to be indexed by ID
        optionSpaceDict[obj_id] = name

    # Create and populate dictionary containing DHCP Option Codes
    log.info("Getting DHCP option codes")
    json_results = b1ddi.get('/dhcp/option_code', _fields='code,id,option_space')
    results = json_results.json()['results']
    for item in results:
        code = str(item['code'])
        obj_id = item['id']

        # handle option space
        opt_space_id = item['option_space']
        opt_space_name = optionSpaceDict[opt_space_id]
        if opt_space_name not in ['dhcp4', 'dhcp6']:
            # There is a custom option space
            # Add it to the option name so it matches the CSV
            code = opt_space_name + '-' + code

        optionDict[code] = obj_id

    # Create and populate dictionary containing DHCP Hosts (Servers)
    log.info("Getting DHCP servers")
    json_results = b1ddi.get('/dhcp/host', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        dhcphostDict[name] = obj_id

    # Create and populate dictionary containing DHCP Groups
    log.info("Getting DHCP groups")
    json_results = b1ddi.get('/dhcp/ha_group', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        dhcpGroupDict[name] = obj_id

    # Create and populate dictionary containing DNS hosts
    log.info("Getting DNS servers")
    json_results = b1ddi.get('/dns/host', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        dnsHostDict[name] = obj_id

    # Create and populate dictionary containing DNS views
    log.info("Getting DNS views")
    json_results = b1ddi.get('/dns/view', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        dnsViewDict[name] = obj_id

    # Create and populate dictionary containing Auth NS Groups
    log.info("Getting Auth NS Groups")
    json_results = b1ddi.get('/dns/auth_nsg', _fields='name,id,external_primaries')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        if item['external_primaries']:
            # this is a slave group. Add it to the slave dict
            slaveGroupDict[name] = obj_id
        else:
            # this is a primary group. Add it to the nsg dict
            nsGroupDict[name] = obj_id

    # Create and populate dictionary containing Forwarder NS Groups
    log.info("Getting Forwarder NS Groups")
    json_results = b1ddi.get('/dns/forward_nsg', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        fwdGroupDict[name] = obj_id

    # Create and populate dictionary containing TSIG keys
    log.info("Getting TSIG keys")
    json_results = b1ddi.get('/keys/tsig', _fields='name,id')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']
        tsigKeysDict[name] = obj_id

    # Create and populate dictionary containing Named ACL keys
    log.info("Getting Named ACLs")
    json_results = b1ddi.get('/dns/acl', _fields='name,id,list')
    results = json_results.json()['results']
    for item in results:
        name = item['name']
        obj_id = item['id']

        # process list, look for tsig keys
        # trim fields that cause updating the ACl to fail
        # ERROR: Either reference or data for TSIG key can be provided but not both
        acl_list = []
        for aclitem in item['list']:
            if aclitem['element'] == 'tsig_key':
                tsig_id = aclitem['tsig_key']['key']
                aclitem['tsig_key'] = {'key': tsig_id}
            acl_list.append(aclitem)

        namedACLDict[name] = {'id': obj_id, 'list': acl_list}


def netmask_to_cidr(m_netmask):
    """ This will convert all Subnet Mask(i.e. 255.255.255.0) to CIDR(24) notation """
    return sum([bin(int(bits)).count("1") for bits in m_netmask.split(".")])


def map_csv_fields(csv_type, csv_field):
    """ This function finds what fields we want to capture from the IBCSV
        and maps them to the B1DDI names """
    if csv_type in fieldmap and csv_field in fieldmap[csv_type]["optional"]:
        return fieldmap[csv_type]["optional"][csv_field]
    else:
        # check if it's an extensible attribute
        if isExtAttrRE.match(csv_field):
            # It's an EA. We will keep all the EAs for now
            return csv_field
        else:
            # there was no match. return none.
            return None


def init_required_fields(csvobj):
    """ This function defines any required fields for the csv object type
        so it doesn't throw KeyError exceptions. The API will determine
        whether the missing field is really an error."""
    csv_type = csvobj["csvtype"]
    # walk the required fields and see if they are defined
    for fieldname in fieldmap[csv_type]["required"]:
        if fieldname not in csvobj:
            # define it as null. The API will error if it's needed.
            csvobj[fieldname] = ''


def get_dhcp_options(csvobj):
    """ Definition for getting DHCP options and putting them in right JSON format """
    dhcp_option_list = []
    unknown_option_list = []

    # now parse the object looking for dhcp options
    for key in csvobj.keys():

        if csvobj[key]:
            # this field has a value. check for dhcp options
            # First handle DHCP options referenced by a name instead of OPTION-XX
            if key == 'routers':

                # make the option body
                dhcp_opt = {
                    "type": "option",
                    "option_code": optionDict["3"],
                    "option_value": csvobj[key]
                }

                # add it to the list
                dhcp_option_list.append(dhcp_opt)

            elif key == 'domain_name_servers':

                # make the option body
                dhcp_opt = {
                    "type": "option",
                    "option_code": optionDict["6"],
                    "option_value": csvobj[key]
                }

                # add it to the list
                dhcp_option_list.append(dhcp_opt)

            elif key == 'domain_name':

                # make the option body
                dhcp_opt = {
                    "type": "option",
                    "option_code": optionDict["15"],
                    "option_value": csvobj[key]
                }

                # add it to the list
                dhcp_option_list.append(dhcp_opt)

            else:
                # Next see if it matches OPTION-XXX
                dhcp_opt_name, is_dhcp_opt = isDhcpOptionRE.subn('', key)
                if is_dhcp_opt:
                    # This is a DHCP option
                    # get the code and the value
                    try:
                        opt_code_id = optionDict[dhcp_opt_name]
                    except KeyError:
                        # option code not supported. add it to the list
                        unknown_option_list.append(dhcp_opt_name)
                        continue

                    opt_value = csvobj[key]

                    # start the option body
                    dhcp_opt = {
                        "type": "option",
                        "option_code": opt_code_id,
                        "option_value": opt_value
                    }

                    # add it to the list
                    dhcp_option_list.append(dhcp_opt)

    return dhcp_option_list, unknown_option_list


def reject_csv(csvobj, error_msg):
    """ # handle CSV errors """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    csvrow = csvobj["csvrow"]

    # fix the csvtype
    csvrow[0] = csvType

    # format the message
    error_msg = f"Line {line_num}: {error_msg}"

    # prepend the error, and output the error line
    csv_error.writerow([error_msg] + csvrow)


def add_tsig_key(line_num, keyname, keystring, keyalg):
    """ # add TSIG keys """
    keyalg = 'hmac_' + keyalg.lower()

    # make the body
    body = {
        "algorithm": keyalg,
        "name": keyname,
        "secret": keystring
    }

    jsonBody = json.dumps(body)

    log.info(f'{line_num} : Adding TSIG key : {keyname}')

    t1 = time.perf_counter()

    response = b1ddi.create('/keys/tsig', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num} : {t2:0.2f}s : Added TSIG key : {keyname} : {objID}')

        # add a new entry to the dict
        tsigKeysDict[keyname] = objID

        # return success with objID
        return objID

    else:
        log.error(
            f'{line_num} : {t2:0.2f}s : Failed to add TSIG key : {keyname} : {response.status_code} : {response.text}')
        # return error
        return 0


def add_named_acl(csvobj):
    """ import ACLs """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    namedACL = csvobj['name']

    if namedACL in namedACLDict:
        # it already exists, log an error
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} : {namedACL} already exists')
        reject_csv(csvobj, f'{line_num} : 0.00s : Failed to add {csvType} : {namedACL} already exists')
        # return error
        return 0

    # Start the body with an empty list
    body = {
        'name': namedACL,
        'list': []
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field:
                if b1field == 'comment':
                    # this is lease time.
                    # add it to the dhcp_config dict
                    body['comment'] = csvobj[csvField]

                else:
                    # check if it's an EA
                    (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                    if isExtAttr:
                        # It's an EA, so add it to the tags
                        tags[b1field] = csvobj[csvField]
                    else:
                        # Else just add it to the body
                        body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    jsonBody = json.dumps(body)

    log.info(f'{line_num} : Adding {csvType} : {namedACL}')

    t1 = time.perf_counter()

    response = b1ddi.create('/dns/acl', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num} : {t2:0.2f}s : Added {csvType} : {namedACL} : {objID}')

        # add a new entry to the dict
        namedACLDict[namedACL] = {'id': objID, 'list': []}
        # return success
        return 1
    else:
        log.error(
            f'{line_num} : {t2:0.2f}s : Failed to add {csvType} : {namedACL} : {response.status_code} : {response.text}')
        reject_csv(csvobj,
                   f'{line_num} : {t2:0.2f}s : Failed to add {csvType} : {namedACL} : {response.status_code} : {response.text}')
        # return error
        return 0


def add_named_acl_item(csvobj):
    lineNum = csvobj["line_num"]
    csvType = csvobj['csvtype']
    namedACL = csvobj['parent']

    # verify it exists
    if namedACL not in namedACLDict:
        # ACL doesn't exist, log an error
        logging.error(f'{lineNum} : 0.00s : Failed to add {csvType} : {namedACL} does not exist')
        reject_csv(csvobj, f'{lineNum} : 0.00s : Failed to add {csvType} : {namedACL} does not exist')
        # return error
        return 0

    # let's figure out what type of ACL this is
    if csvobj['address']:
        # This is an address

        # split off the action
        address = csvobj['address']
        fields = re.split('/', address)

        if len(fields) > 2:
            # We were given a network, put the mask back
            address = fields[0] + '/' + fields[1]
            action = fields[2]

        else:
            # we were given an IP address
            address = fields[0]
            action = fields[1]

        # build the aclitem
        aclitem = {
            "access": action.lower(),  # action wants to be lower case
        }

        if isAnyRE.match(address):
            # handle "any" ACL
            aclitem["element"] = "any"
        else:
            # add the IP to the item
            aclitem["address"] = address
            aclitem["element"] = "ip"

    elif csvobj['defined_acl']:

        # check that it exists
        definedACL = csvobj['defined_acl']

        defACLID = ''

        if definedACL in namedACLDict:
            defACLID = namedACLDict[definedACL]['id']
        else:
            # it doesn't exist, log an error
            logging.error(f'{lineNum} : 0.00s : Failed to add {csvType} : ACL {definedACL} does not exist')
            reject_csv(fcsvobj, '{lineNum} : 0.00s : Failed to add {csvType} : ACL {definedACL} does not exist')
            # return error
            return 0

        # build the aclitem
        aclitem = {
            "acl": defACLID,
            "element": "acl"
        }

    elif csvobj['tsig_key']:
        # This is tsig key
        # we need to get teh ID first
        tsigID = ''

        # This field includes required information or TSIG key based ACEs.
        # Use forward slashes as the delimiter to separate tsig_key_name,
        # tsig_key, tsig_key_alg, and use_2x_tsig_key.
        # Example:
        # “key_1/ny/bY2Da8Lj+2YZ4dYEJLQ==/HMAC-SHA256/false”

        # check that the format matches
        tsigFieldsMatch = extractTSIGfieldsRE.match(csvobj['tsig_key'])
        # the string matched the format
        # split the fields
        keyname, keystring, keyalg = tsigFieldsMatch.groups()

        if not tsigFieldsMatch:
            # it didn't match so log an error
            log.error(
                f'{lineNum} : 0.00s : Failed to add {csvType} : {namedACL} : Bad format for TSIG key : {keyname}.')
            reject_csv(csvobj,
                       f'{lineNum} : 0.00s : Failed to add {csvType} : {namedACL} : Bad format for TSIG key : {keyname}.')
            # return error
            return 0

        if not trailingDotRE.search(keyname):
            # There is no trailing dot, so add one
            keyname = keyname + '.'

        # check if its defined already
        if keyname in tsigKeysDict:
            # it exists so get the ID
            tsigID = tsigKeysDict[keyname]
        else:
            # it doesn't exist, so add it
            tsigID = add_tsig_key(lineNum, keyname, keystring, keyalg)

            if not tsigID:
                # adding the key failed, so log an error
                log.error(
                    f'{lineNum} : 0.00s : Failed to add {csvType} : {namedACL} : Adding TSIG key {keyname} failed.')
                reject_csv(csvobj,
                           f'{lineNum} : 0.00s : Failed to add {csvType} : {namedACL} : Adding TSIG key {keyname} failed.')
                # return error
                return 0

        # build the aclitem
        aclitem = {
            "access": "allow",
            "element": "tsig_key",
            "tsig_key": {
                "key": tsigID
            }
        }

    else:
        # shouldn't get here, but log an error if we do
        log.error(f'{lineNum} : 0.00s : Failed to add {csvType} : Must be IP, Named ACL, or TSIG key')
        reject_csv(csvobj, f'{lineNum} : 0.00s : Failed to add {csvType} : Must be IP, Named ACL, or TSIG key')
        return 0

    # add the item to the list
    namedACLDict[namedACL]['list'].append(aclitem)

    # Start the body
    body = {
        "list": namedACLDict[namedACL]['list']
    }

    # update the ACL
    aclID = namedACLDict[namedACL]['id']

    jsonBody = json.dumps(body)

    log.debug(f'{lineNum} : Adding {csvType} : {namedACL} : {aclitem}')

    t1 = time.perf_counter()

    response = b1ddi.replace('', id=aclID, body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{lineNum} : {t2:0.2f}s : Added {csvType} : {namedACL} : {aclitem} : {objID}')

        # return success
        return 1
    else:
        # the last item failed.
        # we need to pull it off the list so future adds don't fail
        namedACLDict[namedACL]['list'].pop()

        # log error and return
        log.error(
            f'{lineNum} : {t2:0.2f}s : Failed to add {csvType} : {namedACL} : {aclitem} : {response.status_code} : {response.text}')
        reject_csv(csvobj,
                   f'{lineNum} : {t2:0.2f}s : Failed to add {csvType} : {namedACL} : {aclitem} : {response.status_code} : {response.text}')

        return 0


def add_address_block(csvobj):
    """ Import NIOS CSV for networkcontainers """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']

    ipspace = csvobj['network_view']
    address = csvobj['address'] + '/' + csvobj['netmask']
    if ipspace in ipSpaceDict:
        ipspace = ipSpaceDict[ipspace]
    elif ipspace:
        # network_view doesn't match an IP space
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add netcontainer : {address} : Unknown network_view : {ipspace}')
        reject_csv(csvobj, f'Failed to add netcontainer : {address} : Unknown network_view : {ipspace}')
        return 0

    dhcpOptions, unknownOptions = get_dhcp_options(csvobj)  # Get DHCP Options

    if unknownOptions:
        # There were undefined DHCP options
        # log an error and return
        log.error(
            f'{line_num} : 0.00s : Failed to add netcontainer {address} : Unknown DHCP options : {unknownOptions}')
        reject_csv(csvobj, f'Failed to add netcontainer {address} : Unknown DHCP options : {unknownOptions}')
        return 0

    # Start the body
    body = {
        'address': address,
        'space': ipspace,
        'dhcp_options': dhcpOptions
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field:
                if b1field == 'lease_time':
                    # this is lease time.
                    # add it to the dhcp_config dict
                    body['dhcp_config'].update({'lease_time': csvobj[csvField]})

                    # handle leasetime override
                    body['inheritance_sources'].update({'dhcp_config': overrideLeasetime})
                else:
                    # check if it's an EA
                    (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                    if isExtAttr:
                        # It's an EA, so add it to the tags
                        tags[b1field] = csvobj[csvField]
                    else:
                        # Else just add it to the body
                        body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    jsonBody = json.dumps(body)
    # jsonBody = body

    log.info(f'{line_num}: Adding netcontainer {address}')

    t1 = time.perf_counter()

    response = b1ddi.create('/ipam/address_block', body=jsonBody)

    # print(response.text)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num} : {t2:0.2f}s : Added netcontainer {address} : {objID}')

        # return success
        return 1
    else:
        log.error(
            f'{line_num} : {t2:0.2f}s : Failed to add netcontainer {address}: {response.status_code} : {response.text}')
        reject_csv(csvobj, f'Failed to add netcontainer {address}: {response.status_code} : {response.text}')
        # return failure
        return 0


def add_network(csvobj):
    """ import NIOS networks """
    line_num = csvobj["line_num"]

    csvType = csvobj['csvtype']

    ipspace = csvobj['network_view']
    cidr = netmask_to_cidr(csvobj["netmask"])
    address = csvobj["address"] + '/' + str(cidr)
    if ipspace in ipSpaceDict:
        ipspace = ipSpaceDict[ipspace]
    elif ipspace:
        # network_view doesn't match an IP space
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add network : {address} : Unknown network_view : {ipspace}')
        reject_csv(csvobj, f'Failed to add network : {address} : Unknown network_view : {ipspace}')
        return 0

    # Get DHCP Host ID
    dhcp_host_id = csvobj['dhcp_members']

    if dhcp_host_id:
        if dhcp_host_id in dhcphostDict:
            # dhcp host
            dhcp_host_id = dhcphostDict[csvobj['dhcp_members']]
        elif dhcp_host_id in dhcpGroupDict:
            # HA group
            dhcp_host_id = dhcpGroupDict[csvobj['dhcp_members']]
        else:
            # member doesn't exist
            # log an error and return
            log.error(f'{line_num} : 0.00s : Failed to add network : {address} : Unknown dhcp_members : {dhcp_host_id}')
            reject_csv(csvobj, f'Failed to add network : {address} : Unknown dhcp_members : {dhcp_host_id}')
            return 0

    dhcpOptions, unknownOptions = get_dhcp_options(csvobj)  # Get DHCP Options

    if unknownOptions:
        # There were undefined DHCP options
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add network : {address} : Unknown DHCP options : {unknownOptions}')
        reject_csv(csvobj, f'Failed to add network : {address} : Unknown DHCP options : {unknownOptions}')
        return 0

    # Start the body
    body = {
        'address': address,
        'space': ipspace,
        'dhcp_host': dhcp_host_id,
        'dhcp_options': dhcpOptions,
        'inheritance_sources': {},
        'dhcp_config': {}
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field:
                if b1field == 'lease_time':
                    # this is lease time.
                    # add it to the dhcp_config dict
                    body['dhcp_config'].update({'lease_time': csvobj[csvField]})

                    # handle leasetime override
                    body['inheritance_sources'].update({'dhcp_config': overrideLeasetime})
                else:
                    # check if it's an EA
                    (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                    if isExtAttr:
                        # It's an EA, so add it to the tags
                        tags[b1field] = csvobj[csvField]
                    else:
                        # Else just add it to the body
                        body[b1field] = csvobj[csvField]

            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    jsonBody = json.dumps(body)

    log.info(f'{line_num}: Adding network {address}')

    t1 = time.perf_counter()
    response = b1ddi.create('/ipam/subnet', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num} : {t2:0.2f}s : Added network {address} : {objID}')

        # return success
        return 1
    else:
        log.error(
            f'{line_num} : {t2:0.2f}s : Failed to add network {address}: {response.status_code} : {response.text}')
        reject_csv(csvobj, f'Failed to add network {address}: {response.status_code} : {response.text}')
        # return failure
        return 0


def add_range(csvobj):
    """ # import NIOS DHCP ranges """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    start = csvobj['start_address']
    end = csvobj['end_address']

    ipspace = csvobj['network_view']
    if ipspace in ipSpaceDict:
        ipspace = ipSpaceDict[ipspace]
    elif ipspace:
        # network_view doesn't match an IP space
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add dhcprange {start}-{end} : Unknown network_view : {ipspace}')
        reject_csv(csvobj, f'Failed to add dhcprange {start}-{end} : Unknown network_view : {ipspace}')
        return 0

    # handle member/failover/reserver
    dhcphostID = ''
    if csvobj['server_association_type'] == 'MEMBER':
        # Get DHCP Host ID
        dhcphostID = csvobj['member']
        if dhcphostID in dhcphostDict:
            dhcphostID = dhcphostDict[dhcphostID]
        else:
            # log an error
            log.error(f'{line_num} : 0.00s : Failed to add dhcprange {start}-{end} : Unknown member : {dhcphostID}')
            reject_csv(csvobj, f'Failed to add dhcprange {start}-{end} : Unknown member : {dhcphostID}')
            return 0
    elif csvobj['server_association_type'] == 'FAILOVER':
        # get teh group ID
        dhcphostID = csvobj['failover_association']
        if dhcphostID in dhcpGroupDict:
            dhcphostID = dhcpGroupDict[dhcphostID]
        else:
            # log an error
            log.error(
                f'{line_num} : 0.00s : Failed to add dhcprange {start}-{end} : Unknown failover_association : {dhcphostID}')
            reject_csv(csvobj, f'Failed to add dhcprange {start}-{end} : Unknown failover_association : {dhcphostID}')
            return 0

    # Get DHCP Options
    dhcpOptions, unknownOptions = get_dhcp_options(csvobj)  # Get DHCP Options

    if unknownOptions:
        # There were undefined DHCP options
        # log an error and return
        log.error(
            f'{line_num} : 0.00s : Failed to add dhcprange {start}-{end} : Unknown DHCP options : {unknownOptions}')
        reject_csv(csvobj, f'Failed to add dhcprange {start}-{end} : Unknown DHCP options : {unknownOptions}')
        return 0

    # Start the body
    body = {
        'start': start,
        'end': end,
        'space': ipspace,
        'dhcp_host': dhcphostID,
        'dhcp_options': dhcpOptions,
        'exclusion_ranges': []
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field:
                if b1field == 'exclusion_ranges':
                    # This range has exclusion ranges
                    # start a loop and add each to the body
                    for exclRange in re.split(',', csvobj[csvField]):

                        # split the NIOS def into start, end, comment
                        comment = ''
                        if re.search('/', exclRange):
                            exclRange, comment = re.split("/", exclRange)
                        startaddr, endaddr = re.split("-", exclRange)

                        # make a dict to contain this exclude
                        exclDict = {
                            "start": startaddr,
                            "end": endaddr
                        }

                        # handle comments
                        comment = re.sub(r"^'|'$", '', comment)
                        if comment:
                            exclDict["comment"] = comment

                        # add it to the body
                        body["exclusion_ranges"].append(exclDict)

                else:
                    # check if it's an EA
                    (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                    if isExtAttr:
                        # It's an EA, so add it to the tags
                        tags[b1field] = csvobj[csvField]
                    else:
                        # Else just add it to the body
                        body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    jsonBody = json.dumps(body)

    log.info(f'{line_num}: Adding range {start}-{end}')

    t1 = time.perf_counter()

    response = b1ddi.create('/ipam/range', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num} : {t2:0.2f}s : Added range {start}-{end} : {objID}')
        # return success
        return 1
    else:
        error_response = json.loads(response.text)
        message = error_response['error'][0]['message']
        log.error(f'{line_num} : {t2:0.2f}s : Failed to add dhcprange {start}-{end} : {message}')
        reject_csv(csvobj, f'Failed to add dhcprange {start}-{end} : {response.status_code} : {response.text}')
        # return failure
        return 0


def add_reserved_range(csvobj):
    line_num = csvobj["line_num"]
    jsonResults = csvobj['csvtype']
    start = csvobj['start_address']
    end = csvobj['end_address']

    ipspace = csvobj['network_view']
    if ipspace in ipSpaceDict:
        ipspace = ipSpaceDict[ipspace]
    elif ipspace:
        # network_view doesn't match an IP space
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add reservedrange {start}-{end} : Unknown network_view : {ipspace}')
        reject_csv(csvobj, f'Failed to add reservedrange {start}-{end} : Unknown network_view : {ipspace}')
        return 0

    if start == end:
        # single address range create as an IPAM address
        result = add_ipam_address(csvobj)
        return result

    else:

        # Start the body
        body = {
            'start': start,
            'end': end,
            'space': ipspace,
            'dhcp_host': ""
        }

        # walk the rest of the fields
        # find the ones that interest us
        # add them to the body
        tags = {}
        for csvField in csvobj:
            if csvobj[csvField]:
                b1field = map_csv_fields(jsonResults, csvField)
                if b1field:
                    # check if it's an EA
                    (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                    if isExtAttr:
                        # It's an EA, so add it to the tags
                        tags[b1field] = csvobj[csvField]
                    else:
                        # Else just add it to the body
                        body[b1field] = csvobj[csvField]
                else:
                    # no b1field was returned, so ignore it
                    ...

        if tags:
            # There were tags, so add them to the body
            body["tags"] = tags

        jsonBody = json.dumps(body)

        log.info(f'{line_num}: Adding reservedrange {start}-{end} : {ipspace}')

        t1 = time.perf_counter()

        response = b1ddi.create('/ipam/range', body=jsonBody)

        t2 = time.perf_counter() - t1

        if response.status_code in b1ddi.return_codes_ok:
            jsonResp = json.loads(response.content)
            objID = jsonResp["result"]["id"]
            log.info(f'{line_num} : {t2:0.2f}s : Added reservedrange {start}-{end} : {ipspace} : {objID}')

            # return success
            return 1
        else:
            log.error(
                f'{line_num} : {t2:0.2f}s : Failed to add reservedrange {start}-{end} : {ipspace} : {response.status_code} : {response.text}')
            reject_csv(csvobj, f'Failed to add reservedrange {start}-{end} : {response.status_code} : {response.text}')
            # return failure
            return 0


def add_fixed_address(csvobj):
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    address = csvobj['ip_address']
    match_value = ''

    ipspace = csvobj['network_view']
    if ipspace in ipSpaceDict:
        ipspace = ipSpaceDict[ipspace]
    elif ipspace:
        # network_view doesn't match an IP space
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add fixedaddress : {address} : Unknown network_view : {ipspace}')
        reject_csv(csvobj, f'Failed to add fixedaddress : {address} : Unknown network_view : {ipspace}')
        return 0

    # determine the type of match
    match_option = csvobj['match_option']
    if not match_option:
        if csvobj['mac_address'] == '00:00:00:00:00:00':
            match_option = "RESERVED"
        else:
            match_option = "MAC_ADDRESS"

    if match_option == "MAC_ADDRESS":
        match_value = csvobj['mac_address']
        if not match_value:
            log.error(f'{line_num} : 0.00s : Failed to add fixedaddress {address} : no mac_address.')
            reject_csv(csvobj, f'Failed to add fixedaddress {address} : no mac_address.')
            return 0

    elif match_option == "CLIENT_ID":
        match_value = csvobj['dhcp_client_identifier']
        if not match_value:
            log.error(f'{line_num} : 0.00s : Failed to add fixedaddress {address} : no dhcp_client_identifier.')
            reject_csv(csvobj, f'Failed to add fixedaddress {address} : no dhcp_client_identifier.')
            return 0

    dhcpOptions, unknownOptions = get_dhcp_options(csvobj)  # Get DHCP Options

    if unknownOptions:
        # There were undefined DHCP options
        # log an error and return
        log.error(
            f'{line_num} : 0.00s : Failed to add fixedaddress {address} {match_value} : Unknown DHCP options : {unknownOptions}')
        reject_csv(csvobj,
                   f'Failed to add fixedaddress {address} {match_value} : Unknown DHCP options : {unknownOptions}')
        return 0

    # Start the body
    body = {
        'address': address
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field:
                if b1field == 'name':
                    if match_option == 'RESERVED':
                        body['names'] = [
                            {
                                "name": csvobj[csvField],
                                "type": "user"
                            }
                        ]
                    else:
                        # add it to the body
                        body[b1field] = csvobj[csvField]
                else:
                    # check if it's an EA
                    (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                    if isExtAttr:
                        # It's an EA, so add it to the tags
                        tags[b1field] = csvobj[csvField]
                    else:
                        # Else just add it to the body
                        body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    if match_option == 'RESERVED':

        body['space'] = ipspace
        jsonBody = json.dumps(body)

        log.info(f'{line_num}: Adding reservedaddress {address}')

        t1 = time.perf_counter()

        response = b1ddi.create('/ipam/address', body=jsonBody)

        t2 = time.perf_counter() - t1

        if response.status_code in b1ddi.return_codes_ok:
            jsonResp = json.loads(response.content)
            objID = jsonResp["result"]["id"]
            log.info(f'{line_num} : {t2:0.2f}s : Added reservedaddress {address} : {objID}')
            # return success
            return 1
        else:
            log.error(
                f'{line_num} : {t2:0.2f}s : Failed to add reservedaddress {address} : {response.status_code} : {response.text}')
            reject_csv(csvobj, f'Failed to add reservedaddress {address} : {response.status_code} : {response.text}')
            # return failure
            return 0
    elif match_option == 'MAC_ADDRESS':
        body["match_type"] = "mac"
        body["match_value"] = match_value
        body['dhcp_options'] = dhcpOptions
        body['ip_space'] = ipspace

        jsonBody = json.dumps(body)

        log.info(f'{line_num}: Adding fixedaddress {address} {match_value}')

        t1 = time.perf_counter()

        response = b1ddi.create('/dhcp/fixed_address', body=jsonBody)

        t2 = time.perf_counter() - t1

        if response.status_code in b1ddi.return_codes_ok:
            jsonResp = json.loads(response.content)
            objID = jsonResp["result"]["id"]
            log.info(f'{line_num} : {t2:0.2f}s : Added fixedaddress {address} {match_value} : {objID}')
            # return success
            return 1
        else:
            log.error(
                f'{line_num} : {t2:0.2f}s : Failed to add fixedaddress {address} {match_value} : {response.status_code} : {response.text}')
            reject_csv(csvobj,
                       f'Failed to add fixedaddress {address} {match_value} : {response.status_code} : {response.text}')
            # return failure
            return 0
    elif match_option == 'CLIENT_ID':
        body["match_type"] = "client_text"
        body["match_value"] = match_value
        body['dhcp_options'] = dhcpOptions
        body['ip_space'] = ipspace

        jsonBody = json.dumps(body)

        log.info(f'{line_num}: Adding fixedaddress {address} {match_value}')

        t1 = time.perf_counter()

        response = b1ddi.create('/dhcp/fixed_address', body=jsonBody)

        t2 = time.perf_counter() - t1

        if response.status_code in b1ddi.return_codes_ok:
            jsonResp = json.loads(response.content)
            objID = jsonResp["result"]["id"]
            log.info(f'{line_num} : {t2:0.2f}s : Added fixedaddress {address} {match_value} : {objID}')
            # return success
            return 1
        else:
            log.error(
                f'{line_num} : {t2:0.2f}s : Failed to add fixedaddress {address} {match_value} : {response.status_code} : {response.text}')
            reject_csv(csvobj,
                       f'Failed to add fixedaddress {address} {match_value} : {response.status_code} : {response.text}')
            # return failure
            return 0
    else:
        log.error(f'{line_num}: Failed to add fixedaddress {address} : invalid match_option: {match_type}')
        reject_csv(csvobj, f'Failed to add fixedaddress {address} : invalid match_option: {match_type}')


def add_ipam_address(csvobj):
    """ begin add IPAM address """
    # Adding objects for IPAM only no DHCP settings no DNS
    # used to add not for DHCP or DNS hostrecords
    # used to add in single address IP reservation ranges
    name = ''
    line_num = csvobj["line_num"]

    csvType = csvobj['csvtype']
    address = ''
    # set the fields depending on what NIOS object we have been called for
    if csvType == 'reservedrange':
        address = csvobj['end_address']
        name = csvobj['name']
    elif csvType == 'hostrecord':
        address = csvobj['addresses']
        name = csvobj['fqdn']
    else:
        log.error(
            f'{line_num} : 0.00s : Failed to add reservedaddress : {csvType} : Unknown source object type for IPAM address')
        reject_csv(csvobj, f'Failed to add reservedaddress : {csvType} : Unknown source object type for IPAM address')

    ipspace = csvobj['network_view']
    comment = csvobj['comment']

    if ipspace in ipSpaceDict:
        ipspace = ipSpaceDict[ipspace]
    elif ipspace:
        # network_view doesn't match an IP space
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add reservedaddress : {address} : Unknown network_view : {ipspace}')
        reject_csv(csvobj, f'Failed to add reservedaddress : {address} : Unknown network_view : {ipspace}')
        return 0

    # Start the body
    body = {'address': address, 'names': [{
        "name": name,
        "type": "user"
    }
    ], 'comment': comment, 'space': ipspace}

    # walk the rest of the fields
    # we are only interested in tags
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field:
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    body['space'] = ipspace
    jsonBody = json.dumps(body)

    log.info(f'{line_num}: Adding reservedaddress {address} : {ipspace} ')

    t1 = time.perf_counter()

    response = b1ddi.create('/ipam/address', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num} : {t2:0.2f}s : Added reservedaddress {address} : {ipspace}: {objID}')

        # return success
        return 1
    else:
        log.error(
            f'{line_num} : {t2:0.2f}s : Failed to add reservedaddress {address} : {ipspace}: {response.status_code} : {response.text}')
        reject_csv(csvobj,
                   f'Failed to add reservedaddress {address} : {ipspace} : {response.status_code} : {response.text}')
        # return failure
        return 0


def add_record(body, line_num, csvobj, multi=False):
    fqdn = body["absolute_name_spec"]
    rdata = str(body["rdata"])
    rtype = body["type"]

    jsonBody = json.dumps(body)

    log.info(f'{line_num}: Sending {rtype} {fqdn} {rdata}')

    t1 = time.perf_counter()

    response = b1ddi.create('/dns/record', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        if multi:
            # we were called in multi-object mode, so just return the result
            return 1, f'{fqdn}:{rdata}:{objID}'
        # else log and return
        log.info(f'{line_num} : {t2:0.2f}s : Added {rtype} {fqdn} {rdata} : {objID}')
        # return success
        return 1
    else:
        if multi:
            # we were called in multi-object mode, so just return the result
            return 0, f"Failed to add {rtype} {fqdn} {rdata} : {response.status_code} : {response.text}"
        # else log and return
        log.error(
            f'{line_num} : {t2:0.2f}s : Failed to add {rtype} {fqdn} {rdata} : {response.status_code} : {response.text}')
        reject_csv(csvobj, f'Failed to add {rtype} {fqdn} {rdata} : {response.status_code} : {response.text}')
        # return failure
        return 0


def add_aaaa_record(csvobj):
    line_num = csvobj["line_num"]

    csvType = csvobj['csvtype']

    fqdn = csvobj['fqdn']
    address = csvobj['address']

    dnsview = csvobj['view']
    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {address} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {address} : Unknown view : {dnsview}')
        return 0

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"address": address},
        "type": "AAAA"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_txt_record(csvobj):
    """ Add TXT Record """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']
    text = csvobj['text']

    dnsview = csvobj['view']
    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {text} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {text} : Unknown view : {dnsview}')
        return 0

    # remove unsupported chars?
    # Just let it fail for now.
    # text = unsupportTXTre.sub("", text)

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"text": text},
        "type": "TXT"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_srv_record(csvobj):
    """ Add SRV Record """
    line_num = csvobj["line_num"]

    csvType = csvobj['csvtype']

    fqdn = csvobj['fqdn']
    port = csvobj['port']
    priority = csvobj['priority']
    target = csvobj['target']
    weight = csvobj['weight']

    dnsview = csvobj['view']
    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {target} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {target} : Unknown view : {dnsview}')
        return 0

    # check for trailing dot in RDATA
    if not trailingDotRE.search(target):
        # There is no trailing dot, so add one
        target = target + '.'

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"priority": int(priority), "weight": int(weight), "port": int(port), "target": target},
        "type": "SRV"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_naptr_record(csvobj):
    """ Add NAPTR Record """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']
    naFlags = csvobj['flags']
    naOrder = csvobj['order']
    naPref = csvobj['preference']
    naService = csvobj['services']
    naReplace = csvobj['replacement']
    naRegex = csvobj['regexp']
    dnsview = csvobj['view']

    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(
            f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {naService} {naReplace} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {naService} {naReplace} : Unknown view : {dnsview}')
        return 0

    # check for trailing dot in RDATA
    if not trailingDotRE.search(naReplace):
        # There is no trailing dot, so add one
        naReplace = naReplace + '.'

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"flags": naFlags, "order": int(naOrder), "preference": int(naPref), "regexp": naRegex,
                  "services": naService, "replacement": naReplace},
        "type": "NAPTR"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_caa_record(csvobj):
    """ Add CAA Record """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']
    caFlags = csvobj['ca_flag']
    caTag = csvobj['ca_tag']
    caValue = csvobj['ca_value']
    dnsview = csvobj['view']

    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {caValue} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {caValue} : Unknown view : {dnsview}')
        return 0

    # no dot for CAA
    # check for trailing dot in RDATA
    # if not trailingDotRE.search(caValue):
    #     # There is no trailing dot, so add one
    #     caValue = caValue + '.'

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"flags": int(caFlags), "tag": caTag, "value": caValue},
        "type": "CAA"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_mx_record(csvobj):
    """ Add MX Record """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']
    mxname = csvobj['mx']
    mxpriority = csvobj['priority']
    dnsview = csvobj['view']

    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {mxname} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {mxname} : Unknown view : {dnsview}')
        return 0

    # check for trailing dot in RDATA
    if not trailingDotRE.search(mxname):
        # There is no trailing dot, so add one
        mxname = mxname + '.'

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"exchange": mxname, "preference": int(mxpriority)},
        "type": "MX"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_cname_record(csvobj):
    """ Add CNAME Record """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']
    cname = csvobj['canonical_name']
    dnsview = csvobj['view']

    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {canonical_name} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {canonical_name} : Unknown view : {dnsview}')
        return 0

    # check for trailing dot in RDATA
    if not trailingDotRE.search(cname):
        # There is no trailing dot, so add one
        cname = cname + '.'

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"cname": cname},
        "type": "CNAME"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_a_record(csvobj):
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']
    address = csvobj['address']
    dnsview = csvobj['view']
    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {address} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {address} : Unknown view : {dnsview}')
        return 0

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"address": address},
        "type": "A"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_ptr_record(csvobj):
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    # FQDN can be specified a few different ways
    fqdn = ''

    if csvobj['fqdn']:
        fqdn = csvobj['fqdn']
    elif csvobj['address']:
        fqdn = csvobj['address']
        # convert it to reverse notation
        ip_addr = ipaddress.ip_address(fqdn)
        fqdn = ip_addr.reverse_pointer

    dname = csvobj['dname']
    dnsview = csvobj['view']

    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} {dname} : Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add {csvType} {fqdn} {dname} : Unknown view : {dnsview}')
        return 0

    # check for trailing dot in RDATA
    if not trailingDotRE.search(dname):
        # There is no trailing dot, so add one
        dname = dname + '.'

    # Start the body
    body = {
        "view": dnsview,
        "absolute_name_spec": fqdn,
        "rdata": {"dname": dname},
        "type": "PTR"
    }

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'ttl':
                # handle the TTL
                body[b1field] = csvobj[csvField]
                # add override flag for ttl
                body["inheritance_sources"] = overrideTTL
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # call addRecord to add it
    result = add_record(body, line_num, csvobj)
    return result


def add_host_address(csvobj):
    """"  B1DDI does not have a DHCP host address
          add fixed instead """

    line_num = csvobj["line_num"]
    fqdn = csvobj["parent"]
    address = csvobj["address"]
    macaddr = csvobj["mac_address"]

    # configure_for_dhcp = csvobj["configure_for_dhcp"]

    ipspace = csvobj['network_view']

    if macaddr:
        # log.info(f"{line_num}: Processing as DHCP object Hostaddress: {fqdn} : {address}")

        if macaddr and macaddr != "00:00:00:00:00:00":
            """ there is a fixed address
                we used to check if configure_for_dhcp is true
                (isTrueRE.match(csvobj["configure_for_dhcp"]))
                but for IPAM purposes we are just going to add 
                it for now """

            csvobj["csvtype"] = "fixedaddress"
            csvobj["name"] = fqdn
            csvobj["ip_address"] = address
            csvobj['match_option'] = "MAC_ADDRESS"

            # log.info(f"{line_num}: adding as as fixed address Hostaddress: {fqdn} : {address}")
            result = add_fixed_address(csvobj)
            return result

        else:
            # there is a host already there, so no need to add a reservation for 00:00:00:00:00:00
            log.error(f"{line_num}: Skipping Hostaddress reservation: {fqdn} : {address} : {ipspace}")
            reject_csv(csvobj, f'Skipping Hostaddress reservation: {fqdn} : {address}: {ipspace}')
            return 0
    else:
        log.error(f"{line_num}: Skipping non-DHCP Hostaddress: {fqdn} : {address}: {ipspace}")
        reject_csv(csvobj, f'Skipping non-DHCP Hostaddress: {fqdn} : {address}: {ipspace}')
        return 0


def add_host_record(csvobj):
    """ add IPAM reservation or DNS RRs to represent a NIOS hostrecord """
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj["fqdn"]
    dnsview = csvobj['view']

    # ipspace = csvobj['network_view']

    configure_for_dns = csvobj['configure_for_dns']

    if configure_for_dns == "TRUE":
        """ log.info(f'{line_num} : 0.00s : processing as a DNS record {csvType} {fqdn} : {dnsview}')
            check for dns view if configure for DNS is true
            B1DDI does not have a DNS host record
            add A/PTR/CNAME instead """

        if dnsview in dnsViewDict:
            dnsview = dnsViewDict[dnsview]
        elif dnsview:
            # the DNS view does not exist
            # log an error and return
            log.error(f'{line_num} : 0.00s : Failed to add {csvType} {fqdn} : Unknown view : {dnsview}')
            reject_csv(csvobj, f'Failed to add {csvType} {fqdn} : Unknown view : {dnsview}')
            return 0

        t1 = time.perf_counter()
        """ Even though we are adding multiple records, we will treat a
            hostrecord as a single object for counting/stats purposes
            this variable will track if an error occurs which will
            be returned to the caller """

        hostError = 0
        # also need to keep track of which objects are created vs failed
        hostObjCount = 0
        hostObjCreated = 0
        hostRRsuccess = []
        hostRRfailed = []

        # count for v4 addresses
        addresses = csvobj["addresses"]
        if addresses:
            addresses = re.split(',', addresses)
            hostObjCount += len(addresses) * 2

        # count for v6 addresses
        v6addresses = csvobj["ipv6_addresses"]
        if v6addresses:
            v6addresses = re.split(',', v6addresses)
            hostObjCount += len(v6addresses) * 2

        # count aliases
        hostaliases = csvobj["aliases"]
        if hostaliases:
            hostaliases = re.split(',', hostaliases)
            hostObjCount += len(hostaliases)

        # Start the body
        body = {
            "view": dnsview,
            "absolute_name_spec": fqdn,
        }

        # walk the rest of the fields
        # find the ones that interest us
        # add them to the body
        tags = {}
        for csvField in csvobj:
            if csvobj[csvField]:
                b1field = map_csv_fields(csvType, csvField)
                if b1field == 'disabled':
                    # handle disabled method
                    if isTrueRE.match(csvobj[csvField]):
                        # only set it when disabled=true
                        body[b1field] = True
                elif b1field == 'configure_for_dns':
                    # handle disabled method
                    if isFalseRE.match(csvobj[csvField]):
                        # only set it when configure_for_dns=false
                        body['disabled'] = True
                elif b1field == 'ttl':
                    # handle the TTL
                    body[b1field] = csvobj[csvField]
                    # add override flag for ttl
                    body["inheritance_sources"] = overrideTTL
                elif b1field:
                    # check if it's an EA
                    (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                    if isExtAttr:
                        # It's an EA, so add it to the tags
                        tags[b1field] = csvobj[csvField]
                    else:
                        # Else just add it to the body
                        body[b1field] = csvobj[csvField]
                else:
                    # no b1field was returned, so ignore it
                    ...

        if tags:
            # There were tags, so add them to the body
            body["tags"] = tags

        # walk though the v4 addresses
        for addr in addresses:

            # make a copy of the body and update it
            newbody = dict(body)
            newbody["type"] = "A"
            newbody["rdata"] = {"address": addr}

            # add the Arecord
            (result, message) = add_record(newbody, line_num, csvobj, multi=True)

            # check for error
            if result:
                # the record was successful, update stats, add it to the success list
                hostObjCreated += 1
                hostRRsuccess.append(message)
            else:
                # there was an error
                hostError += 1
                hostRRfailed.append(message)

            # now do the reverse
            # calculate the reverse fqdn
            ipAddr = ipaddress.ip_address(addr)
            newfqdn = ipAddr.reverse_pointer

            # make a copy of the body and update it
            newbody = dict(body)
            newbody["type"] = "PTR"
            newbody["absolute_name_spec"] = newfqdn
            if not trailingDotRE.search(fqdn):
                # There is no trailing dot, so add one
                fqdn = fqdn + '.'
            newbody["rdata"] = {"dname": fqdn}

            # add the ptr record
            (result, message) = add_record(newbody, line_num, csvobj, multi=True, )

            # check for error
            if result:
                # the record was successful, update stats, add it to the success list
                hostObjCreated += 1
                hostRRsuccess.append(message)
            else:
                # there was an error
                hostError += 1
                hostRRfailed.append(message)

        # walk though any v6 addresses
        for addr in v6addresses:

            # make a copy of the body and update it
            newbody = dict(body)
            newbody["type"] = "AAAA"
            newbody["rdata"] = {"address": addr}

            # add the AAAA record
            (result, message) = add_record(newbody, line_num, csvobj, multi=True)

            # check for error
            if result:
                # the record was successful, update stats, add it to the success list
                hostObjCreated += 1
                hostRRsuccess.append(message)
            else:
                # there was an error
                hostError += 1
                hostRRfailed.append(message)

            # now do the reverse
            # calculate the reverse fqdn
            ipAddr = ipaddress.ip_address(addr)
            newfqdn = ipAddr.reverse_pointer

            # make a copy of the body and update it
            newbody = dict(body)
            newbody["type"] = "PTR"
            newbody["absolute_name_spec"] = newfqdn

            if not trailingDotRE.search(fqdn):
                # There is no trailing dot, so add one
                fqdn = fqdn + '.'
            newbody["rdata"] = {"dname": fqdn}

            # add the ptr record
            (result, message) = add_record(newbody, line_num, csvobj, multi=True)

            # check for error
            if result:
                # the record was successful, update stats, add it to the success list
                hostObjCreated += 1
                hostRRsuccess.append(message)
            else:
                # there was an error
                hostError += 1
                hostRRfailed.append(message)

        # handle any aliases
        for alias in hostaliases:

            # make a copy of the body and update it
            newbody = dict(body)
            newbody["type"] = "CNAME"
            newbody["absolute_name_spec"] = alias
            newbody["rdata"] = {"cname": fqdn}

            # add the cname record
            (result, message) = add_record(newbody, line_num, csvobj, multi=True)

            # check for error
            if result:
                # the record was successful, update stats, add it to the success list
                hostObjCreated += 1
                hostRRsuccess.append(message)
            else:
                # there was an error
                hostError += 1
                hostRRfailed.append(message)

        t2 = time.perf_counter() - t1

        # we are done processing. Let check for errors and output the relevant lines
        if hostError:
            # There were errors
            log.info(
                f'{line_num} : {t2:0.2f}s : Errors adding {hostError} / {hostObjCount} objects for Hostrecord {fqdn} : Success {hostRRsuccess} : Error {hostRRfailed}')
            # add to the errors file
            reject_csv(csvobj, f'{hostRRfailed}')
            return 0

        # no errors output sucess message
        log.info(f"{line_num}: {t2:0.2f}s : Added Hostrecord: {fqdn} : {hostRRsuccess}")
        return 1

    else:
        # IPAM only object add as a reservation
        log.info(f'{line_num} : 0.00s : processing as IPAM record {csvType} {fqdn} : {dnsview}')
        result = add_ipam_address(csvobj)
        return result


def add_auth_zone(csvobj):
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']

    # get the zone type from the NS group
    primaryType = ''
    nsgroup = csvobj['ns_group']
    if nsgroup in nsGroupDict:
        nsgroup = nsGroupDict[nsgroup]
        primaryType = 'cloud'
    elif nsgroup in slaveGroupDict:
        nsgroup = slaveGroupDict[nsgroup]
        primaryType = 'external'
    elif nsgroup:
        # the NS Group does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add authzone {fqdn}: Unknown ns_group : {nsgroup}')
        reject_csv(csvobj, f'Failed to add authzone {fqdn}: Unknown ns_group : {nsgroup}')
        return 0

    dnsview = csvobj['view']
    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add authzone {fqdn}: Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add authzone {fqdn}: Unknown view : {dnsview}')
        return 0

    t1 = time.perf_counter()

    # Start the body
    body = {
        "fqdn": fqdn,
        "view": dnsview,
        "nsgs": [nsgroup],
        "primary_type": primaryType
    }

    """ walk the rest of the fields
        find the ones that interest us
        add them to the body """

    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'prefix':
                if csvobj['prefix']:
                    # Currently RFC2317 not supported so log an error
                    log.error(
                        f'{line_num} : 0.00s : Failed to add authzone {fqdn}: RFC2317 reverse zone not supported.')
                    reject_csv(csvobj, f'Failed to add authzone {fqdn}: RFC2317 reverse zone not supported.')
                    continue
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    jsonBody = json.dumps(body)
    response = b1ddi.create('/dns/auth_zone', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num}: {t2:0.2f}s : Added authzone {fqdn} : {objID}')
        return 1
    else:
        log.error(f'{line_num}: Failed to add authzone {fqdn}: {response.status_code} : {response.text}')
        reject_csv(csvobj, f'Failed to add authzone {fqdn}: {response.status_code} : {response.text}')
        return 0


def add_forwarder_zone(csvobj):
    line_num = csvobj["line_num"]

    csvType = csvobj['csvtype']

    fqdn = csvobj['fqdn']

    dnsview = csvobj['view']
    if dnsview in dnsViewDict:
        dnsview = dnsViewDict[dnsview]
    elif dnsview:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add forwardzone {fqdn}:  Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to add forwardzone {fqdn}:  Unknown view : {dnsview}')
        return 0

    t1 = time.perf_counter()
    # Start the body
    body = {
        "fqdn": fqdn,
        "view": dnsview,
        "nsgs": [],
        "external_forwarders": [],
        "hosts": []
    }

    # Are we using Groups or DNS hosts and fwd IPs?
    # set the necessary fields in the body
    nsGroup = csvobj['ns_group']
    if nsGroup in fwdGroupDict:
        # This zone uses groups for members
        nsGroup = fwdGroupDict[nsGroup]
        body["nsgs"].append(nsGroup)
    elif nsGroup:
        # the group doesn't exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add forwardzone {fqdn}:  Unknown ns_group : {nsGroup}')
        reject_csv(csvobj, f'Failed to add forwardzone {fqdn}:  Unknown ns_group : {nsGroup}')
        return 0

    # handle external groups
    extGroup = csvobj['ns_group_external']
    if extGroup:
        extGroup = fwdGroupDict[extGroup]
        body["nsgs"].append(extGroup)
    elif extGroup:
        # the group doesn't exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add forwardzone {fqdn}:  Unknown ns_group_external : {extGroup}')
        reject_csv(csvobj, f'Failed to add forwardzone {fqdn}:  Unknown ns_group_external : {extGroup}')
        return 0

    fwdTo = csvobj['forward_to']
    if fwdTo:
        # this field has a list of names/IPs to forward to
        # start a loop and add each to the body
        for fwdr in re.split(',', fwdTo):
            # split the NIOS def into name and addr
            # Do we need to add glue records?
            # There is no where to specify the address
            dname, ipaddr = re.split('/', fwdr)

            if not trailingDotRE.search(dname):
                # There is no trailing dot, so add one
                dname = dname + '.'

            # make a dict to contain this forwarder
            fwdDict = {
                'fqdn': dname,
                'address': ipaddr
            }

            # add it to the body
            body["external_forwarders"].append(fwdDict)

    fwdServrs = csvobj['forwarding_servers']
    if fwdServrs:
        # this field has a list DHCP hosts doing the forwarding
        # start a loop and add each to the body
        for fwdMem in re.split(',', fwdServrs):
            # split the NIOS def into fields
            fwdOnly, enableOverride, memName, *overrideServers = re.split('/', fwdMem)

            if isTrueRE.match(enableOverride):
                # This is not supported on the DNS host.
                # need to create a DNS forwarder group
                # log an error and continue
                log.error(
                    f'{line_num}: 0.00s : Failed to add DHCP member {memName} to forwarder zone {fqdn}: Overriding forwarders not supported.')
                reject_csv(csvobj,
                           f'Failed to add DHCP member {memName} to forwarder zone {fqdn}: Overriding forwarders not supported.')
                continue

            # lookup the DNS host ID
            # dnsHost_id = ''
            if memName in dnsHostDict:
                dnsHost_id = dnsHostDict[memName]
            else:
                # The host doesn't exist
                # log an error and return
                log.error(
                    f'{line_num} : 0.00s : Failed to add forwardzone {fqdn}:  Unknown member in forwarding_servers : {memName}')
                reject_csv(csvobj,
                           f'Failed to add forwardzone {fqdn}:  Unknown member in forwarding_servers : {memName}')
                return 0

            # add it to the body
            body["hosts"].append(dnsHost_id)

    # walk the rest of the fields
    # find the ones that interest us
    # add them to the body
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'forward_only':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when forward only=true
                    body[b1field] = True
            elif b1field == 'prefix':
                if csvobj['prefix']:
                    # Currently RFC2317 not supported so log an error
                    log.error(
                        f'{line_num} : 0.00s : Failed to add forwardzone {fqdn}: RFC2317 reverse zone not supported.')
                    reject_csv(csvobj, f'Failed to add forwardzone {fqdn}: RFC2317 reverse zone not supported.')
                    continue
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    jsonBody = json.dumps(body)
    response = b1ddi.create('/dns/forward_zone', body=jsonBody)

    t2 = time.perf_counter() - t1

    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num}: {t2:0.2f}s : Added forwardzone {fqdn} : {objID}')
        return 1
    else:
        log.error(f'{line_num}: Failed to add forwardzone {fqdn}: {response.status_code} : {response.text}')
        reject_csv(csvobj, f'Failed to add forwardzone {fqdn}: {response.status_code} : {response.text}')
        return 0


def add_delegation(csvobj):
    line_num = csvobj["line_num"]
    csvType = csvobj['csvtype']
    fqdn = csvobj['fqdn']
    delgTo = csvobj['delegate_to']
    dns_view = csvobj['view']
    dnsview = ''
    if dns_view in dnsViewDict:
        dnsview = dnsViewDict[dns_view]
    elif dns_view:
        # the DNS view does not exist
        # log an error and return
        log.error(f'{line_num} : 0.00s : Failed to add delegatedzone {fqdn}: Unknown view : {dns_view}')
        reject_csv(csvobj, f'Failed to add delegatedzone {fqdn}: Unknown view : {dns_view}')
        return 0

    t1 = time.perf_counter()

    delegations = re.split(',', delgTo)

    body = {
        "delegation_servers": [],
        "fqdn": f'{fqdn}.',
        "view": dnsview,
    }

    """ walk the rest of the fields
        find the ones that interest us
        add them to the body """
    tags = {}
    for csvField in csvobj:
        if csvobj[csvField]:
            b1field = map_csv_fields(csvType, csvField)
            if b1field == 'disabled':
                # handle disabled method
                if isTrueRE.match(csvobj[csvField]):
                    # only set it when disabled=true
                    body[b1field] = True
            elif b1field == 'prefix':
                if csvobj['prefix']:
                    # Currently RFC2317 not supported so log an error
                    log.error(
                        f'{line_num} : 0.00s : Failed to add delegatedzone {fqdn} in view {dnsview}: RFC2317 reverse zone not supported.')
                    reject_csv(csvobj, f'')
                    continue
            elif b1field:
                # check if it's an EA
                (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                if isExtAttr:
                    # It's an EA, so add it to the tags
                    tags[b1field] = csvobj[csvField]
                else:
                    # Else just add it to the body
                    body[b1field] = csvobj[csvField]
            else:
                # no b1field was returned, so ignore it
                ...

    if tags:
        # There were tags, so add them to the body
        body["tags"] = tags

    # Process the delegate_to field
    # NIOS CSV lists mulitple NS servers in this field
    # start a loop to add a record for each
    for delg in delegations:
        # split the NIOS value into name and addr
        # Do we need to add glue records?
        # There is no where to specify the address
        dname, ipaddr = re.split('/', delg)

        # check for trailing dot in RDATA
        if not trailingDotRE.search(dname):
            # There is no trailing dot, so add one
            dname = dname + '.'

        # Add delegated server to josn list
        body["delegation_servers"].append({"fqdn": dname, "address": ipaddr})

        # There were tags, so add them to the body
        body["tags"] = tags

    jsonBody = json.dumps(body)

    response = b1ddi.create('/dns/delegation', body=jsonBody)

    t2 = time.perf_counter() - t1

    # we are done processing. Let check for errors and output the relevant lines
    if response.status_code in b1ddi.return_codes_ok:
        jsonResp = json.loads(response.content)
        objID = jsonResp["result"]["id"]
        log.info(f'{line_num} : {t2:0.2f}s : Added delegated zone {fqdn}: {objID}')
        return 1
    else:
        log.error(
            f'{line_num} : {t2:0.2f}s : Failed to add delegated zone {fqdn} : {response.status_code} : {response.text}')
        reject_csv(csvobj, f'Failed to add delegated zone {fqdn}: {response.status_code} : {response.text}')
        return 0


def start_threads(threadfunc, b1_object):
    """ This function invokes multiple concurrent instances of threadfunc(object)
        using threading. ThreadPoolExecutor() takes an optional argument, max_workers,
        which sets the maximum number of threads to invoke at the same same.
        In Python version 3.5, if max_workers is None or not given, it will default to
        the number of processors on the machine, multiplied by 5. As of Python
        version 3.8, the default value of max_workers is changed to
        min(32, os.cpu_count() + 4), which should be sufficient for most situations.
    """
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for item in b1_object:
            futures.append(executor.submit(threadfunc, item))

        for future in concurrent.futures.as_completed(futures):
            try:
                csvType = item["csvtype"]
                success = future.result()
                if success:
                    # The operation was successful. Update the stats
                    stats[csvType]["success"] += 1
                else:
                    # The operation failed. Update the stats
                    stats[csvType]["failed"] += 1
            except Exception as exc:
                log.error('Thread Exception: %s' % exc)

    # wait for all threads to finish
    executor.shutdown(wait=True)


def no_start_threads(threadfunc, thread_obj):
    """ this function is really more for debugging.
        switch to this instead of startThreads() when debugging.
        This will run import without multi-threading. """

    for item in thread_obj:
        csvType = item["csvtype"]
        success = threadfunc(item)
        if success:
            # The operation was successful. Update the stats
            stats[csvType]["success"] += 1
        else:
            # The operation failed. Update the stats
            stats[csvType]["failed"] += 1

#Uses IPv4 library to generate listIP with all the IP addresses between the provided start and end IPs.
def ips (start, end):
    '''Return IPs in IPv4 range, inclusive.'''
    start_int = int(ip_address(start).packed.hex(), 16)
    end_int = int(ip_address(end).packed.hex(), 16)
    return [ip_address(ip).exploded for ip in range(start_int, end_int)]

#Gets all the bulkrecords and creates one A record per IP in the bulkhost range
# If "Reverse" is checked, the equivalent PTR will be also generated
def process_bulkhost_record(csvobj):

    count_ok = 0
    count_ok_ptr = 0
    comment = ''
    line_num = csvobj['line_num']
    csvType = csvobj['csvtype']
    
    #Using start and end address as input, this ips function creates a list with all the ip addresses on this range
    start_address = csvobj['start_address']
    end_address = csvobj['end_address']
    ipList = ips(start_address,end_address)
    
    comment = csvobj['comment']
    disabled = csvobj['disabled']
    reverse = csvobj['reverse']
    parentfqdn = csvobj['parentfqdn']
    prefix = csvobj['prefix']
    
    dnsview = csvobj['view']
    tempfqdn = prefix + '.' + parentfqdn + '.' 
    
    if dnsview in dnsViewDict:
        viewid = dnsViewDict[dnsview]
    else:
        # the DNS view does not exist, log an error and return
        log.error(f'{line_num} : 0.00s : Failed to process bulkhost {tempfqdn}: Unknown view : {dnsview}')
        reject_csv(csvobj, f'Failed to process bulkhost {tempfqdn}: Unknown view : {dnsview}')
        return 0
    if not disabled:
        log.error(f'{line_num} : 0.00s : Failed to process bulkhost {tempfqdn}: Record is Disabled')
        reject_csv(csvobj, f'Failed to process bulkhost {tempfqdn}: Record is Disabled')
        return 0
    else:
        #Generate one A record for each IP within the range of the bulkhost. FQDN, Zone, View... are the common for all records, only IP address changes 
        for i in range(0,len(ipList)):
            ip_addr = ipList[i]
            octects = ip_addr.split('.')
            fqdn = prefix + '-' + octects[3]+ '.'+ parentfqdn + '.'
            body = {
                "absolute_name_spec": fqdn,
                "rdata": {"address": ip_addr},
                "options": {"create_ptr": True},
                "type": "A",
                "view": viewid
            }
    
            tags = {}
            for csvField in csvobj: #Only consider those cases where a bulkhost has some EAs defined
                if csvobj[csvField]:
                    b1field = map_csv_fields(csvType, csvField)
                    if b1field:
                        # check if it's an EA
                        (b1field, isExtAttr) = isExtAttrRE.subn('', b1field)
                        if isExtAttr:
                            # It's an EA, so add it to the tags
                            tags[b1field] = csvobj[csvField]
            # There were tags, so add them to the body
            if tags:
                body["tags"] = tags

            jsonBody = json.dumps(body)
            t1 = time.perf_counter()
            response = b1ddi.create('/dns/record', body=jsonBody)
            t2 = time.perf_counter() - t1
        
            # we are done processing. Let check for errors and output the relevant lines
            if response.status_code in b1ddi.return_codes_ok:
                jsonResp = json.loads(response.content)
                objID = jsonResp["result"]["id"]
                log.info(f'{line_num} : {t2:0.2f}s : Added A record {fqdn} {ip_addr} : {objID}')
                count_ok += 1
                #return 1 --> With return, the loop is never completed so will only create one A record per bulkhost
            else:
                log.error(f'{line_num} : {t2:0.2f}s : Failed to add A record {fqdn} {ip_addr} : {response.status_code} : {response.text}')
                reject_csv(csvobj, f'Failed to add A record {fqdn} {ip_addr}: {response.status_code} : {response.text}')
                #return 0 
        
            

    print(count_ok,' A records have been added successfully')
    print(count_ok_ptr,' PTR records have been added successfully')
    
def process_csv_data(options, supported_types):
    global csv_error
    """ Process NIOS CSV Data """

    # csv variables
    csvfilename = options.csvfilename
    csvdelimiter = options.csvdelimiter or ','
    csvErrorFile = f"b1ddi-import-{dateTime}-error.csv"
    csvErrorFileObj = open(csvErrorFile, 'w', newline='')
    csv_error = csv.writer(csvErrorFileObj, delimiter=csvdelimiter)

    # Dictionary's are used for reference ID's
    build_global_dicts()

    # Start parsing the CSV file and
    # sort the different object types into the csvdata Dict
    with open(csvfilename) as csv_file:

        csv_reader = csv.reader(csv_file, delimiter=csvdelimiter)

        line_count = 0
        for row in csv_reader:
            line_count += 1
            # look for header rows. Chop off the 'header-' with this regex
            (csvType, isHeader) = headerRegex.subn('', row[0])
            # make it lower case
            csvType = row[0] = csvType.lower()

            if isHeader:
                # This is a header row, normalize the header and store it in our headerdict
                if csvType not in supported_types:
                    # skip unsupported types
                    log.info(f'Line#: {line_count}: Unsupported type: {csvType}. Skipping')
                    continue

                # normalize the header fields (eg. remove any *s in the columns, etc)
                for i in range(len(row)):
                    headerfield = re.sub(r'\*$', '', row[i])

                    if not isExtAttrRE.match(headerfield) and not isDhcpOptionRE.match(headerfield):
                        # make the name lowercase. its not a DHCP option or EA name.
                        headerfield = headerfield.lower()

                    row[i] = headerfield

                # add a line to the csv_error
                csv_error.writerow(['error'] + row)

                # fix the csvtype column
                row[0] = 'csvtype'

                # store the header line in this dictionary
                headerdict[csvType] = row

                # setup entries in the stats dict
                # Don't overwrite existing stats
                if csvType not in stats:
                    stats[csvType] = {"success": 0, "failed": 0, "runtime": 0}
                continue

            else:
                if csvType not in supported_types:
                    # skip unsupported types

                    line_num = line_count
                    log.error(f'Line#: {line_count}: Unsupported type: {csvType}. Skipping')
                    csvrow = row

                    # fix the csvtype
                    csvrow[0] = csvType

                    # format the message
                    errorMsg = f"Line {line_num}: Unsupported type: {csvType}. Skipping"

                    # prepend the error, and output the error line
                    csv_error.writerow([errorMsg] + csvrow)
                    continue

                if csvType not in headerdict:
                    # no header found
                    log.error(f'Line#: {line_count}: header not found for {csvType}. Exiting.')
                    exit()

                # create a dict for the row using the last known header
                csvheader = headerdict[csvType]
                csvobj = {csvheader[i]: row[i] for i in range(len(csvheader))}

                # initialize any required fields that are not defined
                init_required_fields(csvobj)

                # add the line number
                csvobj["line_num"] = line_count

                # save the CSV line for the errors file
                csvobj["csvrow"] = row

                # store the csv object in the right csvdata bucket
                csvdata[csvType].append(csvobj)

        log.info(f"CSV file processing complete. {line_count} rows processed.")

    log.info("line# : time(s) : message")

    # Now work our way through the csvdata dict and add the objects
    if csvdata["networkcontainer"]:
        starttime = time.perf_counter()
        start_threads(add_address_block, csvdata["networkcontainer"])
        runtime = time.perf_counter() - starttime
        stats["networkcontainer"]["runtime"] = runtime

    if csvdata["network"]:
        starttime = time.perf_counter()
        start_threads(add_network, csvdata["network"])
        runtime = time.perf_counter() - starttime
        stats["network"]["runtime"] = runtime

    if csvdata["dhcprange"]:
        starttime = time.perf_counter()
        start_threads(add_range, csvdata["dhcprange"])
        runtime = time.perf_counter() - starttime
        stats["dhcprange"]["runtime"] = runtime

    if csvdata["reservedrange"]:
        starttime = time.perf_counter()
        start_threads(add_reserved_range, csvdata["reservedrange"])
        runtime = time.perf_counter() - starttime
        stats["reservedrange"]["runtime"] = runtime

    if csvdata["fixedaddress"]:
        starttime = time.perf_counter()
        start_threads(add_fixed_address, csvdata["fixedaddress"])
        runtime = time.perf_counter() - starttime
        stats["fixedaddress"]["runtime"] = runtime

    if csvdata["namedacl"]:
        starttime = time.perf_counter()
        start_threads(add_named_acl, csvdata["namedacl"])
        runtime = time.perf_counter() - starttime
        stats["namedacl"]["runtime"] = runtime

    if csvdata["namedaclitem"]:
        starttime = time.perf_counter()
        start_threads(add_named_acl_item, csvdata["namedaclitem"])
        runtime = time.perf_counter() - starttime
        stats["namedaclitem"]["runtime"] = runtime

    if csvdata["authzone"]:
        starttime = time.perf_counter()
        start_threads(add_auth_zone, csvdata["authzone"])
        runtime = time.perf_counter() - starttime
        stats["authzone"]["runtime"] = runtime

    if csvdata["delegatedzone"]:
        starttime = time.perf_counter()
        start_threads(add_delegation, csvdata["delegatedzone"])
        runtime = time.perf_counter() - starttime
        stats["delegatedzone"]["runtime"] = runtime

    if csvdata["forwardzone"]:
        starttime = time.perf_counter()
        start_threads(add_forwarder_zone, csvdata["forwardzone"])
        runtime = time.perf_counter() - starttime
        stats["forwardzone"]["runtime"] = runtime

    if csvdata["hostrecord"]:
        starttime = time.perf_counter()
        start_threads(add_host_record, csvdata["hostrecord"])
        runtime = time.perf_counter() - starttime
        stats["hostrecord"]["runtime"] = runtime

    if csvdata["hostaddress"]:
        starttime = time.perf_counter()
        start_threads(add_host_address, csvdata["hostaddress"])
        runtime = time.perf_counter() - starttime
        stats["hostaddress"]["runtime"] = runtime

    if csvdata["arecord"]:
        starttime = time.perf_counter()
        start_threads(add_a_record, csvdata["arecord"])
        runtime = time.perf_counter() - starttime
        stats["arecord"]["runtime"] = runtime

    if csvdata["aaaarecord"]:
        starttime = time.perf_counter()
        start_threads(add_aaaa_record, csvdata["aaaarecord"])
        runtime = time.perf_counter() - starttime
        stats["aaaarecord"]["runtime"] = runtime

    if csvdata["ptrrecord"]:
        starttime = time.perf_counter()
        start_threads(add_ptr_record, csvdata["ptrrecord"])
        runtime = time.perf_counter() - starttime
        stats["ptrrecord"]["runtime"] = runtime

    if csvdata["caarecord"]:
        starttime = time.perf_counter()
        start_threads(add_caa_record, csvdata["caarecord"])
        runtime = time.perf_counter() - starttime
        stats["caarecord"]["runtime"] = runtime

    if csvdata["cnamerecord"]:
        starttime = time.perf_counter()
        start_threads(add_cname_record, csvdata["cnamerecord"])
        runtime = time.perf_counter() - starttime
        stats["cnamerecord"]["runtime"] = runtime

    if csvdata["mxrecord"]:
        starttime = time.perf_counter()
        start_threads(add_mx_record, csvdata["mxrecord"])
        runtime = time.perf_counter() - starttime
        stats["mxrecord"]["runtime"] = runtime

    if csvdata["naptrrecord"]:
        starttime = time.perf_counter()
        start_threads(add_naptr_record, csvdata["naptrrecord"])
        runtime = time.perf_counter() - starttime
        stats["naptrrecord"]["runtime"] = runtime

    if csvdata["srvrecord"]:
        starttime = time.perf_counter()
        start_threads(add_srv_record, csvdata["srvrecord"])
        runtime = time.perf_counter() - starttime
        stats["srvrecord"]["runtime"] = runtime

    if csvdata["txtrecord"]:
        starttime = time.perf_counter()
        start_threads(add_txt_record, csvdata["txtrecord"])
        runtime = time.perf_counter() - starttime
        stats["txtrecord"]["runtime"] = runtime

    if csvdata["bulkhost"]:
        starttime = time.perf_counter()
        start_threads(process_bulkhost_record, csvdata["bulkhost"])
        runtime = time.perf_counter() - starttime
        stats["bulkhost"]["runtime"] = runtime

    # output the stats
    log.info("=====================================================================")
    log.info("")
    log.info("Data Import Statistics")
    log.info("")
    log.info("     CSV Type          Total    Success   Failed   Time(s)   Obj/Sec")
    log.info("==================== ========= ========= ======== ========= =========")
    totFailed = 0
    totSuccess = 0

    for csvtype in sorted(stats):

        # calculate stats
        success = stats[csvtype]["success"]
        totSuccess += success
        failed = stats[csvtype]["failed"]
        totFailed += failed
        total = success + failed

        # calculate speed
        speed = 0.0
        runtime = stats[csvtype]["runtime"]
        if runtime:
            speed = total / runtime

        # log the stats
        log.info(f'{csvtype:<20} {total:>9} {success:>9} {failed:>8} {runtime:>9.2f} {speed:>9.2f}')

    # compute the runtime
    grandTotal = totSuccess + totFailed
    t2 = time.perf_counter() - t
    average = grandTotal / t2

    # output the totals
    log.info("==================== ========= ========= ======== ========= =========")
    log.info(f"Total                {grandTotal:>9} {totSuccess:>9} {totFailed:>8} {t2:>9.2f} {average:>9.2f}")
    log.info("")
    log.info(f'Finished processing {grandTotal} objects in {t2:0.2f} seconds.')

    csvErrorFileObj.close()


def get_args():
    # Parse arguments
    parser = argparse.ArgumentParser(description='This is a NIOS CSV to B1DDI migration tool', prog='nios2b1ddi')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 20210216.3')
    parser.add_argument('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    parser.add_argument('-d', '--csvfile', action="store", dest="csvfilename", help="Path to CSV data file", required=True)
    parser.add_argument('--delimiter', action="store", dest="csvdelimiter", help="Delimiter used in CSV data file", required=False)
    parser.add_argument('-y', '--yaml', action="store", help="Alternate yaml config file for supported objects", default='objects.yaml')

    return parser.parse_args()


def main():
    global b1ddi, fieldmap

    options = get_args()
    # Read Supported Objects from yaml file
    obj_yaml = options.yaml

    # Read yaml file  and load into dictionary
    with open(obj_yaml) as fh:
        fieldmap = yaml.load(fh, Loader=yaml.FullLoader)

    # Parse the config options including URL, version and API key
    b1ddi = bloxone.b1ddi(cfg_file=options.config)

    # Build list of supported object types
    supported_types = fieldmap.keys()

    # Process all CSV data and pass support object types
    process_csv_data(options, supported_types)


if __name__ == "__main__":
    # execute only if run as a script
    main()

    sys.exit()
