#!/usr/local/bin/python3
'''
------------------------------------------------------------------------
 Description:
   Python script to search for feature gaps between NIOS and BloxOne DDI

 Requirements:
   Python3 with lxml, argparse, tarfile, logging, re, time, sys, tqdm

 Author: Chris Marrison & John Neerdael

 Date Last Updated: 20210825
 
 Copyright (c) 2021 John Neerdael / Infoblox

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHetreeHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
------------------------------------------------------------------------
'''
__version__ = '0.8.1'
__author__ = 'Chris Marrison, John Neerdael'
__author_email__ = 'chris@infoblox.com, jneerdael@infoblox.com'

import datetime
import logging
import re
import os
import configparser
import collections
import yaml
import pandas as pd
import xlsxwriter
import pprint
from lxml import etree
from itertools import (takewhile,repeat)

rehex = re.compile('^[0-9a-fA-F:\s]*$')

class DBCONFIG():
    '''
    Define Class for onedb.xml db objects
    '''

    def __init__(self, cfg_file='objects.yaml'):
        '''
        Initialise Class Using YAML config
        '''
        self.config = {}
   
        # Check for inifile and raise exception if not found
        if os.path.isfile(cfg_file):
            # Attempt to read api_key from ini file
            try:

                self.config = yaml.safe_load(open(cfg_file, 'r'))
            except yaml.YAMLError as err:
                logging.error(err)
                raise
        else:
            logging.error('No such file {}'.format(cfg_file))
            raise FileNotFoundError('YAML object file "{}" not found.'.format(cfg_file))

        return


    def version(self):
        return self.config['version']


    def keys(self):
        return self.config.keys()


    def objects(self):
        return self.config['objects'].keys()


    def obj_keys(self, dbobj):
        '''
        Return Objects Keys
        '''
        if self.included(dbobj):
             response = self.config['objects'][dbobj].keys()
        else:
            response = None
        
        return response


    def count(self):
        return len(self.config['objects'])  


    def included(self, dbobj):
        '''
        Check whether this dbobj is configured
        '''
        status = False
        if dbobj in self.objects():
            status = True
        else:
            status = False

        return status


    def obj_type(self, dbobj):
        '''
        Return simple name of object
        '''
        t = None
        if self.included(dbobj):
            t = self.config['objects'][dbobj]['type']
        else:
            t = None
        
        return t


    def header(self, dbobj):
        '''
        Return name of function for dbobj
        '''
        if self.included(dbobj):
            if 'header' in self.config['objects'][dbobj]:
                header = self.config['objects'][dbobj]['header']
            else:
                header = ''
        else:
            header = ''
            # Consider raising KeyError Exception

        return header


    def actions(self, dbobj):
        '''
        Get list of actions for dbobj
        '''
        actions = []
        if self.included(dbobj):
            actions = self.config['objects'][dbobj]['actions']
        else:
            actions = []
        
        return actions
    

    def func(self, dbobj):
        '''
        Return name of function for dbobj
        '''
        if self.included(dbobj):
            if 'func' in self.config['objects'][dbobj]:
                function = self.config['objects'][dbobj]['func']
            else:
                function = None
        else:
            function = None
            # Consider raising KeyError Exception

        return function


    def properties(self, dbobj):
        return self.config['objects'][dbobj]['properties']


    def feature(self, dbobj):
        '''
        Return 'feature' value if exists
        '''
        if self.included(dbobj):
            if 'feature' in self.obj_keys(dbobj):
                r = self.config['objects'][dbobj]['feature']
            else:
                r = None
        else:
            r = None
        
        return r


    def keypair(self, dbobj):
        '''
        Return Keypair as a list
        '''
        if 'keypair' in self.obj_keys(dbobj):
            response = self.config['objects'][dbobj]['keypair']
        else:
            response = None
        
        return response


    def report_types(self, dbobj):
        '''
        Return list of reports for dbobj
        '''
        reports = []
        if self.included(dbobj):
            reports = self.config['objects'][dbobj]['reports']
        else:
            reports = None
        
        return reports


    def incompatible_options(self):
        return self.config['incompatible_options']
   

    def validate_options(self):
        return self.config['validate_options']

    
    def srg_records(self):
        return self.config['srg_records']


class REPORT_CONFIG():
    '''
    Define Class for reporting db objects
    '''

    def __init__(self, cfg_file='report_config.yaml'):
        '''
        Initialise Class Using YAML config
        '''
        self.config = {}
   
        # Check for inifile and raise exception if not found
        if os.path.isfile(cfg_file):
            # Attempt to read api_key from ini file
            try:

                self.config = yaml.safe_load(open(cfg_file, 'r'))
            except yaml.YAMLError as err:
                logging.error(err)
                raise
        else:
            logging.error('No such file {}'.format(cfg_file))
            raise FileNotFoundError('YAML object file "{}" not found.'.format(cfg_file))

        return


    def version(self):
        return self.config['version']


    def report_sections(self):
        return self.config['report_sections']
    

    def summary_items(self):
        return self.config['summary_items']


    def summary_keys(self, item):
        return self.config['summary_items'][item]['keys']


    def summary_name(self, item):
        return self.config['summary_items'][item]['name']
  

# *** Functions ***

# Read config as global var 
CONFIG = DBCONFIG()

def read_ini(ini_filename):
    '''
    Open and parse ini file

    Parameters:
        ini_filename (str): name of inifile

    Returns:
        config (dict): Dictionary of BloxOne configuration elements

    '''
    # Local Variables
    cfg = configparser.ConfigParser()
    config = {}
    ini_keys = [ 'db_type', 'output_path', 'create_archive', 'dbobjects_config', 'report_config' ]

    # Attempt to read api_key from ini file
    try:
        cfg.read(ini_filename)
    except configparser.Error as err:
        logging.error(err)

    # Look for demo section
    if 'DDI_Analysis' in cfg:
        for key in ini_keys:
            # Check for key in BloxOne section
            if key in cfg['DDI_Analysis']:
                config[key] = cfg['DDI_Analysis'][key].strip("'\"")
                logging.debug('Key {} found in {}: {}'.format(key, ini_filename, config[key]))
            else:
                logging.warning('Key {} not found in B1DDI_demo section.'.format(key))
                config[key] = ''
    else:
        logging.warning('No DDI_Analysis Section in config file: {}'.format(ini_filename))

    return config


def check_feature(xmlobject, key_name='enabled', expected_value='true'):
    '''
    Check for feature enabled
    '''
    enabled = None
    for property in xmlobject:
        if property.attrib['NAME'] == key_name:
            if property.attrib['VALUE'] == expected_value:
                enabled = True
            else:
                enabled = False
            break
        else:
            enabled = None
    return enabled


def process_object(xmlobject, collect_properties):
    '''
    Generic Object Capture

    Parameters:
        xmlobject (obj): XML Object
        collect_properties (list): list of XML Properties to collect

    Returns:
        Dictionary of properties
    '''
    obj_dict = obj_to_dict(xmlobject, collect_only=collect_properties)
    logging.debug(f'- process_object: {obj_dict}')

    return obj_dict


def obj_to_dict(xmlobject, collect_only=None):
    '''
    Collect property/value pairs in dict

    Parameters:
        xmlobject (obj): object to process
        collect_only (list): list of properties to return
    
    Returns:
        dict of properties
    '''
    dict_obj = collections.defaultdict()
    for property in xmlobject:
        dict_obj[property.attrib['NAME']] = property.attrib['VALUE']
    
    if collect_only:
        temp_dict = collections.defaultdict()
        for k in dict_obj.keys():
            if k in collect_only:
                temp_dict[k] = dict_obj[k]
        dict_obj = temp_dict
    
    return dict_obj


def dump_object(db_obj, xmlfile, all=False, property='', value=''):
    '''
    Dump first instance of specified object or all matching objects

    Parameters:
        one_db_obj (str): OneDB Object Type
        xmlfile (obj): File handler for XML file
        property (str): match property
        value (str): value property should match
    
    '''
    found = False
    context = etree.iterparse(xmlfile, events=('end',), tag='OBJECT')
    for event, elem in context:
        if event == 'end':
            obj_value = get_object_value(elem)
            if obj_value == db_obj:
                if property:
                    if check_feature(elem, key_name=property, expected_value=value):
                        output_object(elem)
                        found = True
                        if not all:
                            break
                else:
                    # Just match first object
                    output_object(elem)
                    found = True
                    if not all:
                        break
                    
    if not found:
        if property:
            print(f'Object: {db_obj} not found in db with key/value {property}/{value}')
        else:
            print(f'Object: {db_obj} not found in db')

    return found


def output_object(xmlobject):
    '''
    Generic Object Capture

    Parameters:
        xmlobject (obj): XML Object

    Returns:
        Dictionary of properties
    '''
    collected_properties = obj_to_dict(xmlobject)
    pprint.pprint(collected_properties)

    return collected_properties


def list_object_types(xmlfile):
    '''
    List unique object types in NIOS db
    
    Parameters:
        xmlfile (obj): File handler for XML file
    
    '''
    obj_types = set()
    status = False

    context = etree.iterparse(xmlfile, events=('end',), tag='OBJECT')
    for event, elem in context:
        if event == 'end':
            obj_types.add(get_object_value(elem))
            
    
    if len(obj_types):
        for obj in sorted(obj_types):
            print(obj)
        status = True
    else:
        print('No objects found')
    
    return status


def processdhcpoption(xmlobject, count):
    '''
    Look for DHCP options that need further verification
    '''
    parent = optiondef = value = ''

    values = [ 'parent', 'option_definition', 'value' ]
    option_values = process_object(xmlobject, values)
    if option_values:
        parent = option_values['parent']
        optiondef = option_values['option_definition']
        value = option_values['value']
        type, parentobj = checkparentobject(parent)
        optionspace, optioncode = checkdhcpoption(optiondef)
        hexvalue = False
        if rehex.match(value):
            hexvalue = True

    report = validatedhcpoption(type, parentobj, optionspace, optioncode, hexvalue, value, count)
    if len(report) == 1 and report[0] == '':
        report = None

    return report


def process_network(xmlobject, count):
    '''
    Look for /32 networks
    '''

    dict = obj_to_dict(xmlobject)
    cidr = dict.get('cidr')
    address = dict.get('address')

    if cidr == '32':
        report = [ 'DHCPNETWORK', 'CHECK_GUARDRAILS', address, '/' + cidr , str(count) ]
        logging.debug(f'{report}')
    else:
        report = []

    if len(report) == 1 and report[0] == '':
        report = []
    return report


def process_mac_filter_item(xmlobject, count):
    '''
    Look for Mac prefix filters
    '''
    report = []
    dict = obj_to_dict(xmlobject)
    mac_address = dict.get('mac_address')
    mac_filter = dict.get('dhcp_mac_filter')

    if len(mac_address.split(':')) < 6:
        report = [ 'MAC_PREFIX_FILTER', 'CHECK_GUARDRAILS', mac_address, 
                   mac_filter, str(count) ]
        logging.debug(f'{report}')
    
    return report


def rawincount(filename):
    bufgen = takewhile(lambda x: x, (filename.raw.read(1024*1024) for _ in repeat(None)))
    return sum( buf.count(b'\n') for buf in bufgen )


def validateobject(xmlobject):
    '''
    Validate object type
    *** Deprecated ***
    '''
    object = ''
    for property in xmlobject:
        if property.attrib['NAME'] == '__type' and property.attrib['VALUE'] == '.com.infoblox.dns.option':
            object = 'dhcpoption'
            break
        elif property.attrib['NAME'] == '__type' and property.attrib['VALUE'] == '.com.infoblox.dns.network':
            object = 'dhcpnetwork'
            break
        elif property.attrib['NAME'] == '__type' and property.attrib['VALUE'] == '.com.infoblox.dns.lease':
            object = 'dhcplease'
            break
        elif property.attrib['NAME'] == '__type':
            object = ''
            break
    return object


def get_object_value(xmlobject):
    '''
    Return the object value
    '''
    obj = ''
    for property in xmlobject:
        if property.attrib['NAME'] == '__type':
            obj = property.attrib['VALUE']
            break

    return str(obj)


def checkparentobject(parent):
    objects = parent.split('$')
    type = parentobj = ''
    if objects:
        if objects[0] == '.com.infoblox.dns.network':
            type = 'NETWORK'
            parentobj = objects[1][:-2]
        elif objects[0] == '.com.infoblox.dns.fixed_address':
            type = 'FIXEDADDRESS'
            parentobj = objects[1][:-4]
        elif objects[0] == '.com.infoblox.dns.dhcp_range':
            type = 'DHCPRANGE'
            parentobj = objects[1][:-5]
        elif objects[0] == '.com.infoblox.dns.network_container':
            type = 'NETWORKCONTAINER'
            parentobj = objects[1][:-2]
    return type, parentobj


def checkdhcpoption(dhcpoption):
    optioncodes = dhcpoption.split('.')
    optionspace = optioncode = ''
    if dhcpoption == '':
        optionspace = optioncode = ''
    else:
        optionspace = optioncodes[0]
        optioncode = int(optioncodes[3])
    return optionspace, optioncode

'''
def validatehex(values):
    if re.search(r"^[0-9a-fA-F:\s]*$", values):
        # Normalize the HEX
        values = values.replace(':', '')
        values = values.replace(' ', '')
        values = values.lower()
        list = iter(values)
        values = ':'.join(a + b for a, b in zip(list, list))
        hexvalue = True
        return hexvalue, values
    else:
        hexvalue = False
        return hexvalue, values
'''

def validatedhcpoption(type, parentobj, optionspace, optioncode, hexvalue, optionvalue, count):
    '''
    Validate DHCP Options
    '''
    incompatible_options = CONFIG.incompatible_options()
    validate_options = CONFIG.validate_options()

    r = []

    if optioncode in incompatible_options:
        r = [ 'DHCPOPTION', 'CHECK_GUARDRAILS', type, parentobj, optionspace, str(optioncode), optionvalue, str(count) ]
    elif optioncode in validate_options:
        if optioncode == 43:
            if hexvalue == True:
                r = [ 'DHCPOPTION', 'VALIDATION_NEEDED', type, parentobj, optionspace, str(optioncode), optionvalue, str(count) ]
            elif hexvalue == False:
                r = [ 'DHCPOPTION', 'CHECK_GUARDRAILS', type, parentobj, optionspace, str(optioncode), optionvalue, str(count) ]
        else:
            r = [ 'DHCPOPTION', 'VALIDATION_NEEDED', type, parentobj, optionspace, str(optioncode), optionvalue, str(count) ]
    else:
        r = []

    validation = r
    logging.debug(f'{validation}')

    return validation


def validatenetwork(address, cidr, count):
    '''
    Look for /32 networks
    '''
    if cidr == '32':
        report = [ 'DHCPNETWORK', 'CHECK_GUARDRAILS', address, '/' + cidr , str(count) ]
        logging.debug(f'{report}')
    else:
        report = []
    
    return report


def member_leases(xmlobject):
    '''
    Determine Lease State
    '''
    member = ''
    for property in xmlobject:
        count = False
        if property.attrib['NAME'] == 'node_id':
            node = property.attrib['VALUE']
        if property.attrib['NAME'] == 'binding_state' and property.attrib['VALUE'] == 'active':
            member = node

    return member


def process_activeip(xmlobject):
    '''
    Collect IP if deemed active
    '''
    ip_identifier = ''
    obj_value = get_object_value(xmlobject)
    properties = obj_to_dict(xmlobject)

    # Active Leases
    if obj_value == '.com.infoblox.dns.lease':
       if properties.get('binding_state') == 'active': 
           network_view = properties.get('network_view', '0')
           ip_identifier = f'{network_view}${properties["ip_address"]}'
    # Fixed Addresses
    elif obj_value == '.com.infoblox.dns.fixed_address':
        network_view = properties.get('network_view', '0')
        ip_identifier = f'{network_view}${properties["ip_address"]}'
    # Host Addresses
    elif obj_value == '.com.infoblox.dns.host_address':
        network_view = properties.get('dhcp_delegation_root', '$0').split('$')[1]
        ip_identifier = f'{network_view}${properties["address"]}'
    # A Records
    elif obj_value == '.com.infoblox.dns.bind_a':
        dns_view = properties.get('zone', '._default').split('.')[1]
        ip_identifier = f'{dns_view}${properties["address"]}'
    # AAAA Records
    elif obj_value == '.com.infoblox.dns.bind_aaaa':
        dns_view = properties.get('zone', '._default').split('.')[1]
        ip_identifier = f'{dns_view}${properties["address"]}'
    # PTR Records
    elif obj_value == '.com.infoblox.dns.bind_ptr':
        ip_identifier = ip_from_ptr(properties)
    # Not Applicable
    else:
        ip_identifier = ''
    
    logging.debug(f'{obj_value} - {ip_identifier}')

    return ip_identifier


def ip_from_ptr(properties):
    '''
    Convert dict of .com.infoblox.dns.bind_ptr to IP address
    '''
    ip_id = ''
    zone = properties.get('zone').split('.')
    dns_view = zone[1]

    # Check IP version
    if zone[3] == 'in-addr':
        delimiter = '.'
    else:
        delimiter = ':'
    # Build IP identity
    ip_id = f'{dns_view}$'
    # Generate IP string
    for i in range(4, len(zone)):
        ip_id += f'{zone[i]}{delimiter}' 
    ip_id += properties['name']

    return ip_id


def reverse_labels(domain):
    '''
    Reserve order of domain labels (or any dot separated data, e.g. IP)

    Parameters:
        domain (str): domain.labels
    Returns:
        rdomain (str): labels.domain
    '''
    rdomain = ""
    labels = domain.split(".")
    for l in reversed(labels):
        if rdomain:
            rdomain = rdomain+"."+l
        else:
            rdomain = l
    return rdomain


def writeheaders():
    logging.info('HEADER-DHCPOPTION,STATUS,OBJECTTYPE,OBJECT,OPTIONSPACE,OPTIONCODE,OPTIONVALUE')
    logging.info('HEADER-DHCPNETWORK,STATUS,OBJECT,OBJECTLINE')
    logging.info('HEADER-LEASECOUNT,MEMBER,ACTIVELEASES')
    return


def output_to_excel(dict_of_dataframes, 
                    title='Report', 
                    output_path=None,
                    filename='temp.xlsx'):
    '''
    Output a set of DataFrames to Excel
    '''
    if output_path:
        filename = f'{output_path}{title}_{filename}'
    else:
        filename = f'{title}_{filename}'

    logging.info(f'Ouput filename set to: {filename}')

    # Create Excel Writer using xlsxwriter as the engine
    try:
        writer = pd.ExcelWriter(filename, engine='xlsxwriter')
        logging.info(f'Creating excel file: {filename}')
    
        # Create Excel Sheets
        for name in dict_of_dataframes:
            if not dict_of_dataframes[name].empty:
                logging.info(f'+ Creating sheet {name}')
                dict_of_dataframes[name].to_excel(writer, sheet_name=name)
            else:
                err = [ 'Not data for ' + name ]
                df = pd.DataFrame(err)
                df.to_excel(writer, sheet_name=name)
                logging.error(f'DataFrame {name} empty: {dict_of_dataframes[name]}')

        # Save Excel
        writer.save()
        logging.info(f'Saved excel file: {filename}')

    except:
        logging.error(f'Failed to create excel file: {filename}')

    return


def report_processed(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Generate and Output report for processed content
    '''
    report_dfs = collections.defaultdict(pd.DataFrame)
    if len(report.keys()):
        for obj in report.keys():
            if DBOBJECTS.header(obj):
                labels = DBOBJECTS.header(obj).split(',')
            else:
                labels = []
            # Generate Dataframes(DBOBJECTS.obj_type(obj))
            try:
                otype = DBOBJECTS.obj_type(obj)
                logging.info(f'Generating dataframe for processed object: {obj}, type: {otype}')
                report_dfs[otype] = pd.DataFrame(report[obj], columns=labels)
            except:
                logging.error('{}: {}, {}'.format(obj, report[obj], labels))
            # pprint.pprint(df)
    else:
        logging.info('No data for processed objects')

    return report_dfs


def report_collected(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Generate and Output report for collected content
    '''
    report_dfs = collections.defaultdict(pd.DataFrame)
    for obj in report.keys():
        logging.info(f'Generating dataframe for collected data for object: {obj}')
        report_dfs[DBOBJECTS.obj_type(obj)] = pd.DataFrame(report[obj])
    
    return report_dfs


def report_counters(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Report Counters
    '''
    logging.info(f'Generating dataframe for object counters')
    report_df = pd.DataFrame(report.most_common(), columns=['Object', 'Count'])
    logging.debug(report_df) 
    
    return report_df


def report_mcounters(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Report Counters
    '''
    report_dfs = collections.defaultdict(pd.DataFrame)
    logging.info(f'Generating dataframe for Member counters')
    for obj in report.keys():
        logging.info(f'+ Creating dataframe for object: {obj}')
        report_dfs[obj] = pd.DataFrame(report[obj].most_common(), 
                                       columns=['Member', 'Count'])
        logging.debug(report_dfs[obj]) 
    return report_dfs


def report_features(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Report Counters
    '''
    logging.info(f'Generating dataframe for features')
    report_df = pd.DataFrame(report.items(), columns=['Feature', 'Enabled'])
    report_df.fillna('Check Req')
    logging.debug(report_df)
    
    return report_df


def report_activeip(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Report Active IP Estimate
    '''
    view = '0'
    total = 0
    dns_views = report['collected'].get('.com.infoblox.dns.view')
    network_views = report['collected'].get('.com.infoblox.dns.network_view')
    dataset = []
    view_ip = collections.defaultdict()
    per_view_report = []
    report_dfs = collections.defaultdict(pd.DataFrame)
    net_objs = [ '.com.infoblox.dns.lease', '.com.infoblox.dns.fixed_address']

    logging.info(f'Generating dataframe for active IP estimate')
    # Get Network Views for DNS objects
    for obj in report['activeip'].keys():
        type_counter = int()
        type_report = collections.defaultdict()
        obj_type = DBOBJECTS.obj_type(obj)

        # Interate over IP identifiers for obj
        for ip_id in report['activeip'][obj]:
            ip_identifier = ip_id.split('$')
            if len(ip_identifier) == 2:
                view = ip_identifier[0]
                ip = ip_identifier[1]
            else:
                logging.debug(f'{obj} {ip_identifier}')
                view = '0'
                ip = '0.0.0.0'
            if obj not in net_objs:
                # Get associated network view
                for dview in dns_views:
                    if dview.get('zone') == f'.{view}':
                        view = dview.get('network_view')
                        break
            # Check for dictionary elements
            if view not in type_report.keys():
                type_report[view] = set()
            if view not in view_ip.keys():
                view_ip[view] = set()
            # Assign to reports
            type_report[view].add(ip)
            view_ip[view].add(ip)
    
        # Build per object Reports
        for v in type_report.keys():
            type_counter += len(type_report[v])

        dataset.append({ 'Object Type': obj_type,
                         'Est_Active_IPs': type_counter } )
            
    # Unique per Network View Report
    for v in view_ip.keys():
        vname = v
        unique_ip_count = len(view_ip[v])
        # Get network view name
        for nview in network_views:
            if nview.get('id') == v:
                vname = nview.get('name')
                break
        per_view_report.append({ 'Network View': vname,
                                 'Est_Active_IPs': unique_ip_count } )
        total += unique_ip_count
    per_view_report.append({'Network View': 'Total Active IP Estimate:',
                            'Est_Active_IPs': total })
    
    total_est = [ { 'Estimated Active IPs': total }]

            
    report_dfs['Active IP by Type'] = pd.DataFrame.from_records(dataset)
    report_dfs['Active IP by View'] = pd.DataFrame.from_records(per_view_report)
    report_dfs['Estimated Active IPs'] = pd.DataFrame.from_records(total_est)

    logging.debug(report_dfs) 

    return report_dfs
    


def report_srg(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Generate SRG Report for data import
    '''
    # srgs = collections.defaultdict()
    report_dfs = collections.defaultdict(pd.DataFrame)
    srgs = []
    zone_list = []
    srg_obj = '.com.infoblox.dns.srg'

    if srg_obj in report.keys():
        for group in report[srg_obj]:
            zone_list = srg_zone_list(report, group['zone'])
            srgs.append({'srg': group['zone'],
                         'name': group['name'],
                         'linked_zones':  zone_list })

        report_dfs['SRGs'] = pd.DataFrame.from_dict(srgs)
        # report_df = pd.DataFrame(srgs)
        logging.debug(report_dfs)
    return report_dfs


def srg_zone_list(report, srg):
    '''
    Take table of SRG/zone mappings and convert in to list
    '''
    srg_zones = []
    srg_zone_links = '.com.infoblox.dns.srg_zone_linking'

    if srg_zone_links in report.keys():
        for group in report[srg_zone_links]:
            if group.get('srg') == srg:
                srg_zones.append(group.get('zone'))
    
    return srg_zones


def generate_summary(report, REPORT_CONFIG, DBOBJECTS):
    '''
    Generate Dict of Dataframes For Summary Report
    '''
    summary_report = collections.defaultdict()

    if 'processed' in report.keys():
       for item in report['processed'].keys():
            if item in REPORT_CONFIG.summary_items():
                logging.info(f'Checking dataframe summary for {item}')
                if not report['processed'][item].empty:
                    logging.info(f'Generating summary for {item}')
                    summary_report[REPORT_CONFIG.summary_name(item)] = \
                        report['processed'][item].value_counts(
                            REPORT_CONFIG.summary_keys(item)).reset_index(name='No of instances') 
                else:
                    logging.warning(f'Dataframe for {item} reports as empty')
            else:
                logging.info(f'No summary report defined for processed object: {item}')

    if 'counters' in report.keys():
        summary_report['Object_Counters'] = report['counters']
    
    if 'member_counts' in report.keys():
        for obj in report['member_counts'].keys():
            sheet_name = 'Member_Count_' + str(obj)
            summary_report[sheet_name] = report['member_counts'][obj]
    
    if 'features' in report.keys():
        summary_report['Features'] = report['features']
    
    if 'activeip' in report.keys():
        for item in report['activeip'].keys():
            summary_report[item] = report['activeip'][item]
    
    return summary_report
