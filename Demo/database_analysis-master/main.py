#!/usr/local/bin/python3
'''
------------------------------------------------------------------------
 Description:
   Python script to generate and NIOS Shared Record Group Report
 Note:
   This is a fork of database_analysis v0.7.5
 Requirements:
   Python3 with lxml, argparse, tarfile, logging, re, time, sys, tqdm

 Author: Chris Marrison

 Date Last Updated: 20210824

 Copyright (c) 2021 Chris Marrison / John Neerdael / Infoblox
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
__author_email__ = 'chris@infoblox.com'

import dblib
import argparse, tarfile, logging, time, sys, tqdm
import os
import collections
import pprint
from itertools import (takewhile, repeat)
from lxml import etree


def parseargs():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Validate NIOS database backup for B1DDI compatibility')
    parser.add_argument('-d', '--database', action="store", help="Path to database file", default='database.bak')
    parser.add_argument('-c', '--customer', action="store", help="Customer name (optional)")
    parser.add_argument('-p', '--output_path', type=str, default='', help="Output file path (optional)")
    parser.add_argument('--dump', type=str, default='', help="Dump Object")
    parser.add_argument('--dump_all', action='store_true', help="Dump All Objects")
    parser.add_argument('--list_objects', action='store_true', help="Dump All Objects")
    parser.add_argument('--key_value', nargs=2, type=str, default='', help="Key/value pair to match on dump")
    parser.add_argument('--silent', action='store_true', help="Silent Mode")
    parser.add_argument('-v', '--version', action='store_true', help="Silent Mode")
    parser.add_argument('-y', '--yaml', type=str, help="Alternate yaml config file for objects", default='objects.yaml')
    parser.add_argument('-r', '--ryaml', type=str, help="Alternate report yaml config file for objects", default='report_config.yaml')
    parser.add_argument('--debug', help="Enable debug logging", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.INFO)

    return parser.parse_args()

def report_versions(objyaml):
    '''
    Rerport code and config versions
    '''
    DBCONFIG = dblib.DBCONFIG(objyaml)
    RCONFIG = dblib.REPORT_CONFIG()
    version_report = { 'main': __version__, 
                       'dblib': dblib.__version__, 
                       'DB Config': DBCONFIG.version(), 
                       'Report Config': RCONFIG.version() 
                      }
    return version_report


def process_onedb(xmlfile, iterations, silent_mode=False, objyaml=''):
    '''
    Process onedb.xml
    '''
    # parser = etree.XMLPullParser(target=AttributeFilter())
    report = {}
    object_counts = collections.Counter()
    member_counts = collections.Counter()
    enabled_features = collections.defaultdict(bool)

    report['processed'] = collections.defaultdict(list)
    report['collected'] = collections.defaultdict(list)
    report['counters'] = object_counts
    report['features'] = enabled_features
    report['member_counts'] = collections.defaultdict()
    report['activeip'] = collections.defaultdict()
    # node_lease_count = collections.Counter()

    OBJECTS = dblib.DBCONFIG(objyaml)
    with tqdm.tqdm(total=iterations, disable=silent_mode) as pbar:
        count = 0
        #xmlfile.seek(0)
        context = etree.iterparse(xmlfile, events=('end',), tag='OBJECT')
        for event, elem in context:
            if event == 'end':
                count += 1
                try:
                    obj_value = dblib.get_object_value(elem)
                    obj_type = OBJECTS.obj_type(obj_value)
                    if OBJECTS.included(obj_value):
                        logging.debug('Processing object {}'.format(obj_value))
                        for action in OBJECTS.actions(obj_value):
                            # Action Count
                            if action == 'count':
                                # Use friendly object name
                                object_counts[obj_type] += 1

                            # Action Feature Enabled
                            elif action == 'feature':
                                feature = OBJECTS.feature(obj_value)
                                keypair = OBJECTS.keypair(obj_value)
                                if not enabled_features[feature]:
                                    if keypair and len(keypair) == 2:
                                        # Assume valid keypair
                                        enabled_features[feature] = dblib.check_feature(elem,
                                                                                        key_name=keypair[0],
                                                                                        expected_value=keypair[1])
                                    else:
                                        # Try default check
                                        enabled_features[feature] = dblib.check_feature(elem)
                                else:
                                    # Feature has already been found
                                    None

                            # Action Process
                            elif action == 'process':
                                process_object = getattr(dblib, OBJECTS.func(obj_value))
                                # onsider using a pandas dataframe
                                response = process_object(elem, count)
                                if response:
                                    report['processed'][obj_value].append(response)

                            # Action Collect 
                            elif action == 'collect':
                                collect_properties = OBJECTS.properties(obj_value)
                                response = dblib.process_object(elem, collect_properties)
                                if response:
                                    report['collected'][obj_value].append(response)

                            # Action Member Count
                            elif action == 'member':
                                process_object = getattr(dblib, OBJECTS.func(obj_value))
                                if obj_type not in report['member_counts'].keys():
                                    report['member_counts'][obj_type] = collections.Counter()
                                member = process_object(elem)
                                if member:
                                    report['member_counts'][obj_type][member] += 1
                            
                            # Action Active IP Estimate
                            elif action == 'activeip':
                                if obj_value not in report['activeip'].keys():
                                    report['activeip'][obj_value] = set()
                                report['activeip'][obj_value].add(dblib.process_activeip(elem))
                                    
                            # Action Not Implemented
                            else:
                                logging.warning('Action: {} not implemented'.format(action))
                                None
                    else:
                        logging.debug('Object: {} not defined'.format(obj_value))
                    
                        
                except:
                    raise
                pbar.update(1)
            elem.clear()

        '''
        # Log lease info
        for key in node_lease_count:
            logging.info('LEASECOUNT,{},{}'.format(key, node_lease_count[key]))
        '''

    return report


def output_reports(report, outfile, output_path=None, objyaml=''):
    '''
    Generate and output reports
    '''
    OBJECTS = dblib.DBCONFIG(objyaml)
    REPORT_CONFIG = dblib.REPORT_CONFIG()
    report_dataframes = {}
    summary_report = {}

    for section in REPORT_CONFIG.report_sections():
        if section in report.keys():
            if section == 'collected':
                logging.info('Generating dataframes for collected objects')
                report_dataframes['collected'] = dblib.report_collected(report['collected'], 
                                                                        REPORT_CONFIG, 
                                                                        OBJECTS)
                dblib.output_to_excel(report_dataframes['collected'], 
                                      title='Collected_Properties', 
                                      output_path=output_path,
                                      filename=outfile)

            elif section == 'processed':
                logging.info('Generating dataframes for processed objects')
                report_dataframes['processed'] = dblib.report_processed(report['processed'], 
                                                                        REPORT_CONFIG, 
                                                                        OBJECTS)
                dblib.output_to_excel(report_dataframes['processed'],
                                      title='Processed_Objects', 
                                      output_path=output_path,
                                      filename=outfile)

            elif section == 'counters':
                # counters_dfs = dblib.report_counters(report, REPORT_CONFIG, OBJECTS)
                logging.info('Generating dataframes for object counters')
                report_dataframes['counters'] = dblib.report_counters(report['counters'], 
                                                                      REPORT_CONFIG, 
                                                                      OBJECTS)

            elif section == 'member_counts':
                logging.info('Generating dataframes for member counters')
                report_dataframes['member_counts'] = dblib.report_mcounters(report['member_counts'], 
                                                                      REPORT_CONFIG, 
                                                                      OBJECTS)

            elif section == 'features':
                logging.info('Generating dataframes for features enabled')
                report_dataframes['features'] = dblib.report_features(report['features'],
                                                                      REPORT_CONFIG,
                                                                      OBJECTS)
            elif section == 'activeip':
                logging.info('Generating dataframes for Active IP Estimate')
                report_dataframes['activeip'] = dblib.report_activeip(report,
                                                                      REPORT_CONFIG,
                                                                      OBJECTS)
            
        # Additional reports
        elif section == 'srg':
            logging.info('Generating report for SRGs')
            report_dataframes['srg'] = dblib.report_srg(report['collected'],
                                                        REPORT_CONFIG,
                                                        OBJECTS)
            dblib.output_to_excel(report_dataframes['srg'],
                                    title='SRG Report',
                                    output_path=output_path,
                                    filename=outfile)

        elif section == 'summary':
            summary_report = dblib.generate_summary(report_dataframes,
                                                    REPORT_CONFIG,
                                                    OBJECTS)
            dblib.output_to_excel(summary_report,
                                    title='Summary_Report',
                                    output_path=output_path,
                                    filename=outfile)

        else:
            logging.error(f'Report {section} not implemented')
            print(f'Report {section} not implemented')


    return


def process_backup(database, 
                   outfile, 
                   output_path=None,
                   silent_mode=False, 
                   dump_obj=None,
                   dump_all=False,
                   list_objs=False,
                   key_value=None,
                   logfile='',
                   objyaml=''):
    '''
    Determine whether backup File or XML

    Parameters:
        database (str): Filename
        outfile (str): postfix for output files
        output_path (str): Path for file output
        silent_mode (bool): Do not log to console
        dump_obj(str): Dump object from database
        dump_all(bool): Dump all specified objects
        list_objs(bool): List all object types
        key_value(list): Key Value Pair to match using dump 
        objyaml (str): Object config yaml file
    '''
    status = False
    t = time.perf_counter()

    if tarfile.is_tarfile(database):
        # Extract db from backup
        logging.info('EXTRACTING DATABASE FROM BACKUP')
        with tarfile.open(database, "r:gz") as tar:
            xmlfile = tar.extractfile('onedb.xml')
            status = process_file(xmlfile, 
                                  outfile,
                                  output_path=output_path,
                                  silent_mode=silent_mode, 
                                  dump_obj=dump_obj,
                                  dump_all=dump_all,
                                  list_objs=list_objs,
                                  key_value=key_value,
                                  t=t,
                                  objyaml=objyaml)

        t2 = time.perf_counter() - t
        logging.info(f'EXTRACTED DATABASE FROM BACKUP IN {t2:0.2f}S')
    else:
        # Assume onedb.xml
        logging.info('NOT BACKUP FILE ATTEMPTING TO PROCESS AS onedb.xml')
        with open(database, 'rb') as xmlfile:
            status = process_file(xmlfile, 
                                  outfile,
                                  output_path=output_path,
                                  silent_mode=silent_mode, 
                                  dump_obj=dump_obj,
                                  dump_all=dump_all,
                                  key_value=key_value,
                                  logfile=logfile,
                                  objyaml=objyaml)

    return status


def process_file(xmlfile, outfile, 
                 output_path=None,
                 silent_mode=False, 
                 dump_obj=None,
                 dump_all=False,
                 list_objs=False,
                 key_value=None,
                 logfile='',
                 t=time.perf_counter(),
                 objyaml=''):
    '''
    Process file

    Parameters:
        xmlfile (file): file handler
        outfile (str): postfix for output files
        output_path (str): Path for file output
        silent_mode (bool): Do not log to console
        dump_obj(str): Dump object from database
        dump_all(bool): Dump all specified objects
        list_objs(bool): List all object types
        logfile (str): Logging filename
        t (obj): time.perfcounter object
        objyaml (str): Object config yaml file
    
    Returns:
        True or False 
    '''
    status = False

    if not dump_obj and not list_objs:
        t2 = time.perf_counter() - t
        iterations = dblib.rawincount(xmlfile)
        xmlfile.seek(0)
        t3 = time.perf_counter() - t2

        logging.info(f'COUNTED {iterations} OBJECTS IN {t3:0.2f}S')

        # searchrootobjects(xmlfile, iterations)
        db_report = process_onedb(xmlfile, iterations, silent_mode=silent_mode, objyaml=objyaml)
        output_reports(db_report, outfile, output_path=output_path, objyaml=objyaml)

        t4 = time.perf_counter() - t
        logging.info(f'FINISHED PROCESSING IN {t4:0.2f}S, LOGFILE: {logfile}')
        status = True

    if dump_obj:
        if key_value:
            if dblib.dump_object(dump_obj, 
                                 xmlfile, 
                                 all=dump_all,
                                 property=key_value[0], 
                                 value=key_value[1]):
                status = True
        else:
            if dblib.dump_object(dump_obj, xmlfile, all=dump_all):
                status = True
    
    if list_objs:
        if dblib.list_object_types(xmlfile):
            status = True

    return status


def main():
    '''
    Core logic
    '''
    exitcode = 0
    logfile = ''
    options = parseargs()
    database = options.database
    objyaml = options.yaml

    # Set up logging & reporting
    # log events to the log file and to stdout
    # dateTime=time.strftime("%H%M%S-%d%m%Y")
    dateTime = time.strftime('%Y%m%d-%H%M%S')

    # Set output path if provided
    if options.output_path:
        if os.path.isdir(options.output_path):
            output_path = f'{options.output_path}/'
        else:
            print(f'Specified output path {options.output_path} does not exit')
            output_path = None
    else:
        output_path = None

    # Set output file
    if options.customer:
        outfile = f'{options.customer}-{dateTime}.xlsx'
    else:
        outfile = f'-{dateTime}.xlsx'

    # Set up logging
    logfile = f'{output_path}{dateTime}.log'
    file_handler = logging.FileHandler(filename=logfile)
    stdout_handler = logging.StreamHandler(sys.stdout)
    # Output to CLI and config
    handlers = [file_handler, stdout_handler]
    # Output to config only
    filehandler = [file_handler]

    # Check for silent mode
    if options.silent:
        logging.basicConfig(
            level=options.loglevel,
            format='%(message)s',
            handlers=filehandler
            )
    else:
        logging.basicConfig(
            level=options.loglevel,
            format='%(message)s',
            handlers=handlers
            )

    # Check run mode
    if options.version:
       v = report_versions(objyaml)
       pprint.pprint(v)
    else:
       process_backup(database, outfile, 
                      output_path = output_path,
                      silent_mode=options.silent, 
                      dump_obj=options.dump,
                      dump_all=options.dump_all,
                      list_objs=options.list_objects,
                      key_value=options.key_value,
                      logfile=logfile,
                      objyaml=objyaml)

    return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)