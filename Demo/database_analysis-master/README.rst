===============
DDI DB Analysis
===============

Version: 0.6.0
Author: Chris Marrison
Email: chris@infoblox.com

Description
-----------

This package is designed to provide an collect and provide some analysis of 
DDI configurations for the purpose of allowing the user to view and compare
the features against the B1DDI "Guardrail" documents.

The package currently performs this analysis against a either a backup file
from a NIOS Grid or the onedb.xml file from a NIOS Grid.


Prerequisites
-------------

Python 3.6 or above with Pandas 1.2.3+ and xlswriter


Modules
~~~~~~~

Requires:

    - pandas 1.2.3+
    - xlsxwriter
    - tqdmd
    - itertools
    - collections
    - lxml
    - yaml
    - time

Complete list of modules::

    import os
    import sys
    import json
    import argparse
    import configparser
    import logging
    import datetime
    import time


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

Configuration
--------------

There are two configuration files included that

Usage
-----


    - Implmented silent mode (--silernt)

    - Implemented –version

    -   This reports on the version of the main script (currently named 
        main.py), the associated library and as well as version numbers for 
        the YAML config files.

        This is return as a plain dictionary (json) output to STDOUT but let 
        me know if you need headers or anything added.


        

Basic examples::
 
    $ main.py –version
    $ main.py -d <backup_database> -c <customer_name> --silent
    $ main.py -d <database> --dump <object>
    $ main.py -d <database> --dump <object> --key_value <key> <value>


    


License
-------

This project is licensed under the 2-Clause BSD License - please see LICENSE
file for details.

Aknowledgements
---------------

A huge thanks to John Neerdael for coming up with the idea and building the
original prototype, and his contributions. Without this initial idea and work
this project wouldn't have happened.

Thanks to John Steele and Don Smith for their input, and especially to Krishna
for building the web front end and making this available to the field.

