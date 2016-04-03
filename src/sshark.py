#!/usr/bin/python

"""
This tool used to capture packets (pcap file) by tshark and insert them into a sqlite file
"""

import argparse
import subprocess
import shlex
import sys
import signal
import sqlite3
import xml.etree.cElementTree as ET

__main_author__ = 'M. Fatemipour'
__email__ = 'm.fatemipour@gmail.com'
__date__ = '2016-Apr-2'
__last_modified_date__ = '2016-Apr-2'
__version__ = '1.0.0'


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


profiles = {}

def handler(signum, frame):
    print 'interupt'
    proc.terminate()


def add_profile(prof):
    col = []
    filed = []
    type = []
    for f in prof:
        filed.append(f.attrib['filed'])
        col.append(f.attrib['column'])
        type.append(f.attrib['type'])

    display_fields = ''
    create_table_query = 'CREATE TABLE packets ('
    for i in range(0, len(col)):
        display_fields += '-e ' + filed[i] + ' '
        if i > 0:
            create_table_query += ', '
        create_table_query += col[i] + ' ' + type[i]
    create_table_query += ')'
    p = {'captureFilter': prof.attrib['captureFilter'], 'displayFilter': prof.attrib['displayFilter'],
         'sqliteName': prof.attrib['sqliteName'], 'pcapName': prof.attrib['pcapName'],
         'display_fields': display_fields, 'create_table_query': create_table_query}
    profiles[prof.attrib['Name']] = p



def parse_config(config_file):
    tree = ET.parse(config_file)
    root = tree.getroot()
    if root.tag != 'sshark_profiles':
        raise Exception('root of profiles xml must be sshark_profiles')
    for profile in root:
        add_profile(profile)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-c', '--config', type=argparse.FileType('r'), default='/usr/local/config/sshark_config.xml',
                    help="config file, if not mentioned /usr/local/sshark_config.xml will be used")
    parser.add_argument('-p', '--profile', type=str, default='TCP',
                    help="profile name, if not mentioned TCP will be used")
    parser.add_argument('-r', '--input', type=argparse.FileType('r'), default=None,
                    help="read packets from input file instead of network")
    args = parser.parse_args()
    print args.config.name
    parse_config(args.config.name)
    p = args.profile
    print 'Using profile ' + p
    conn = sqlite3.connect(profiles[p]['sqliteName'])
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS packets')
    capture_filter = profiles[p]['captureFilter']
    display_fields_str = profiles[p]['display_fields']
    c.execute(profiles[p]['create_table_query'])

    tshark_command = 'tshark -T fields ' + display_fields_str

    if args.input == None and len(profiles[p]['displayFilter']) == 0:
        tshark_command += ' -F pcap -w ' + profiles[p]['pcapName']

    if args.input == None:
        tshark_command += ' -f "' + profiles[p]['captureFilter'] + '"'

    if args.input != None:
        tshark_command += ' -r ' + args.input.name

    if  len(profiles[p]['displayFilter']) > 0:
        print bcolors.WARNING + 'When displayFilter has value saving captured file (pcap) is disabled.' +\
            bcolors.ENDC
        tshark_command += ' -Y "' + profiles[p]['displayFilter'] + '"'

    print 'tshark command: ' + bcolors.OKBLUE +  tshark_command + bcolors.ENDC
    proc = subprocess.Popen(shlex.split(tshark_command), stdout=subprocess.PIPE, stderr=sys.stderr)
    signal.signal(signal.SIGINT, handler)

    values_to_be_added = ''
    i = 0
    while True:
      line = proc.stdout.readline()
      if line != '':
          i += 1
          if len(values_to_be_added) > 0:
              values_to_be_added += ','
          values_to_be_added += '("' + line.replace('\t', '","').strip() + '")\n'
          if i % 100 == 0:
              conn.execute('INSERT INTO packets VALUES ' + values_to_be_added)
              conn.commit()
              values_to_be_added = ''
      else:
        break

    if len(values_to_be_added) > 0:
        conn.execute('INSERT INTO packets VALUES ' + values_to_be_added)
        conn.commit()
    proc.wait()
    print 'Done.'
