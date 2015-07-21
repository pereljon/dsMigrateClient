#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'jonathan.perel'

# IMPORTS
import sys
import os
import exceptions
import subprocess
import re
import logging
import argparse
import getpass
import types
import time
from ConfigParser import SafeConfigParser
from SystemConfiguration import SCDynamicStoreCopyConsoleUser

# CONSTANTS
kIniFilePath = "/Users/Shared/dsMigrateClient.ini"
kProgramPath = "/Users/Shared/dsMigrateClient.py"
kLogPath = "/Users/Shared/dsMigrateClient.log"
kLaunchDaemonName = 'com.pereljon.dsMigrateClient'
kLaunchDaemonPath = '/Library/LaunchDaemons/' + kLaunchDaemonName + '.plist'
kLaunchDaemon = '<?xml version="1.0" encoding="UTF-8"?>\n\
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n\
<plist version="1.0">\n\
<dict>\n\
    <key>Label</key>\n\
    <string>' + kLaunchDaemonName + '</string>\n\
    <key>ProgramArguments</key>\n\
    <array>\n\
        <string>' + kProgramPath + '</string>\n\
        <string>-f</string>\n\
        <string>' + kIniFilePath + '</string>\n\
    </array>\n\
    <key>RunAtLoad</key>\n\
    <true/>\n\
</dict>\n\
</plist>'


def parse_arguments():
    # GLOBALS
    global gTestingMode
    global gForceDebug
    global gVerbose

    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Migrate a mobile user from once Mac OS X Directory Service to another.')
    parser.add_argument('-a', '--ad', action='store_true',
                        help='Active Directory.')
    parser.add_argument('-c', dest='computer', metavar='computername',
                        help='computer name .')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='log all debugging info to log file. Not needed if running in testing mode.')
    parser.add_argument('--delete', action='store_true',
                        help='delete settings files and scripts after use.')
    parser.add_argument('-f', '--file', metavar='filename',
                        help='read setting from file. All other options will be ignored.')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help="run in interactive mode, asking for the users password.")
    parser.add_argument('--headless', action='store_true',
                        help='headless (daemon) mode. Wait to run until user has logged out.')
    parser.add_argument('-l', '--ldap', action='store_true',
                        help='LDAP (OpenDirectory).')
    parser.add_argument('-n', '--dns', metavar='dnsserver', action='append',
                        help='dns.')
    parser.add_argument('-p', dest='target_password', metavar='password',
                        help='password for target (new) domain administrator.')
    parser.add_argument('-P', dest='source_password', metavar='password',
                        help='password for source (old) domain administrator.')
    parser.add_argument('-s', '--serial', action='store_true',
                        help='use system serial number as computer name.')
    parser.add_argument('-t', '--testing', action='store_true',
                        help='run in testing mode. Migration commands are logged to log file.')
    parser.add_argument('-u', dest='target_username', metavar='username',
                        help='administrator user for target (new) domain.')
    parser.add_argument('-U', dest='source_username', metavar='username',
                        help='administrator user for source (old) domain.')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output.')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='continue without prompting. \
                        Warning: do not use this unless you are 100%% sure of what you are doing.')
    parser.add_argument('target_domain', nargs='?', help='AD domain or LDAP server')
    args = parser.parse_args()

    # Set the logging level
    if args.testing or args.debug:
        logging.basicConfig(filename=kLogPath, level=logging.DEBUG)
    else:
        logging.basicConfig(filename=kLogPath, level=logging.INFO)

    if args.file is not None:
        if not os.path.exists(args.file):
            # Settings file not found
            logging.critical('Missing settings file at: %s', args.file)
            print 'Missing settings file at:' + args.file
            sys.exit(1)
        # Parse the settings file
        args = load_preferences(args)
        # Set the logging level
        if args.testing or args.debug:
            logger = logging.getLogger()
            logger.setLevel(level=logging.DEBUG)

    # Set globals from arguments
    # Set testing mode if running in testing mode or swapped testing mode
    gTestingMode = args.testing
    gForceDebug = args.debug
    # Set verbose output if requested or running in testing mode
    gVerbose = args.verbose or gTestingMode

    if gTestingMode:
        logging.info('### Running in Test Mode ###')
        print '### Running in Test Mode ###'
    else:
        logging.info('### Running in Production Mode###')
        if gVerbose:
            print '### Running in Production Mode ###'

    logging.debug('Running as: %s', getpass.getuser())

    # Error-checking on arguments
    if args.headless and args.interactive:
        logging.critical('Either specify headless or interactive mode.')
        print 'Either specify headless or interactive mode.'
        sys.exit(1)
    if args.file is None:
        # Settings file NOT specified
        if args.target_domain is None:
            # Did NOT specify a domain or settings file
            logging.critical('Either specify a domain or a settings file.')
            print 'Either specify a domain or a settings file.'
            sys.exit(1)
        if (args.ad and args.ldap) or (not args.ad and not args.ldap):
            print 'Error: Select either AD or LDAP for migration'
            sys.exit(1)

    return args


def load_preferences(args):
    # Load preferences file and return as args namespace
    logging.info('Loading preferences: %s', args.file)
    parser = SafeConfigParser()
    parser.read(args.file)
    # Remove settings file
    if args.delete:
        logging.debug('Remove settings file: %s', args.file)
        execute_command(['srm', args.file])
    # Parse sections
    for next_section in parser.sections():
        if next_section == 'general':
            # No section prefix for general
            prefix = ''
        else:
            # Section prefix
            prefix = next_section + '_'
        # Parse items
        for next_item in parser.items(next_section):
            next_name = prefix + next_item[0]
            if next_item[1].lower() == "true":
                next_value = True
            elif next_item[1].lower() == "false":
                next_value = False
            elif next_item[1].lower() == "none":
                next_value = None
            elif next_name == "dns":
                # Put DNS values in list
                next_value = next_item[1].split(",")
            else:
                next_value = next_item[1]
            setattr(args, next_name, next_value)
    return args


def save_preferences(args, filename):
    # Save args to preferences
    logging.info('Saving preferences: %s', filename)
    delattr(args,'file')
    parser = SafeConfigParser()
    args = vars(args)
    for next_item in args:
        value = args[next_item]
        section_split = next_item.split('_')
        if len(section_split) == 2:
            # Non-general section
            section = section_split[0]
            item = section_split[1]
        else:
            # General section
            section = 'general'
            item = next_item
        if not parser.has_section(section):
            # Add section
            parser.add_section(section)
        if isinstance(value, types.ListType):
            # Join list values with comma
            value = ",".join(value)
        parser.set(section, item, str(value))
    afile = open(filename, 'w')
    parser.write(afile)
    afile.close()


def execute_command(command):
    # Execute command
    logging.debug('executeCommand: %s', ' '.join(command))
    try:
        result = subprocess.check_output(command)
        logging.debug('Result: %s', result)
    except subprocess.CalledProcessError as error:
        logging.error('Return code: %s.', error.returncode)
        logging.error('Output: %s.', error.output)
        return error.output
    except exceptions.OSError as error:
        logging.critical('OS Error: %s.', error)
        sys.exit(1)
    except:
        logging.critical('Unexpected error: %s', sys.exc_info()[0])
        sys.exit(1)
    return result


def get_console_user():
    username = (SCDynamicStoreCopyConsoleUser(None, None, None) or [None])[0]
    username = [username, ""][username in [u"loginwindow", None, u""]]
    return username


def display_dialog(text, title=None, buttons=None, default=None, icon=None, answer=None, hidden=False, timeout=None):
    logging.info('Display dialog')
    # Process arguments
    if not text:
        print 'Empty dialog text'
        sys.exit(1)
    text = ' "' + text + '"'
    if title:
        title = ' with title "' + title + '"'
    else:
        title = ''
    if icon:
        # icon can be 'stop', 'caution', 'note'
        icon = ' with icon ' + icon
    else:
        icon = ''
    if buttons is not None and len(buttons):
        buttons = ' buttons ["' + '","'.join(buttons) + '"]'
    else:
        buttons = ''
    if default:
        default = ' default button ' + str(default)
    else:
        default = ''
    if answer is not None:
        answer = ' default answer "' + answer + '"'
    else:
        answer = ''
    if timeout:
        timeout = ' giving up after ' + str(timeout)
    else:
        timeout = ''
    if hidden:
        hidden = ' hidden answer true'
    else:
        hidden = ''
    # Create AppleScript
    script = 'display dialog' + text + title + icon + buttons + default + answer + hidden + timeout
    # Create command
    command = ['osascript', '-e', script]
    # Execute command
    return_result = {}
    try:
        result = subprocess.check_output(command)
        find_result = re.search(r'button returned:(\w+)(?:, text returned:(.+))?', result)
        return_result['button'] = find_result.group(1)
        return_result['text'] = find_result.group(2)
    except subprocess.CalledProcessError as error:
        # User cancelled
        logging.info('User cancelled: %s', error)
    except:
        logging.critical('Unexpected error: %s', sys.exc_info()[0])
        sys.exit(1)
    return return_result


def authorize_password(username, password, domain='.'):
    logging.info('Authorizing: %s at: %s', username, domain)
    command = ['dscl', domain, '-authonly', username, password]
    try:
        result = subprocess.check_output(command)
        logging.debug('Result: %s', result)
    except subprocess.CalledProcessError as error:
        logging.debug('Authorization error: %s', error)
        return False
    except:
        logging.critical('Unexpected error: %s', sys.exc_info()[0])
        sys.exit(1)
    return True


def logout():
    logging.info('Logging out')
    command = ['osascript', '-e', 'tell application "loginwindow" to «event aevtrlgo»']
    try:
        result = subprocess.check_output(command)
        logging.debug('Result: %s', result)
    except subprocess.CalledProcessError as error:
        logging.debug('Logout error: %s', error)
        return False
    except:
        logging.critical('Unexpected error: %s', sys.exc_info()[0])
        sys.exit(1)
    return True


def launch_launchdaemon():
    logging.info('Launching launchdaemon')

    # Copy script for LaunchDaemon
    execute_command(['cp', '-a', sys.argv[0], kProgramPath])
    # Save LaunchDaemon
    write_file = open(kLaunchDaemonPath, 'w')
    write_file.write(kLaunchDaemon)
    write_file.close()
    # Launch LaunchDaemon
    execute_command(['launchctl', 'load', kLaunchDaemonPath])


def remove_launchdaemon():
    logging.info('Remove launchdaemon')

    # Load loginwindow to allow user to log in
    execute_command(['launchctl', 'load', '/System/Library/LaunchDaemons/com.apple.loginwindow.plist'])
    # Unload LaunchDaemon
    execute_command(['launchctl', 'unload', kLaunchDaemonPath])
    # Remove LaunchDaemon
    # execute_command(['launchctl', 'remove', kLaunchDaemonName])
    os.remove(kLaunchDaemonPath)


def get_serialnumber():
    logging.info('Get system serial number')
    command = ['system_profiler', 'SPHardwareDataType']
    result = execute_command(command)
    search_result = re.findall('\s*Serial Number \(system\): (.+)', result)
    if not search_result:
        logging.error('Mobile users not found')
        sys.exit(1)
    return search_result[0]


def get_network_services():
    logging.info('Get network services')
    command = ['networksetup', 'listallnetworkservices']
    result = execute_command(command)
    search_result = re.findall('.*Ethernet.*|.*Wi.*Fi.*', result)
    if not search_result:
        logging.error('Mobile users not found')
        sys.exit(1)
    return search_result


def set_dns_servers(network_service, dns_servers):
    logging.info('Set DNS servers for %s: %s', network_service, dns_servers)
    command = ['networksetup', 'setdnsservers', network_service] + dns_servers
    execute_command(command)


def ds_get_nodes():
    # Check Directory Services search order
    logging.info('Get source and target directories')
    command = ['dscl', '-plist', '/Search', '-read', '/']
    result_dscl = execute_command(command)
    # Find CSPSearchPaths
    search_path = re.search(
        r'\s*<key>dsAttrTypeStandard:CSPSearchPath</key>\n\s*<array>\n(?:\s*<string>.+</string>\n)+\s*</array>\n',
        result_dscl)
    if not search_path:
        logging.error('Search Path not found')
        sys.exit(1)
    # Find array of nodes
    node_list = re.findall(r'\s*<string>(.+)</string>\n', search_path.group(0))
    result = {}
    for node_path in node_list:
        if node_path.startswith('/Local/'):
            node_type = 'Local'
            node_domain = re.search('/Local/(.+)', node_path).group(1)
            node_meta = None
        elif node_path.startswith('/LDAPv3/'):
            node_type = 'LDAP'
            node_domain = re.search('/LDAPv3/(.+)', node_path).group(1)
            node_meta = None
        elif node_path.startswith('/Active Directory/'):
            node_type = 'AD'
            # Active Directory domain
            node_domain = re.search('/Active Directory/(.+)/All Domains', node_path).group(1)
            # Active Directory meta node location
            command = ['dscl', node_path, '-read', '/OrganizationalUnit/Domain Controllers',
                       'dsAttrTypeStandard:AppleMetaNodeLocation']
            result_dscl = execute_command(command)
            search_meta = re.search(r'AppleMetaNodeLocation:\n\s*(.*)', result_dscl)
            node_meta = search_meta.group(1)
        else:
            logging.critical('Unknown source node type: %s', node_path)
            sys.exit(1)
        # result[node_type] = (node_type, node_domain, node_path, node_meta)
        result[node_type] = {}
        result[node_type]['type'] = node_type
        result[node_type]['domain'] = node_domain
        result[node_type]['path'] = node_path
        result[node_type]['meta'] = node_meta
    return result


def ds_read_node(node, read_path, read_key):
    # Get Directory Services users returning dictionary with username,theKey,and GeneratedUID
    # GeneratedUID isn't being used as ACLs can only be assigned by name
    logging.info('Reading directory %s at path %s for key %s', node, read_path, read_key)
    node_path = node['path']
    command = ['dscl', '-plist', node_path, '-read', read_path, read_key, 'RecordName', 'GeneratedUID']
    result = execute_command(command)
    if read_key == 'UniqueID':
        # Create dictionary of GeneratedUID and UniqueID by RecordName
        search_results = re.search(
            r'\s*<key>dsAttrTypeStandard:GeneratedUID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:RecordName</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:UniqueID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n',
            result)
    elif read_key == 'PrimaryGroupID':
        # Find RecordName and UniqueID
        search_results = re.search(
            r'\s*<key>dsAttrTypeStandard:GeneratedUID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:PrimaryGroupID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:RecordName</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n',
            result)
    else:
        logging.error('Unknown key: %s', read_key)
        sys.exit(1)
    if not search_results:
        logging.error('Record not found')
        sys.exit(1)
    return search_results.group(3), search_results.group(1)


def ds_add_node(node_type, node_domain, computer, username, password):
    # Add a Directory Service node
    logging.info('Add Directory Service: %s', [node_type, node_domain, computer, username, password])

    if node_type == 'LDAP':
        # Add Active Directory command
        auth = []
        # Authentication for target AD domain
        if username is not None and password is not None:
            auth = ['-u', username, '-p', password]
        # Options
        if computer is not None:
            computer = ['-c' + computer]
        else:
            computer = []
        options = ['-N', '-a', node_domain] + auth + computer
        command = ['dsconfigldap'] + options
    elif node_type == 'AD':
        # Add Active Directory command
        if username is None:
            logging.critical('Administrator username is required for AD')
            sys.exit(1)
        auth = []
        # Authentication for target AD domain
        if password is not None:
            auth = ['-password', password]
        # Options
        if computer is not None:
            computer = ['-computer' + computer]
        else:
            computer = []
        options = ['-add', node_domain, '-username', username] + auth + computer
        # Advanced Options - User Experience:
        mobile = ['-mobile', 'enable']
        mobileconfirm = ['-mobileconfirm', 'disable']
        localhome = ['-localhome', 'enable']
        useuncpath = ['-useuncpath', 'disable']
        sharepoint = ['-sharepoint', 'disable']
        shell = ['-shell', '/bin/bash']
        advanced_options = mobile + mobileconfirm + localhome + useuncpath + sharepoint + shell
        command = ['dsconfigad'] + options + advanced_options
    else:
        logging.critical('Unknown directory type: %s', node_type)
        sys.exit(1)
    execute_command(command)


def ds_remove_node(node_type, node_domain, username, password):
    # Remove a Directory Service node
    logging.info('Removing Directory Service: %s', node_domain)
    if node_type == 'LDAP':
        # Remove LDAP command
        # Optional authentication (username and assword)
        auth = []
        if username is not None and password is not None:
            auth = ['-u', username, '-p', password]
        # Options
        options = ['-N', '-r', node_domain] + auth
        command = ['dsconfigldap'] + options
        # Usage: dsconfigldap [-fviSN] -r servername [-u username] [-p password]
        #                     [-l localusername] [-q localuserpassword]
    elif node_type == 'AD':
        # Remove AD command
        if username is None:
            logging.critical('Administrator username is required for AD')
            sys.exit(1)
        # Optional authentication (password)
        auth = []
        if password is not None:
            auth = ['-password', password]
        # Options
        options = ['-remove', '-username', username] + auth
        command = ['dsconfigad'] + options
        # Usage: dsconfigad -remove -username value [-force] [-password value]
        #                   [-localuser value] [-localpassword value]
    else:
        logging.critical('Unknown directory type: %s', node_type)
        sys.exit(1)
    execute_command(command)


def get_mobile_users(node):
    # Get mobile users from source node
    logging.info('Get mobile users: %s', node)
    if node['type'] == "LDAP":
        command = ['dscl', '-plist', '.', 'search', '/Users', 'OriginalNodeName', node['path']]
    elif node['type'] == "AD":
        command = ['dscl', '-plist', '.', 'search', '/Users', 'OriginalNodeName', node['meta']]
    else:
        logging.critical('Bad node type to get mobile users: %s', node['type'])
        sys.exit(1)
    result = execute_command(command)
    # Find CSPSearchPaths
    user_list = re.findall('(.+?)\s*OriginalNodeName.*', result)
    if not user_list:
        logging.error('Mobile user not found')
        sys.exit(1)
    return user_list


def migrate_homes(node, user_list):
    # Change ownership on user homes
    logging.info('Migrating user homes to: %s', node)
    for next_user in user_list:
        logging.info('Migrating user: %s', next_user)
        user_path = '/Users/' + next_user
        user_uid = ds_read_node(node, user_path, 'UniqueID')
        if user_uid:
            if os.path.exists(user_path):
                command = ['chown', '-R', user_uid[0], user_path]
                execute_command(command)
            else:
                print 'Path:', user_path, 'not found for user:', next_user
                logging.error('Path: %s not found for user: %s', user_path, next_user)
        else:
            print 'User:', next_user, 'not found in directory:', node
            logging.error('User: %s not found in directory: %s', next_user, node)


def remove_groups(user_list):
    # Remove local groups for mobile users
    logging.info('Removing local groups for mobile users')
    groups = {}
    for next_user in user_list:
        # Find local groups for each user
        command = ['dscl', '.', '-search', '/Groups', 'GroupMembership', next_user]
        result = execute_command(command)
        groups[next_user] = re.findall(r'(.+?)\s*GroupMembership = \(', result)
        # Remove local groups for each user
        if len(groups[next_user]):
            for next_group in groups[next_user]:
                command = ['dseditgroup', '-o', 'edit', '-d', next_user, '-t', 'user', next_group]
                execute_command(command)
    execute_command(['dscacheutil', '-flushcache'])
    return groups


def add_groups(groups):
    # Add local groups for each mobile user
    logging.info('Adding local groups for mobile users')
    for next_user, user_groups in groups.items():
        for next_group in user_groups:
            command = ['dseditgroup', '-o', 'edit', '-a', next_user, '-t', 'user', next_group]
            execute_command(command)
    execute_command(['dscacheutil', '-flushcache'])


def remove_users(user_list):
    # Remove mobile users
    logging.info('Removing mobile users')
    for next_user in user_list:
        if len(next_user):
            # Make sure nextUser isn't empty so we don't accidentally try to delete '/Users'
            command = ['dscl', '.', '-delete', '/Users/' + next_user]
            execute_command(command)
    execute_command(['dscacheutil', '-flushcache'])
    execute_command(['fdesetup', 'sync'])


def add_users(user_list):
    # Remove mobile users
    logging.info('Adding mobile users')
    for next_user in user_list:
        # Find local groups for each user
        command = ['/System/Library/CoreServices/ManagedClient.app/Contents/Resources/createmobileaccount', '-n',
                   next_user]
        execute_command(command)
    execute_command(['dscacheutil', '-flushcache'])


def set_password(username, password, node, domain_username, domain_password):
    # Change password for user
    logging.info('Set password for %s in node %s', username, node)

    # Find local groups for each user
    command = ['dscl', '-u', domain_username, '-P', domain_password, node['path'], '-passwd', "/Users/" + username,
               password]
    execute_command(command)
    execute_command(['dscacheutil', '-flushcache'])


def migration_start(args):
    logging.info('Migrating client')

    # Get current Directory Services node
    nodes = ds_get_nodes()
    if len(nodes) < 2:
        logging.error('Mobile user not found')
        sys.exit(1)
    elif len(nodes) > 2:
        if args.ad and 'AD' in nodes:
            print 'Error: An Active Directory service already exists:', nodes['AD']
        elif args.ldap and 'LDAP' in nodes:
            print 'Error: An LDAP service already exists:', nodes['LDAP']
        sys.exit(1)
    elif (args.ad and 'AD' in nodes) or (args.ldap and 'LDAP' in nodes):
        print 'Error: Migrating to same directory type'
        sys.exit(1)
    elif (args.ad and 'LDAP' not in nodes) or (args.ldap and 'AD' not in nodes):
        print 'Error: Bad directory type to migrate'
        sys.exit(1)
    elif args.ad:
        source_node = nodes['LDAP']
        target_type = 'AD'
    elif args.ldap:
        source_node = nodes['AD']
        target_type = 'LDAP'
    else:
        print 'Error: Unknown error condition', nodes
        sys.exit(1)
    if gVerbose:
        print 'Source node:', source_node

    # Get mobile users
    user_list = get_mobile_users(source_node)
    if gVerbose:
        print 'Users:', user_list

    # Verify we are running from a local account (what if we are in non-local account but sudo'ed)
    logged_user = getpass.getuser()
    if gVerbose:
        print 'Logged in user:', logged_user
    if not gTestingMode and logged_user in user_list:
        print 'This script must run from a local user account.'

    # Set Ethernet and Wi-Fi DNS if provided
    if args.dns:
        for network_service in get_network_services():
            set_dns_servers(network_service, args.dns)

    # Add target (new) Directory Service node
    if args.serial:
        computer = get_serialnumber()
    else:
        computer = args.computer
    ds_add_node(target_type, args.target_domain, computer, args.target_username, args.target_password)

    # Read updated nodes
    nodes = ds_get_nodes()
    if len(nodes) < 3:
        logging.error('Failed to add new directory service')
        sys.exit(1)
    elif args.ad and 'AD' not in nodes:
        print 'Error: Active Directory service not found'
        sys.exit(1)
    elif args.ldap and 'LDAP' not in nodes:
        print 'Error: LDAP service not found'
        sys.exit(1)
    elif args.ad:
        target_node = nodes['AD']
    elif args.ldap:
        target_node = nodes['LDAP']
    else:
        print 'Bad condition getting target node'
        logging.error('Bad condition getting target node')
        sys.exit(1)
    if gVerbose:
        print 'Target node:', target_node

    # Migrate user homes (change ownership to target node)
    migrate_homes(target_node, user_list)
    # Remove local groups
    groups = remove_groups(user_list)
    # Remove local users
    remove_users(user_list)
    # Remove source node
    ds_remove_node(source_node['type'], source_node['domain'], args.source_username, args.source_password)
    # Create mobile users
    add_users(user_list)
    # Add groups to mobile users
    add_groups(groups)
    # Set password if available
    if hasattr(args,'user_username') and hasattr(args,'user_password') and args.user_username in user_list:
        logging.debug('Setting password for: %s', args.user_username)
        set_password(args.user_username, args.user_password, target_node, args.target_username, args.target_password)


def migration_interactive(args):
    # Get logged in user
    username = get_console_user()
    dialog_text = '''This assistant will migrate your user account to our new directory server.

Enter your password to continue.'''
    while True:
        logging.debug('Getting password for: %s', username)
        # AppleScript dialog asking for user's password
        dialog_result = display_dialog(dialog_text, title='Directory Migration Assistant', buttons=['Cancel', 'OK'],
                                       default=2, icon='caution', answer='', hidden=True)
        if not dialog_result:
            # User cancelled
            logging.info('Exiting. User cancelled.')
            sys.exit(1)
        elif dialog_result['button'] == 'OK' and dialog_result['text']:
            # User pressed OK button and typed a password
            # Verify password is correct
            authorized_user = authorize_password(username, dialog_result['text'])
            if authorized_user:
                # Password is correct
                logging.debug('User authorized.')
                password = dialog_result['text']
                break
                # Password is incorrect
        elif dialog_result['button'] == 'OK' and not dialog_result['text']:
            # User entered empty password
            logging.info('User entered empty password')
        else:
            # Error: Unknown button
            logging.critical('Unknown button: %s', dialog_result['button'])
            sys.exit(0)
        dialog_text = '''Your password was incorrect. Please try again'''

    # Add user's username and password in arguments
    setattr(args, 'user_username', username)
    setattr(args, 'user_password', password)
    # Set interactive flag to false in arguments
    setattr(args, 'interactive', False)
    # Set headless flag to true
    setattr(args, 'headless', True)
    # Save preferences file with updated arguments
    save_preferences(args, kIniFilePath)

    # Launch the launchdaemon
    launch_launchdaemon()

    # Try to log out user
    logout()


def migration_headless(args):
    # Headless migration is launched by the LaunchDaemon
    logging.info('Do migration headless')
    # Wait until user is logged out
    while True:
        username = get_console_user()
        if not username:
            break
        logging.debug('Waiting for user to log out: %s', username)
        time.sleep(5)

    # Unload loginwindow so users can't log in
    logging.debug('Unload loginwindow')
    execute_command(['launchctl', 'unload', '/System/Library/LaunchDaemons/com.apple.loginwindow.plist'])

    # Perform migration
    migration_start(args)

    # Unload loginwindow so users can't log in
    logging.debug('Load loginwindow')
    execute_command(['launchctl', 'load', '/System/Library/LaunchDaemons/com.apple.loginwindow.plist'])

    # Remove the launchdaemon
    remove_launchdaemon()


def main():
    # Parse arguments
    args = parse_arguments()

    if args.interactive:
        # Do interactive migration, asking for user password, logging out, and running headless migration as daemon.
        migration_interactive(args)
    elif args.headless:
        # Run migration headless, with user logged out and input from settings file.
        migration_headless(args)
    else:
        # Do the migration, must be run as a local administrator
        if not gTestingMode and os.getuid() != 0:
            print 'You must run this script with administrator privileges.'
            sys.exit(1)
        migration_start(args)
    # Remove script
    if args.delete:
        execute_command(['srm', sys.argv[0]])


# MAIN
if __name__ == '__main__':
    main()
    sys.exit(0)
