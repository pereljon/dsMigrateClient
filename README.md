# dsMigrateClient
Migrates a client(user) system from one directory service to another.

## Usage
usage: dsMigrateClient.py [-h] [--ad] [--computer COMPUTER_NAME] [-d]<br>
                          [--delete] [--dns DNS_SERVER] [-f filename] [-H]<br>
                          [-i] [-j] [--ldap] [-p PASSWORD] [-P PASSWORD] [-s]<br>
                          [-u USERNAME] [-U USERNAME] [-v]<br>
                          [target_domain]<br>

Migrate a mobile user from once Mac OS X Directory Service to another.

**positional arguments:**<br>
  target_domain         AD domain or LDAP server<br>

**optional arguments:**<br>
  -h, --help            show this help message and exit<br>
  --ad                  migrating to Active Directory.<br>
  --computer COMPUTER_NAME<br>
                        computer name which will be set in new directory.<br>
  -d, --debug           log all debugging info to log file.<br>
  --delete              delete script and settings file after running.<br>
  --dns DNS_SERVER      set up manual DNS entries.<br>
  -f filename, --file filename<br>
                        read setting from file.<br>
  -H, --headless        headless (daemon) mode. Wait to run until all users<br>
                        are logged out.<br>
  -i, --interactive     run in interactive mode. Ask logged in user for<br>
                        password, set up launchdaemon to run in headless mode,<br>
                        and logout.<br>
  -j, --jamf            display status using JAMF Helper.<br>
  --ldap                migrating to LDAP (OpenDirectory).<br>
  -p PASSWORD           password for target (new) domain administrator.<br>
  -P PASSWORD           password for source (old) domain administrator.<br>
  -s, --serial          use system serial number as computer name.<br>
  -u USERNAME           administrator user for target (new) domain.<br>
  -U USERNAME           administrator user for source (old) domain.<br>
  -v, --verbose         verbose output.<br>

## Assumptions
1. Only one directory service connected at start (the source)
2. Users to migrate are mobile users
3. Migration is AD to OD or OD to AD.

## Standard mode
1. Get current DS nodes.
2. Get mobile users.
3. Set DNS (if specificed)
4. Add new DS node.
5. Migrate mobile user home ownership.
6. Remove and save local groups from mobile users.
7. Remove mobile users.
8. Remove old DS node.
9. Add mobile users with new DS node.
10. Add saved local groups to mobile users.
11. Set user password (from interactive mode) to new DS node.

## Interactive mode
1. Get the logged in username and ask for the user's password.
2. Save the username, password, and other arguments to ini file to run in headless mode.
3. Launch launchdameon which will run in headless mode.

## Headless mode
1. Log out user.
2. Unload loginwindow
3. Run migration (standard mode)
4. Load loginwindow
5. Remove launchdaemon