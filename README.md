# dsMigrateClient
Migrate a user account to a Mac OS X Directory Service.

## Usage
usage: dsMigrateClient.py [-h] [--computer COMPUTER_NAME] [-d] [--delete]
                          [--dns DNS_SERVER] [-f filename] [-H] [-i]
                          [--iconpng PATH] [--iconico PATH] [-j] [--log PATH]
                          [-p PASSWORD] [-P PASSWORD] [-s]
                          [--search_binddn LDAP_DN]
                          [--search_bindpass PASSWORD] [--search_uri ATTR]
                          [--search_userattr ATTR] [--search_userdn LDAP_DN]
                          [-t {AD,LDAP}] [-u USERNAME] [-U USERNAME] [-v]
                          [target_domain]

Migrate a user account to a Mac OS X Directory Service.

positional arguments:
  target_domain         AD domain or LDAP server

optional arguments:
  -h, --help            show this help message and exit
  --computer COMPUTER_NAME
                        computer name which will be set in new directory.
  -d, --debug           log all debugging info to log file.
  --delete              delete script and settings file after running.
  --dns DNS_SERVER      set up manual DNS entries.
  -f filename, --file filename
                        read setting from file.
  -H, --headless        headless (daemon) mode. Wait to run until all users
                        are logged out.
  -i, --interactive     run in interactive mode. Ask logged in user for
                        password, set up launchdaemon to run in headless mode,
                        and logout.
  --iconpng PATH        path to PNG icon (used in JAMF dialogs).
  --iconico PATH        path to ICO icon (used in password dialog).
  -j, --jamf            display status using JAMF Helper.
  --log PATH            path to log directory (/var/log is default).
  -p PASSWORD           password for target (new) domain administrator.
  -P PASSWORD           password for source (old) domain administrator.
  -s, --serial          use system serial number as computer name.
  --search_binddn LDAP_DN
                        LDAP bind user DN on target domain (for searching for
                        target username).
  --search_bindpass PASSWORD
                        LDAP bind password on target domain.
  --search_uri ATTR     LDAP URI to search for target username.
  --search_userattr ATTR
                        LDAP attribute to search for target username.
  --search_userdn LDAP_DN
                        LDAP DN on target domain to search for target
                        username.
  -t {AD,LDAP}, --target_type {AD,LDAP}
                        target directory type.
  -u USERNAME           administrator user for target (new) domain.
  -U USERNAME           administrator user for source (old) domain.
  -v, --verbose         verbose output.

## Running with arguments in a settings file
/tmp/dsMigrateClient.py -f /tmp/example.ini

## Running from Casper Self Service
To run the migration, create a Casper package with the script, the ini file, and the icon files for the dialogs and upload it to the JSS. Then create a policy which installs the package and executes the script with the ini file as an argument ( /tmp/dsMigrateClient.py -f /tmp/exampleLocal.ini ) and allow it to be run from Self Service. Users can then initiate the migration from the Self Service application.


## Assumptions
1. Only one directory service connected at start (the source) or none (for local migration to directory)
2. Users to migrate are local or mobile users (not tested for network users)
3. Migration is AD to OD, OD to AD, local to AD or local to OD.
4. User documents are in /Users/ folder. Migration does not currently change permissions outside of each user's folder.

## Migration mode
1. Get current DS nodes.
2. Get mobile users.
3. Get FileVault users.
4. Set DNS (if specificed)
5. Add new DS node.
6. Remove and save local groups from mobile users.
7. Remove mobile users.
8. Remove old DS node.
9. Migrate mobile user home ownership.
10. Add mobile users with new DS node.
11. Add saved local groups to mobile users.
12. Set user password (from interactive mode) to new DS node.
13. Set FileVault key for mobile user
14. Perform JAMF recon & manager 

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
