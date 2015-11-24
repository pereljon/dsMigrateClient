# dsMigrateClient
Migrates a client(user) system from one directory service to another.

## Usage
--- | ---
usage: dsMigrateClient.py | [-h] [--ad] [--computer COMPUTER_NAME] [-d]
                          | [--delete] [--dns DNS_SERVER] [-f filename] [-H]
                          | [-i] [--iconpng PATH] [--iconico PATH] [-j] [--ldap]
                          | [-p PASSWORD] [-P PASSWORD] [-s] [-u USERNAME]
                          | [-U USERNAME] [--local_username USERNAME]
                          | [--local_password PASSWORD] [-v]
                          | [target_domain]

Migrate a mobile user from once Mac OS X Directory Service to another.

--- | ---
positional arguments:  | 
  target_domain        | AD domain or LDAP server

--- | ---
optional arguments: |
  -h, --help           | show this help message and exit
  --ad                 | migrating to Active Directory.
                       | computer name which will be set in new directory.
  -d, --debug          | log all debugging info to log file.
  --delete             | delete script and settings file after running.
  --dns DNS_SERVER     | set up manual DNS entries.
  -f filename, --file filename | read setting from file.
  -H, --headless       | headless (daemon) mode. Wait to run until all users
                       | are logged out.
  -i, --interactive    | run in interactive mode. Ask logged in user for password, set up launchdaemon to run in headless mode, and logout.
  --iconpng PATH       | path to PNG icon (used in JAMF dialogs).
  --iconico PATH       | path to ICO icon (used in password dialog).
  -j, --jamf           | display status using JAMF Helper.
  --ldap               | migrating to LDAP (OpenDirectory).
  -p PASSWORD          | password for target (new) domain administrator.
  -P PASSWORD          | password for source (old) domain administrator.
  -s, --serial         | use system serial number as computer name.
  -u USERNAME          | administrator user for target (new) domain.
  -U USERNAME          | administrator user for source (old) domain.
  --local_username USERNAME | local administrator user.
  --local_password PASSWORD | local administrator password.
  -v, --verbose        | verbose output.
  
## Assumptions
1. Only one directory service connected at start (the source)
2. Users to migrate are mobile users
3. Migration is AD to OD or OD to AD.

## Migration mode
1. Get current DS nodes.
2. Get mobile users.
3. Get FileVault users.
4. Set DNS (if specificed)
5. Remove and save local groups from mobile users.
6. Remove mobile users.
7. Add new DS node.
8. Remove old DS node.
9. Migrate mobile user home ownership.
10. Add mobile users with new DS node.
11. Add saved local groups to mobile users.
12. Set user password (from interactive mode) to new DS node.
13. Set FileVault key for mobile user
14. Perform JAMF recon & manage (optional)

## Interactive mode
1. Get the logged in username and ask for the user's password.
2. Save the username, password, and other arguments to ini file to run in headless mode.
3. Launch launchdameon which will run in headless mode.

## Headless mode
1. Log out user.
2. Unload loginwindow
3. Run migration (migration mode)
4. Load loginwindow
5. Remove launchdaemon