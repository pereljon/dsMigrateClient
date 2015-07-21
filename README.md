# dsMigrateClient
Migrates a client(user) system from one directory service to another.

## Usage
usage: dsMigrateClient.py [-h] [--ad] [-c COMPUTER_NAME] [-d] [-f filename]
                          [--interactive] [--headless] [--ldap]
                          [--dns DNS_SERVER] [-p PASSWORD] [-P PASSWORD] [-s]
                          [-u USERNAME] [-U USERNAME] [-v]
                          [target_domain]

Migrate a mobile user from once Mac OS X Directory Service to another.

positional arguments:
  target_domain     AD domain or LDAP server

optional arguments:
  -h, --help        show this help message and exit
  --ad              migrating to Active Directory.
  -c COMPUTER_NAME  computer name which will be set in new directory.
  -d, --debug       log all debugging info to log file.
  -f filename       read setting from file.
  --interactive     run in interactive mode. Ask logged in user for password,
                    set up launchdaemon to run in headless mode, and logout.
  --headless        headless (daemon) mode. Wait to run until all users are
                    logged out.
  --ldap            migrating to LDAP (OpenDirectory).
  --dns DNS_SERVER  set up manual DNS entries.
  -p PASSWORD       password for target (new) domain administrator.
  -P PASSWORD       password for source (old) domain administrator.
  -s, --serial      use system serial number as computer name.
  -u USERNAME       administrator user for target (new) domain.
  -U USERNAME       administrator user for source (old) domain.
  -v, --verbose     verbose output.


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
3. Launch launchdameon which will run in headless mode once user has logged out.
4. Log out user.

## Headless mode
1. Wait until no users are logged in.
2. Unload loginwindow
3. Run migration (standard mode)
4. Load loginwindow
5. Remove launchdaemon