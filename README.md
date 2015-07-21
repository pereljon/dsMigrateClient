# dsMigrateClient
Migrates a client(user) system from one directory service to another.

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
2. Save the username, password, and other arguements to ini file to run in headless mode.
3. Launch launchdameon which will run in headless mode once user has logged out.
4. Log out user.

## Headless mode
1. Wait until no users are logged in.
2. Unload loginwindow
3. Run migration (standard mode)
4. Load loginwindow
5. Remove launchdaemon