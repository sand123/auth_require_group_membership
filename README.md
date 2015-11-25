# auth_require_group_membership
RoundCube plugin for LDAP authentication with group membership requirement
Tested with 1.1.3 stable release

I have RC installation with 2 interfaces: intranet http for all users and public https for members of certain security group only, and IMAP server with LDAP authentication
This plugin allows you to grant access for all valid users from within local network and require user to be a member of security group to access webmail outside company

All parameters in config file is self-explanatory

Before using it, you have to configure LDAP http://trac.roundcube.net/wiki/Howto_Config/Ldap#ConfiguringRoundcube

This plugin also allows you 
* pre-filter username with regex to check if it includes only allowed chars
* log failed attempts with IP and timestamp to separate file
* check is user exists in AD before IMAP auth attempt
