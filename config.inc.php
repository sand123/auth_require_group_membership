<?php

// use this global config [ldap_public] id for account lookup in LDAP catalog - bind_dn, root, etc
// ID matches [public] in tutorial http://trac.roundcube.net/wiki/Howto_Config/Ldap#ConfiguringRoundcube
$config['auth_require_group_membership_public_ldap'] = 'local_users';

// check for this site names only, for any other - always allowed
$config['auth_require_group_membership_server_names'] = ['mail.mydomain.com'];

// skip these IP list - always allowed
$config['auth_require_group_membership_whitelist'] = ['8.8.8.8'];

// required group distinguishedName
$config['auth_require_group_membership_required_dn'] = 'CN=AllowPublicWebMail,CN=Users,DC=domain,DC=local';

// custom error message about required access.
$config['auth_require_group_membership_msg_on_deny'] = 'Access denied';

// custom error message on LDAP or any server error.
$config['auth_require_group_membership_msg_on_server_error'] = 'Server failure - check later';

// filename (in RC/log folder) or leave empty for logging failed accounts
$config['auth_require_group_membership_login_log'] = 'webmail_logins.log';

// filename (in RC/log folder) or leave empty for logging debug info
$config['auth_require_group_membership_debug_log'] = 'webmail_auth_debug.log';

// use this regex to prefilter username. Leave empty if not required
$config['auth_require_group_membership_username_regexp_filter'] = '/[^a-zA-Zа-яА-Я0-9.]/i';

?>
