<?php
class auth_require_group_membership extends rcube_plugin {
    public $task = 'login';
    public $noajax = true;
    public $noframe = true;

    private $rc;
    private $ldap;
    private $ldap_config = array();
    private $ldap_connected = false;
    private $server_name;
    private $remote_addr;
    private $log_file;

    function init(){
        $this->rc = rcmail::get_instance();
        $this->load_config();
        $this->log_file = $this->rc->config->get('auth_require_group_membership_debug_log');
        $this->server_name = strtolower(getenv('HTTP_HOST'));
        $this->remote_addr = getenv('REMOTE_ADDR');
        $this->add_hook('authenticate', array($this, 'before_login'));
        $this->add_hook('login_failed', array($this, 'on_login_failed'));
    }

    function before_login($data){

        $this->write_log('------------ new request');

        if($this->server_name == '' || !in_array($this->server_name, $this->rc->config->get('auth_require_group_membership_server_names'))){
            return $this->check_complete($data, true, '', 'host not in [auth_require_group_membership_server_names]');
        };

        if(in_array($this->remote_addr, $this->rc->config->get('auth_require_group_membership_whitelist'))){
            return $this->check_complete($data, true, '', 'remote host in [auth_require_group_membership_whitelist]');
        };

        $this->write_log('authenticating on ' . $this->server_name . ' for [' . $data['user']. '] from ' . $this->remote_addr);

        $user = trim(strtolower($data['user']));

        $filter = $this->rc->config->get('auth_require_group_membership_username_regexp_filter');

        if(($filter != '') && (preg_replace($filter, '', $user ) !== $user)){
            $this->write_log('username does not match regex filter');
            return $this->check_complete($data, false, $this->rc->config->get('auth_require_group_membership_msg_on_deny'), 'username regex mismatch');
        };

        $this->write_log('trying LDAP connection');

        $global_ldap_config = $this->rc->config->get('ldap_public');

        if(!$global_ldap_config || !isset($global_ldap_config[$this->rc->config->get('auth_require_group_membership_public_ldap')])){
            $this->write_log('ERROR: LDAP not properly configured: check [auth_require_group_membership_public_ldap] param in plugin config');
            return $this->check_complete($data, false, $this->rc->config->get('auth_require_group_membership_msg_on_server_error'), 'RC LDAP misconfigured');
        };

        $this->ldap_config = $global_ldap_config[$this->rc->config->get('auth_require_group_membership_public_ldap')];

        $this->write_log('connect dn=' . $this->ldap_config['bind_dn']);

        $this->ldap = new Net_LDAP3(array(
            'hosts' => $this->ldap_config['hosts'],
            'port'  => isset($this->ldap_config['port']) ? $this->ldap_config['port'] : 389,
            'use_tls' => false,
            'ldap_version'  => 3,
            'service_bind_dn' => $this->ldap_config['bind_dn'],
            'service_bind_pw' => $this->ldap_config['bind_pass'],
            'root_dn'         => $this->ldap_config['base_dn'],
            'referrals' => 0
        ));

        $this->ldap->config_set('log_hook', array($this, 'debug_ldap'));

        $this->ldap_connected = $this->ldap->connect();

        $this->write_log('connected: ' . ($this->ldap_connected === true ? 'OK' : 'FAILED: ' . $this->ldap_connected));

        if($this->ldap_connected !== true){
            return $this->check_complete($data, false, $this->rc->config->get('auth_require_group_membership_msg_on_server_error'), 'LDAP connection failed');
        };

        $this->write_log('searching LDAP for ' . $user);

        if(!$this->ldap->bind($this->ldap_config['bind_dn'], $this->ldap_config['bind_pass'])){
            $this->write_log('bind LDAP failed');
            return $this->check_complete($data, false, $this->rc->config->get('auth_require_group_membership_msg_on_server_error'), 'LDAP bind failed');
        };

        $found = $this->ldap->search(
            $this->ldap_config['base_dn'],
            '(&(sAMAccountName=' . $user . ')(memberOf=' . $this->rc->config->get('auth_require_group_membership_required_dn') . ')(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            'sub',
            array('distinguishedName'),
            array(),
            true
        );

        $this->write_log('found ' . $found);

        if(is_numeric($found)){
            return $this->check_complete($data, $found===1, $this->rc->config->get('auth_require_group_membership_msg_on_deny'));
        } else {
            return $this->check_complete($data, false, $this->rc->config->get('auth_require_group_membership_msg_on_server_error'));
        }
    }

    function check_complete($data, $success=true, $human_reason='', $details = 'NOT_SET'){
        $data['abort'] = $success !== true;
        $data['error'] = $human_reason;
        if($this->ldap_connected === true) $this->ldap->close();
        $msg = '[roundcube] ' . ($success === true ? 'SUCCESS ' : 'FAILED ') . ' login to [' . $this->server_name . '] for [' . $data['user']. '] from ' . $this->remote_addr;
        $this->rc->write_log($this->rc->config->get('auth_require_group_membership_login_log'), $msg . ' => ' . $details);
        $this->write_log('------------ request complete');
        return $data;
    }


    function write_log($msg){
        $this->rc->write_log($this->log_file, $msg);
    }

    function debug_ldap($level, $msg){
        $msg = implode("\n", $msg);
        $this->write_log($msg);
    }

    function on_login_failed($host, $user, $fail_code){
        $this->rc->write_log($this->rc->config->get('auth_require_group_membership_login_log'), "FAILED LOGIN for $user at host $host, reason: $fail_code");
        return true;
    }
}
?>