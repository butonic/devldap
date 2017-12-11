<?php
$ldap_host = "ldap://127.0.0.1:10389";
$ldap_user  = "cn=admin,dc=example,dc=org";
$ldap_pass = "admin";

//putenv('LDAPTLS_REQCERT=never');
ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 0);

$ds = ldap_connect($ldap_host)
         or exit(">>Could not connect to LDAP server<<");
ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
// $person is all or part of a person's name, eg "Jo"

// ldap_start_tls($ds) ; // TODO currently kills devldap

$dn = "dc=example,dc=org";
$filter="(cn=zombie*)";
$justthese = array("ou", "sn", "givenname", "mail");

$pageSize = 1;

$cookie = '';
do {
	ldap_control_paged_result($ds, $pageSize, true, $cookie);

	$result  = ldap_search($ds, $dn, $filter, $justthese);
	$entries = ldap_get_entries($ds, $result);
	 
	foreach ($entries as $e) {
	 echo $e['dn'] . PHP_EOL;
	}

	ldap_control_paged_result_response($ds, $result, $cookie);

} while($cookie !== null && $cookie != '');