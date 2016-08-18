<?php

/**
 * ownCloud - user_cas
 *
 * @author Sixto Martin <sixto.martin.garcia@gmail.com>
 * @copyright Sixto Martin Garcia. 2012
 * @copyright Leonis. 2014 <devteam@leonis.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#require_once(__DIR__ . '/lib/ldap_backend_adapter.php'); // Not required in 8.2, we now have an autoloader 
use OCA\user_cas\lib\LdapBackendAdapter;

class OC_USER_CAS extends OC_User_Backend {

	// cached settings
	public $autocreate;
	public $updateUserData;
	public $protectedGroups;
	public $defaultGroup;
	public $displayNameMapping;
	public $mailMapping;
	public $groupMapping;
	//public $initialized = false;
	protected static $instance = null;
	protected static $_initialized_php_cas = false;
	private $ldapBackendAdapter=false;
	private $cas_link_to_ldap_backend=false;

	public static function getInstance() {
		if (self::$instance == null) {
			self::$instance = new OC_USER_CAS();
		}
		return self::$instance;
	}

	public function __construct() {
		// copy system settings to app settings when app is initialized for the first time.  
		if( ! self::getAppValue('system_defaults_loaded', false)) {
			self::setAppValue('cas_autocreate', self::getSystemValue('cas_autocreate', true));
			self::setAppValue('cas_force_login', self::getSystemValue('cas_force_login', false));
			self::setAppValue('cas_link_to_ldap_backend', self::getSystemValue('cas_link_to_ldap_backend', false));
			self::setAppValue('cas_update_user_data', self::getSystemValue('cas_update_user_data', true));
			self::setAppValue('cas_default_group', self::getSystemValue('cas_default_group', ''));
			self::setAppValue('cas_protected_groups', self::getSystemValue('cas_protected_groups', ''));
			self::setAppValue('cas_email_mapping', self::getSystemValue('cas_email_mapping', ''));
			self::setAppValue('cas_displayName_mapping', self::getSystemValue('cas_displayName_mapping', ''));
			self::setAppValue('cas_group_mapping', self::getSystemValue('cas_group_mapping', ''));
			self::setAppValue('cas_server_version', self::getSystemValue('cas_server_version', '2.0'));
			self::setAppValue('cas_server_hostname', self::getSystemValue('cas_server_hostname', $_SERVER['SERVER_NAME']));
			self::setAppValue('cas_server_port', self::getSystemValue('cas_server_port', 443));
			self::setAppValue('cas_server_path', self::getSystemValue('cas_server_path', '/cas'));
			self::setAppValue('cas_debug_file', self::getSystemValue('cas_debug_file', ''));
			self::setAppValue('cas_cert_path', self::getSystemValue('cas_cert_path', ''));
			self::setAppValue('cas_php_cas_path', self::getSystemValue('cas_php_cas_path', 'CAS.php'));
			self::setAppValue('cas_service_url', self::getSystemValue('cas_service_url', ''));
			self::setAppValue('system_defaults_loaded', true);
		}
		$this->autocreate = self::getAppValue('cas_autocreate', true);
		$this->cas_link_to_ldap_backend = self::getAppValue('cas_link_to_ldap_backend', false);
		$this->updateUserData = self::getAppValue('cas_update_user_data', true);
		$this->defaultGroup = self::getAppValue('cas_default_group', '');
		$this->protectedGroups = explode (',', str_replace(' ', '', self::getAppValue('cas_protected_groups', '')));
		$this->mailMapping = self::getAppValue('cas_email_mapping', '');
		$this->displayNameMapping = self::getAppValue('cas_displayName_mapping', '');
		$this->groupMapping = self::getAppValue('cas_group_mapping', '');

		self :: initialized_php_cas();
	}

	public static function initialized_php_cas() {
		if(!self :: $_initialized_php_cas) {
			$casVersion = self::getAppValue('cas_server_version', '2.0');
			$casHostname = self::getAppValue('cas_server_hostname', $_SERVER['SERVER_NAME']);
			$casPort = self::getAppValue('cas_server_port', 443);
			$casPath = self::getAppValue('cas_server_path', '/cas');
			$casDebugFile=self::getAppValue('cas_debug_file', '');
			$casCertPath = self::getAppValue('cas_cert_path', '');
			$php_cas_path=self::getAppValue('cas_php_cas_path', 'CAS.php');
			$cas_service_url = self::getAppValue('cas_service_url', '');

			if (!class_exists('phpCAS')) {
				if (empty($php_cas_path)) $php_cas_path='CAS.php';
				\OCP\Util::writeLog('cas',"Try to load phpCAS library ($php_cas_path)", \OCP\Util::DEBUG);
				include_once($php_cas_path);
				if (!class_exists('phpCAS')) {
					\OCP\Util::writeLog('cas','Fail to load phpCAS library !', \OCP\Util::ERROR);
					return false;
				}
			}

			if ($casDebugFile !== '') {
				phpCAS::setDebug($casDebugFile);
			}
			
			phpCAS::client($casVersion,$casHostname,(int)$casPort,$casPath,false);
			
			if (!empty($cas_service_url)) {
				phpCAS::setFixedServiceURL($cas_service_url);
			}
						
			if(!empty($casCertPath)) {
				phpCAS::setCasServerCACert($casCertPath);
			}
			else {
				phpCAS::setNoCasServerValidation();
			}
			self :: $_initialized_php_cas = true;
		}
		return self :: $_initialized_php_cas;
	}

	private function initializeLdapBackendAdapter() {
		if (!$this->cas_link_to_ldap_backend) {
			return false;
		}
		if ($this -> ldapBackendAdapter === false) {
			$this -> ldapBackendAdapter = new LdapBackendAdapter();
		}
		return true;
	}

	public function checkPassword($uid, $password) {
		if (!self :: initialized_php_cas()) {
			return false;
		}

		if(!phpCAS::isAuthenticated()) {
			return false;
		}

		$uid = phpCAS::getUser();
		if ($uid === false) {
			\OCP\Util::writeLog('cas','phpCAS return no user !', \OCP\Util::ERROR);
			return false;
		}

		if ($this->initializeLdapBackendAdapter()) {
			\OCP\Util::writeLog('cas',"Search CAS user '$uid' in LDAP", \OCP\Util::DEBUG);
			//Retrieve user in LDAP directory
			$ocname = $this->ldapBackendAdapter->getUuid($uid);

			if (($uid !== false) && ($ocname !== false)) {
				\OCP\Util::writeLog('cas',"Found CAS user '$uid' in LDAP with name '$ocname'", \OCP\Util::DEBUG);
				return $ocname;
			}
		}
		return $uid;
	}

	
	public function getDisplayName($uid) {
		$udb = new OC_User_Database;
		return $udb->getDisplayName($uid);
	}

	/**
	* Sets the display name for by using the CAS attribute specified in the mapping
	*
	*/
	public function setDisplayName($uid,$displayName) {
		$udb = new OC_User_Database;
		$udb->setDisplayName($uid,$displayName);
	}

	protected static function getAppValue($id, $default) {
		return \OCP\Config::getAppValue('user_cas', $id, $default);
	}

	protected static function setAppValue($id, $value) {
		return \OCP\Config::setAppValue('user_cas', $id, $value);
	}

	protected static function getSystemValue($id, $default) {
		return \OCP\Config::getSystemValue($id, $default);
	}

}

