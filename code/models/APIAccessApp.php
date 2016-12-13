<?php

namespace Ntb\APIBasicAuthApp;

/**
 * The Ntb\APIBasicAuthApp\APIAccessApp class which prevents apps with their credentials, that should get access to the api
 * 
 * @package silverstripe-rest-api-basicauth-app
 * 
 * @property string $Title
 * @property string $AppKey
 * @property string $AppSecret
 * @property string $AppSecretEncryption
 * @property string $Salt
 * @property bool $Blocked
 * 
 * @author Andre Lohmann <lohmann.andre@gmail.com>
 * 
 */

class APIAccessApp extends \DataObject {
    
        private static $db = [
            'Title' => 'Varchar(255)',
            'AppKey' => 'Varchar(32)',
            'Blocked' => 'Boolean',
            'AppSecret' => 'Varchar(160)',
            'AppSecretEncryption' => "Varchar(50)",
            'Salt' => 'Varchar(50)'
        ];

        private static $defaults = [
            'Blocked' => false
        ];

	/**
	 * Check if the passed secret matches the stored one (if the app is not blocked).
	 *
	 * @param string $secret
	 * @return ValidationResult
	 */
	public function checkSecret($secret) {
		$result = $this->canLogIn();

		// Short-circuit the result upon failure, no further checks needed.
		if (!$result->valid()) {
			return $result;
		}

		// Check a secret is set on this app
		if(empty($this->AppSecret) && $this->exists()) {
			$result->error(_t('APIAccessApp.NoSecret','There is no secret set on this app.'));
			return $result;
		}

		$e = \PasswordEncryptor::create_for_algorithm($this->AppSecretEncryption);
		if(!$e->check($this->AppSecret, $secret, $this->Salt, $this)) {
			$result->error(_t (
				'APIAccessApp.ERRORWRONGCRED',
				'The provided details don\'t seem to be correct. Please try again.'
			));
		}

		return $result;
	}
    
        public function generateAppSecret(){

            $generator = new \RandomGenerator();
            $Salt = substr($generator->randomToken('sha1'), 0, 50);

            $secret = md5(time().$Salt);
            return $secret;
        }

        /**
         * Check if the app is not blocked
         *
         * @param  ValidationResult $result
         * @return ValidationResult
         */
        public function canLogIn() {
            $result = \ValidationResult::create();
            if ($this->Blocked) {
                $result->error('The application ist currently blocked!');
            }
            return $result;
        }


	/**
	 * Validate this App object.
	 */
	public function validate() {
		$valid = parent::validate();

		return $valid;
	}

	/**
	 * Change secret. This will cause rehashing according to
	 * the `SecretEncryption` property.
	 *
	 * @param String $secret Cleartext secret
	 */
	public function changeSecret($secret) {
		$this->AppSecret = $secret;
		$valid = $this->validate();

		return $valid;
	}

	/**
	 * Event handler called before writing to the database.
	 */
	public function onBeforeWrite() {
		if(!$this->AppSecret) $this->AppSecret = $this->generateAppSecret();

		// If an app with the same AppKey already exists with a different ID, don't allow merging.
		// Note: This does not a full replacement for safeguards in the controller layer (e.g. in a registration form),
		// but rather a last line of defense against data inconsistencies.
		if($this->AppKey) {

			// Note: Same logic as Member_Validator class
			$filter = array("AppKey" => $this->AppKey);
			if($this->ID) {
				$filter[] = array('"Ntb\APIBasicAuthApp\APIAccessApp"."ID" <> ?' => $this->ID);
			}
			$existingRecord = \DataObject::get_one('Ntb\APIBasicAuthApp\APIAccessApp', $filter);

			if($existingRecord) {
				throw new \ValidationException(\ValidationResult::create(false, _t(
					'APIAccessApp.ValidationAppKeyFailed',
					'Can\'t overwrite existing APIAccessApp #{id} with identical AppKey {value}',
					'Values in brackets show ID and AppKey value',
					array(
						'id' => $existingRecord->ID,
						'value' => $this->AppKey
					)
				)));
			}
		}

		// The test on $this->ID is used for when records are initially created.
		// Note that this only works with cleartext secrets, as we can't rehash
		// existing secrets.
		if((!$this->ID && $this->AppSecret) || $this->isChanged('AppSecret')) {
			// Secret was changed: encrypt the secret according the settings
			$encryption_details = \Security::encrypt_password(
				$this->AppSecret, // this is assumed to be cleartext
				$this->Salt,
				($this->AppSecretEncryption) ?
					$this->AppSecretEncryption : \Security::config()->password_encryption_algorithm,
				$this
			);

			// Overwrite the secret property with the hashed value
			$this->AppSecret = $encryption_details['password'];
			$this->Salt = $encryption_details['salt'];
			$this->AppSecretEncryption = $encryption_details['algorithm'];
		}

		parent::onBeforeWrite();
	}
}