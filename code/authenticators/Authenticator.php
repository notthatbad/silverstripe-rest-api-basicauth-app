<?php

namespace Ntb\APIBasicAuthApp;

/**
 * Authenticator for the APIAccessApp
 *
 * @author Andre Lohmann <lohmann.andre@gmail.com>
 * @package silverstripe-rest-api-basicauth-app
 */
class Authenticator extends \Object {

	/**
	 * Attempt to find and authenticate app if possible from the given data
	 *
	 * @param array $data
	 * @param bool &$success Success flag
	 * @return APIAccessApp Found app, regardless of successful authentication
	 */
	protected static function authenticate_app($data, &$success) {
		// Default success to false
		$success = false;

		// Attempt to identify by temporary ID
		$app = null;

		$app = APIAccessApp::get()->filter("AppKey", $data['AppKey'])->first();

		// Validate against app if possible
		if($app) {
			$result = $app->checkSecret($data['AppSecret']);
			$success = $result->valid();
		} else {
			$result = new \ValidationResult(false, _t (
				'APIAccessApp.ERRORWRONGCRED',
				'The provided details don\'t seem to be correct. Please try again.'
			));
		}

		return $app;
	}

	/**
	 * Method to authenticate an app
	 *
	 * @param array $data Raw data to authenticate the app
         * 
	 * @return bool|APIAccessApp Returns FALSE if authentication fails, otherwise
	 *                     the app object
         * 
	 */
	public static function authenticate($data) {
		// Find authenticated app
		$app = static::authenticate_app($data, $success);

		return $success ? $app : null;
	}
}

