<?php

namespace Ntb\APIBasicAuthApp;

use Ntb\RestAPI\IRestValidator;
use Ntb\RestAPI\RestValidatorHelper;

/**
 * Class Ntb\APIBasicAuthApp\Validator
 * @author Andre Lohmann <lohmann.andre@gmail.com>
 */
class Validator implements \Ntb\RestAPI\IRestValidator {
    const TokenLength = 32;

    public static function validate($data) {
        $keyName = \Config::inst()->get('SessionValidator', 'email_name');;
        $secretName = \Config::inst()->get('SessionValidator', 'password_name');;
        $key = \Ntb\RestAPI\RestValidatorHelper::validate_string($data, $keyName, ['min' => self::TokenLength, 'max' => self::TokenLength]);
        $secret = \Ntb\RestAPI\RestValidatorHelper::validate_string($data, $secretName, ['min' => self::TokenLength, 'max' => self::TokenLength]);
        return [
            'AppKey' => $key,
            'AppSecret' => $secret
        ];
    }
}
