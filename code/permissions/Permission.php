<?php


namespace Ntb\APIBasicAuthApp;

use Ntb\RestAPI\IPermissionChecks;

/**
 * Implements the IPermission interface and uses the Silverstripe permission system.
 * @author Andre Lohmann <lohmann.andre@gmail.com>
 */
class Permission implements \Ntb\RestAPI\IPermissionChecks {

    /**
     * @param \Ntb\APIBasicAuthApp\APIAccessApp $app
     * @return bool
     */
    public function isAdmin($app) {
        // An application should never get admin permissions
        return false;
    }
}