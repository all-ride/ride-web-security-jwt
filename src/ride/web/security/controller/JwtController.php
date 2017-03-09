<?php

namespace ride\web\security\controller;

use ride\library\security\exception\SecurityException;
use ride\library\security\SecurityManager;

use ride\web\mvc\controller\AbstractController;
use ride\web\security\authenticator\JwtAuthenticator;

/**
 * Controller to provide the Json Web Token
 */
class JwtController extends AbstractController {

    /**
     * Instance of the JWT authenticator
     * @var \ride\web\security\authenticator\JwtAuthenticator
     */
    private $authenticator;

    /**
     * Timestamp of the expiration time or an offset in seconds with the current
     * time prepending a +
     * @var integer|string
     */
    private $expirationTime;

    /**
     * Timestamp of the not before time or an offset in seconds with the current
     * time prepending a +
     * @var integer|string
     */
    private $notBeforeTime;

    /**
     * Sets the authenticator to generate the Json Web Token
     * @param \ride\web\security\authenticator\JwtAuthenticator $authenticator
     * @return null
     */
    public function setAuthenticator(JwtAuthenticator $authenticator, $expirationTime = null, $notBeforeTime = null) {
        $this->authenticator = $authenticator;
        $this->expirationTime = $expirationTime;
        $this->notBeforeTime = $notBeforeTime;
    }

    /**
     * Action to provide a Json Web Token
     * @return null
     */
    public function tokenAction(SecurityManager $securityManager) {
        if (!$this->authenticator) {
            throw new SecurityException('Could not generate the Json Web Token: no authenticator set, use setAuthenticator first');
        }

        $user = $securityManager->getUser();
        $token = $this->authenticator->generateToken($user, $this->expirationTime, $this->notBeforeTime);

        $this->setJsonView(array(
            'token' => $token,
        ));
    }

}
