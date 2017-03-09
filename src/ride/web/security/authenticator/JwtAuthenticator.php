<?php

namespace ride\web\security\authenticator;

use Firebase\JWT\JWT;

use ride\library\http\Header;
use ride\library\http\Request;
use ride\library\log\Log;
use ride\library\security\authenticator\AbstractAuthenticator;
use ride\library\security\exception\SecurityException;
use ride\library\security\model\User;

use \Exception;
use \InvalidArgumentException;

/**
 * Authenticator using Json Web Tokens
 *
 * @see https://tools.ietf.org/html/rfc7519
 */
class JwtAuthenticator extends AbstractAuthenticator {

    /**
     * Source for the log messages
     * @var string
     */
    const LOG_SOURCE = 'jwt';

    /**
     * Instance of the log
     * @var \ride\library\log\Log
     */
    private $log;

    /**
     * Name of the algorithm to be used
     * @var string
     */
    private $algorithm = 'HS256';

    /**
     * Secret key to encode and decode the token
     * @var string
     */
    private $secret;

    /**
     * Issuer of the token
     * @var string
     */
    private $issuer;

    /**
     * Subject of the token
     * @var string
     */
    private $subject;

    /**
     * Audience of the token
     * @var string
     */
    private $audience;

    /**
     * Sets the log
     * @param \ride\library\log\Log $log
     * @return null
     */
    public function setLog(Log $log) {
        $this->log = $log;
    }

    /**
     * Sets the used algorithm
     * @param string $algorithm Name of the algorithm
     * @return null
     */
    public function setAlgorithm($algorithm) {
        $this->algorithm;
    }

    /**
     * Gets the algorithm to be used
     * @return string Name of the algorithm, defaults to HS256
     */
    public function getAlgorithm() {
        return $this->algorithm;
    }

    /**
     * Sets the secret key to encode and decode the token
     * @param string $secret Secret key
     * @return null
     */
    public function setSecret($secret) {
        $this->secret = $secret;
    }

    /**
     * Gets the secret key to encode and decode the token
     * @return string
     */
    public function getSecret() {
        return $this->secret;
    }

    /**
     * Sets the issuer of the token
     * @param string $issuer
     * @return null
     */
    public function setIssuer($issuer) {
        $this->issuer = $issuer;
    }

    /**
     * Gets the issuer of the token
     * @return string
     */
    public function getIssuer() {
        return $this->issuer;
    }

    /**
     * Sets the subject of the token
     * @param string $subject
     * @return null
     */
    public function setSubject($subject) {
        $this->subject = $subject;
    }

    /**
     * Gets the subject of the token
     * @return string
     */
    public function getSubject() {
        return $this->subject;
    }

    /**
     * Sets the audience of the token
     * @param string $subject
     * @return null
     */
    public function setAudience($audience) {
        $this->audience = $audience;
    }

    /**
     * Gets the audience of the token
     * @return string
     */
    public function getAudience() {
        return $this->audience;
    }

    /**
     * Gets the current time
     * @return integer Timestamp of the current time
     */
    public function getTime() {
        return time();
    }

    /**
     * Generates a token for the provided user
     * @param \ride\library\security\model\User $user
     * @param integer $expirationTime Timestamp when the token is expired or an
     * offset in seconds with the current time by prepending a +
     * @param integer $notBeforeTime Before this timestamp the token is invalid,
     * can also be an offset in seconds with the current time by prepending a +
     * @return string JWT for the authorization header
     */
    public function generateToken(User $user, $expirationTime = null, $notBeforeTime = null) {
        $algorithm = $this->getAlgorithm();
        if (empty($algorithm)) {
            throw new SecurityException('Could not generate a Json Web Token: no algorithm set, use setAlgorithm first');
        }

        $time = $this->getTime();

        $claim = array(
            'iat' => $time,
            'username' => $user->getUserName(),
        );

        $issuer = $this->getIssuer();
        if ($issuer) {
            $claim['iss'] = $issuer;
        }

        $subject = $this->getSubject();
        if ($subject) {
            $claim['sub'] = $subject;
        }

        $audience = $this->getAudience();
        if ($audience) {
            $claim['aud'] = $audience;
        }

        if ($expirationTime) {
            $isRelative = false;
            if (substr($expirationTime, 0, 1) === '+') {
                $isRelative = true;
                $expirationTime = substr($expirationTime, 1);
            }

            if (!is_numeric($expirationTime)) {
                throw new InvalidArgumentException('Could not generate a Json Web Token: expiration time should be a UNIX timestamp or a relative time in seconds by prepending with +');
            } elseif (!$isRelative && $expirationTime < $time) {
                throw new InvalidArgumentException('Could not generate a Json Web Token: expiration time should be after the current time (' . $time . ' < ' . $expirationTime . ')');
            }

            if ($isRelative) {
                $claim['exp'] = $time + $expirationTime;
            } else {
                $claim['exp'] = (integer) $expirationTime;
            }
        }

        if ($notBeforeTime) {
            $isRelative = false;
            if (substr($notBeforeTime, 0, 1) === '+') {
                $isRelative = true;
                $notBeforeTime = substr($notBeforeTime, 1);
            }

            if (!is_numeric($notBeforeTime)) {
                throw new InvalidArgumentException('Could not generate a Json Web Token: not before time should be a UNIX timestamp or a relative time in seconds by prepending with +');
            }

            if ($isRelative) {
                $claim['nbf'] = $time + $notBeforeTime;
            } else {
                $claim['nbf'] = (integer) $notBeforeTime;
            }
        }

        return JWT::encode($claim, $this->getSecret(), $this->getAlgorithm());
    }

    /**
     * Authenticates a user through the incoming request
     * @param \ride\library\http\Request $request
     * @return \ride\library\security\model\User|null User if the authentication
     * succeeded
     */
    public function authenticate(Request $request) {
        $token = $this->getTokenFromRequest($request);
        if (!$token) {
            if ($this->log) {
                $this->log->logDebug('No Json Web Token in authorization header', null, self:: LOG_SOURCE);
            }

            return null;
        }

        try {
            $claim = (array) JWT::decode($token, $this->getSecret(), array($this->getAlgorithm()));
        } catch (Exception $exception) {
            if ($this->log) {
                $this->log->logDebug('Invalid Json Web Token in authorization header', $exception->getMessage(), self:: LOG_SOURCE);
            }

            return null;
        }

        if (isset($claim['iss']) && $claim['iss'] !== $this->getIssuer()) {
            if ($this->log) {
                $this->log->logDebug('Invalid Json Web Token in authorization header', 'Issuer does not match', self:: LOG_SOURCE);
            }

            return null;
        }

        if (isset($claim['sub']) && $claim['sub'] !== $this->getSubject()) {
            if ($this->log) {
                $this->log->logDebug('Invalid Json Web Token in authorization header', 'Subject does not match', self:: LOG_SOURCE);
            }

            return null;
        }

        if (isset($claim['aud']) && $claim['aud'] !== $this->getAudience()) {
            if ($this->log) {
                $this->log->logDebug('Invalid Json Web Token in authorization header', 'Audience does not match', self:: LOG_SOURCE);
            }

            return null;
        }

        $user = $this->securityManager->getSecurityModel()->getUserByUsername($claim['username']);
        if ($user && $user->isActive()) {
            $this->user = $this->setUser($user);

            if ($this->log) {
                $this->log->logDebug('Json Web Token is authenticated for user', $user->getUserName(), self:: LOG_SOURCE);
            }
        } else {
            $this->user = null;
        }

        return $this->user;
    }

    /**
     * Gets the token from the request
     * @param \ride\library\http\Request $request
     * @return string|boolean Authorization request
     */
    protected function getTokenFromRequest(Request $request) {
        $header = $request->getHeader(Header::HEADER_AUTHORIZATION);
        if (!$header && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if (isset($headers[Header::HEADER_AUTHORIZATION])) {
                $header = $headers[Header::HEADER_AUTHORIZATION];
            }
        }

        if (!$header) {
            if ($this->log) {
                $this->log->logDebug('No authorization header received', null, self:: LOG_SOURCE);
            }

            return false;
        } else {
            if ($this->log) {
                $this->log->logDebug('Json Web Token received in authorization header', $header, self:: LOG_SOURCE);
            }
        }


        if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
            return $matches[1];
        }

        return false;
    }

}
