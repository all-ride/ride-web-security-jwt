<?php

namespace ride\web\security;

use \ride\library\event\Event;

/**
 * Application listener for the Json Web Tokens implementation
 */
class JwtApplicationListener {

    /**
     * Adds the Access-Control-Allow-Origin header to any response
     * @param \ride\library\event\Event $event
     * @return null
     */
    public function addAcaoHeader(Event $event) {
        $web = $event->getArgument('web');
        $response = $web->getResponse();
        $response->setHeader('Access-Control-Allow-Origin', '*');
    }

}
