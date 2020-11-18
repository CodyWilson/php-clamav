<?php

namespace Appwrite\ClamAV;

use function socket_connect;
use function socket_create;

class Pipe extends ClamAV
{
    /**
     * @var string
     */
    private $pip;

    /**
     * Pipe constructor.
     *
     * This class can be used to connect to local socket.
     * You need to pass the path to the socket pipe.
     *
     * @param string $pip
     */
    public function __construct(string $pip = '/var/run/clamav/clamd.ctl')
    {
        $this->pip = $pip;
    }

    /**
     * @return resource
     */
    protected function getSocket()
    {
        $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
        socket_connect($socket, $this->pip);
        return $socket;
    }
}
