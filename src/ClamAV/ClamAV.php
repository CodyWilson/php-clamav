<?php

namespace Appwrite\ClamAV;

use function end;
use function explode;
use function socket_close;
use function socket_recv;
use function socket_send;
use function strlen;
use function trim;

abstract class ClamAV
{
    /**
     * @var int
     */
    public $CLAMAV_MAX = 20000;

    /**
     * @return resource
     */
    abstract protected function getSocket();

    /**
     * @param $command
     * @return null
     */
    private function sendCommand($command)
    {
        $return = null;

        $socket = $this->getSocket();

        socket_send($socket, $command, strlen($command), 0);
        socket_recv($socket, $return, $this->CLAMAV_MAX, 0);
        socket_close($socket);

        return $return;
    }

    /**
     * Ping ClamAV Socket
     *
     * Check if ClamAV is up and responsive
     *
     * @return bool
     */
    public function ping()
    {
        $return = $this->sendCommand('PING');
        return trim($return) === 'PONG';
    }

    /**
     * Check ClamAV Version
     *
     * @return string
     */
    public function version()
    {
        return trim($this->sendCommand('VERSION'));
    }

    /**
     * Reload ClamAV virus databases
     *
     * @return null
     */
    public function reload()
    {
        return $this->sendCommand('RELOAD');
    }

    /**
     * Shutdown ClamAV and preform a clean exit
     *
     * @return null
     */
    public function shutdown()
    {
        return $this->sendCommand('SHUTDOWN');
    }

    /**
     * Scan a file or a directory (recursively) with archive support
     *  enabled (if not disabled in clamd.conf). A full path is required.
     *
     * @param string $file
     * @return bool return true if file is OK or false if not
     */
    public function fileScan(string $file)
    {
        $out = $this->sendCommand('SCAN ' . $file);

        $out = explode(':', $out);
        $stats = end($out);

        $result = trim($stats);

        return ($result === 'OK');
    }

    /**
     * Scan file or directory (recursively) with archive support
     *  enabled and don't stop the scanning when a virus is found.
     *
     * @param string $file
     * @return array
     */
    public function continueScan(string $file)
    {
        $return = [];

        foreach (explode("\n", trim($this->sendCommand('CONTSCAN ' . $file))) as $results) {
            $result = explode(':', $results);
            $file = @$result[0];
            $stats = @$result[1];
            $return[] = ['file' => $file, 'stats' => trim($stats)];
        }

        return $return;
    }

    public function instreamScan(string $file)
    {
        $socket = $this->getSocket();
        $instream = "zINSTREAM\0";
        socket_send($socket, $instream, strlen($instream), 0);

        $h = fopen($file, 'r');
        if (!$h) {
            return false;
        }

        $total = 0;
        while (!feof($h)) {
            $data = fread($h, 2048);
            $total += strlen($data);
            socket_send($socket, pack('N',strlen($data)), 4, 0);
            socket_send($socket, $data, strlen($data), 0);
        }
        socket_send($socket, pack('N', 0), 4, 0);
        $result = null;
        socket_recv($socket, $result, 200, 0);
        socket_close($socket);

        $out = $result;

        $out = explode(':', $out);
        $stats = end($out);

        $result = trim($stats);

        return ($result === 'OK');
    }
}
