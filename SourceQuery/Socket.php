<?php
/**
 * @author  Pavel Djundik <sourcequery@xpaw.me>
 *
 * @link    https://xpaw.me
 * @link    https://github.com/xPaw/PHP-Source-Query
 *
 * @license GNU Lesser General Public License, version 2.1
 *
 * @internal
 */

namespace xPaw\SourceQuery;

use xPaw\SourceQuery\Exception\SocketException;

/**
 * Class Socket.
 *
 *
 * @uses \xPaw\SourceQuery\Exception\SocketException
 */
class Socket extends BaseSocket
{
    public function Close()
    {
        if ($this->Socket) {
            \fclose($this->Socket);

            $this->Socket = null;
        }
    }

    /**
     * @param $Address
     * @param $Port
     * @param $Timeout
     * @param $Engine
     *
     * @throws \xPaw\SourceQuery\Exception\SocketException
     */
    public function Open($Address, $Port, $Timeout, $Engine)
    {
        $this->Timeout = $Timeout;
        $this->Engine = $Engine;
        $this->Port = $Port;
        $this->Address = $Address;

        $this->Socket = @\fsockopen('udp://'.$Address, $Port, $ErrNo, $ErrStr, $Timeout);

        if ($ErrNo || $this->Socket === false) {
            throw new SocketException('Could not create socket: '.$ErrStr, SocketException::COULD_NOT_CREATE_SOCKET);
        }

        \stream_set_timeout($this->Socket, $Timeout);
        \stream_set_blocking($this->Socket, true);
    }

    /**
     * @param        $Header
     * @param string $String
     *
     * @return bool
     */
    public function Write($Header, $String = '')
    {
        $Command = \pack('ccccca*', 0xFF, 0xFF, 0xFF, 0xFF, $Header, $String);
        $Length = \strlen($Command);

        return $Length === \fwrite($this->Socket, $Command, $Length);
    }

    /**
     * Reads from socket and returns Buffer.
     *
     * @param int $Length
     *
     * @throws \xPaw\SourceQuery\Exception\InvalidPacketException
     *
     * @return Buffer Buffer
     */
    public function Read($Length = 1400)
    {
        $Buffer = new Buffer();
        $Buffer->Set(\fread($this->Socket, $Length));

        $this->ReadInternal($Buffer, $Length, [$this, 'Sherlock']);

        return $Buffer;
    }

    /**
     * @param \xPaw\SourceQuery\Buffer $Buffer
     * @param int                      $Length
     *
     * @throws \xPaw\SourceQuery\Exception\InvalidPacketException
     *
     * @return bool
     */
    public function Sherlock(Buffer $Buffer, $Length)
    {
        $Data = \fread($this->Socket, $Length);

        if (\strlen($Data) < 4) {
            return false;
        }

        $Buffer->Set($Data);

        return $Buffer->GetLong() === -2;
    }
}
