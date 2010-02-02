<?php
/**
 *  Copyright (c) 2010, AF83
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1° Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2° Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 *
 *  3° Neither the name of AF83 nor the names of its contributors may be used
 *  to endorse or promote products derived from this software without specific
 *  prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COMPANY AF83 AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Implement this interface for using a special signer
 */
interface SessionInCookie_Signer
{
    public function encrypt($data);

    public function decrypt($data);
}

/**
 * Default Signer
 * Use pear Crypt_Blowfish
 */
class SessionInCookie_DefaultSigner implements SessionInCookie_Signer
{
    protected $blowfish = null;

    public function __construct($secret)
    {
        $bf = new Crypt_Blowfish('cbc');
        $bf->setKey($secret);
        if (PEAR::isError($bf))
        {
            throw new Exception('init error');
        }
        $this->blowfish = $bf;
    }

    public function encrypt($data)
    {
        return base64_encode($this->blowfish->encrypt($data));
    }

    public function decrypt($data)
    {
        return $this->blowfish->decrypt(base64_decode($data));
    }
}
/**
 * Dummy Signer
 * make nothing
 */
class SessionInCookie_DummySigner implements SessionInCookie_Signer
{

    public function encrypt($data)
    {
        return urlencode($data);
    }

    public function decrypt($data)
    {
        return urldecode($data);
    }
}

/**
 * Custom session handler
 * Save session in signed cookie
 */
class SessionInCookie
{
    protected static $signer = null;

    /**
     * Set signer
     * @param SessionInCookie_Signer $signer
     */
    public static function setSigner(SessionInCookie_Signer $signer)
    {
        self::$signer = $signer;
    }

    /**
     * @return SessionInCookie_Signer
     */
    protected static function getSigner()
    {
        if (is_null(self::$signer))
        {
            self::setSigner(new SessionInCookie_DefaultSigner('secret'));
        }
        return self::$signer;
    }

    protected function decode($value)
    {
        return self::getSigner()->decrypt($value);
    }

    /**
     * Register custom session handler
     */
    public static function install()
    {
        session_set_save_handler(array('SessionInCookie', 'open'),
                                 array('SessionInCookie', 'close'),
                                 array('SessionInCookie', 'read'),
                                 array('SessionInCookie', 'write'),
                                 array('SessionInCookie', 'destroy'),
                                 array('SessionInCookie', 'gc'));
    }

    /**
     * Start session
     */
    public static function start()
    {
        session_start();
    }

    /**
     * Stop session
     * You need to call stop before send any content (except headers)
     */
    public static function stop()
    {
        session_write_close();
    }

    /**
     * Needed by session_set_save_handler
     * make nothing
     */
    public static function open($path, $session_name)
    {
        return true;
    }

    /**
     * Needed by session_set_save_handler
     * make nothing
     */
    public static function close()
    {
        return true;
    }

    /**
     * Needed by session_set_save_handler
     *
     */
    public static function read($id)
    {
        if (isset($_COOKIE[$id]))
        {
            return self::decode($_COOKIE[$id]);
        }
        return '';
    }

    /**
     * Unserialize session data
     * In casual usage you don't need to call unserialize()
     * Needed only with bad web agent like Flash
     * After unserialize data are accessible in $_SESSION
     * @param String $value content of session cookie
     * @return True
     */
    public static function unserialize($value)
    {
        return session_decode(self::decode($value));
    }

    /**
     * Needed by session_set_save_handler
     * Write session cookie
     */
    public static function write($id, $data)
    {
        if (!empty($data))
        {
            setcookie($id, self::getSigner()->encrypt($data), 0, "/");
        }
    }

    /**
     * Needed by session_set_save_handler
     * Destroy current session
     */
    public static function destroy($id)
    {
        setcookie($id, '', time() - 3600);
        unset($_COOKIE[$id]);
    }

    /**
     * Needed by session_set_save_handler
     * make nothing
     */
    public static function gc($max_lifetime)
    {
        return true;
    }
}

SessionInCookie::install();
