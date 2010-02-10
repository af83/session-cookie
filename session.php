<?php
/**
 * Copyright (c) 2010 AF83
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * Implement this interface for using a special cipher
 */
interface SessionInCookie_Cipher
{
    public function encrypt($data);

    public function decrypt($data);
}

/**
 * Default Cipher
 * Use pear Crypt_Blowfish
 */
class SessionInCookie_DefaultCipher implements SessionInCookie_Cipher
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
 * Dummy cipher
 * make nothing
 */
class SessionInCookie_DummyCipher implements SessionInCookie_Cipher
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
 * Save session in encrypted cookie
 */
class SessionInCookie
{
    protected static $cipher = null;

    /**
     * Set cipher
     * @param SessionInCookie_Cipher $cipher
     */
    public static function setCipher(SessionInCookie_Cipher $cipher)
    {
        self::$cipher = $cipher;
    }

    /**
     * @return SessionInCookie_Cipher
     */
    protected static function getCipher()
    {
        if (is_null(self::$cipher))
        {
            self::setCipher(new SessionInCookie_DefaultCipher('secret'));
        }
        return self::$cipher;
    }

    protected function decode($value)
    {
        return self::getCipher()->decrypt($value);
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
            setcookie($id, self::getCipher()->encrypt($data), 0, "/");
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
