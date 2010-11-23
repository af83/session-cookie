# In-Cookie Session

Store session in encrypted cookie.

## Basic Usage

        // just include session class
        require_once 'session.php';
        require_once 'Crypt/Blowfish.php'; // pear package, only needed when using SessionInCookie_DefaultCipher

        SessionInCookie::setCipher(new SessionInCookie_DefaultCipher('mysecretkey'));

        // start session normally
        start_session();

        // Read and write in session
        $_SESSION['foo'] = 'bar';

        // juste before output, call session_write_close
        session_write_close();

        // WARNING: now session data have been send to the client via encrypted cookie. You *CANNOT* write on $_SESSION.

        echo 'Hello Word';

## Advanced Usage

### Custom cipher


        class MyCipher implements SessionInCookie_Cipher
        {
            public function encrypt($data)
            {
                return $data;
            }

            public function decrypt($data)
            {
                return $data;
            }
        }

SessionInCookie::setCipher(new MyCipher());

### Custom cookies params

You can set cookies params like [session_set_cookie_params()](http://php.net/session_set_cookie_params).

SessionInCookie::setCookieParams($lifetime, $path, $domain, $secure = false, $httponly = false);

### Debug

You can use SessionInCookie_DummyCipher. 

SessionInCookie::setCipher(new SessionInCookie_DummyCipher());

## Copyright

Copyright (c) 2010 AF83

## LICENSE

MIT

# Authors

François de Metz <fdemetz@af83.com>
