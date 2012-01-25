<?php

class ZHash_Password
{
    CONST A64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
    * The salt used in hashing the key
    *
    * @var string
    * @access protected
    */
    protected $salt;

    /**
    * The number of iterations the hash loop is executed
    *
    * @var int
    * @access protected
    */
    protected $iterations;

    /**
    * The algorithm used for hashing the key
    * must be one of the following: std_des, ext_des, blowfish, sha256, sha512, md5
    *
    * @var string
    * @access protected
    */
    protected $algorithm;

    /**
    * The bytes that form the salt
    * these should be random
    *
    * @var string
    * @access protected
    */
    protected $bytes;

    /**
    * The key that should be hashed
    *
    * @var string
    * @access protected
    */
    protected $key;

    /**
    * The resulting hash of the key
    *
    * @var string
    * @access protected
    */
    protected $hash;

    /**
    * Constructor
    *
    * @param array - can initialize the values for iterations, key, algorithm
    * @return void
    */
    public function __construct($params = array())
    {
        foreach( $params as $key => $value )
        {
            if ( in_array($key, array('iterations', 'key', 'algorithm')) )
            {
                $method = 'set' . ucfirst($key);
                call_user_func(array($this, $method), $value);
            }
        }
    }

    /**
    * Generate random bytes to be used for the salt
    * Now it only works with openssl, 
    * but the random bytes can also be set via the setBytes function,
    * for example if you get them from /dev/urandom
    *
    * @access public
    * @return string
    * @throws Exception - if the openssl_random_pseudo_bytes function failed to use a good algorithm for 
    *                    generating the bytes
    */
    public function generateRandomBytes()
    {
        $strong = false;

        $bytes = openssl_random_pseudo_bytes(30, $strong);

        if ( !$strong )
        {
            throw new Exception('openssl_random_pseudo_bytes failed to produce a good random value');
        }

        $this->setBytes($bytes); 

        return $this;
    }

    /**
    * Generate the salt from the available random bytes
    *
    * @return string
    * @access protected
    */
    protected function generateSaltFromBytes()
    {
        if ( !$this->bytes )
        {
            $this->generateRandomBytes(); 
        }
        
        $salt = base64_encode($this->bytes);
        $this->setSalt($salt);

        return $this;
    }

    /**
    * Return the salt
    *
    * @access public
    * @return string
    */
    public function getSalt()
    {
        if ( empty($this->salt) )
        {
            $this->generateSaltFromBytes(); 
        }
        
        return $this->salt;
    }

    /**
    * Compute the hash for the given key
    *
    * @param string optional $key
    * @return string
    * @access public
    */
    public function hashKey($key = null)
    {
        if ( is_null($key) )
        {
            $key = $this->getKey(); 
        }
        else
        {
            $this->setKey($key);
        }

        $salt = $this->getFullSalt();
        $hash = crypt($key, $salt);
        $this->hash = $hash;

        return $this;
    }

    /**
    * Set the algorithm to be used for hashing the key
    * This function will also check if the algorithm is supported;
    * this is done by checking a constant, for example CRYPT_MD5 if
    * the algorithm is md5; see the crypt manual page from php.net for more details about these constants
    *
    * @param string $algorithm
    * @return ZHash_Password provides fluent interface
    * @access public
    */
    public function setAlgorithm($algorithm)
    {
        $algorithmName = 'CRYPT_' . strtoupper($algorithm);
        if ( constant($algorithmName) != 1 )
        {
            throw new InvalidArgumentException("This algorith is not supported on this machine"); 
        }
        
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
    * Set the number of iterations the hash loop should execute
    *
    * @param int $iterations
    * @return ZHash_Password provides fluent interface
    * @access public
    */
    public function setIterations($iterations)
    {
        $this->iterations = $iterations;

        return $this;
    }

    /**
    * Set the random bytes which will make up the salt
    * if openssl is enabled it is better to let generateRandomBytes to set these
    *
    * @param string $bytes
    * @return ZHash_Password provides fluent interface
    * @access public
    */
    public function setBytes($bytes)
    {
        $this->bytes = $bytes;

        return $this;
    }

    /**
    * Set the salt used for generating the hash
    * it replaces any character outside of ./0-9A-Za-z with a dot
    * because some algorithms don't allow these characters
    *
    * @param string $salt
    * @return ZHash_Password provides fluent interface
    * @access public
    */
    public function setSalt($salt)
    {
        $pattern = '/[^.\/0-9A-Za-z]/';
        $salt = preg_replace($pattern, '.', $salt);
        $this->salt = $salt;

        return $this;
    }

    /**
    * Set the key that should be hashed
    *
    * @param string $key
    * @return ZHash_Password provides fluent interface
    * @access public
    */
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    /**
    * Get the computed hash
    *
    * @return string
    * @access public
    */
    public function getHash()
    {
        return $this->hash;
    }

    /**
    * Get the characters that define the algorithm in the crypt function
    *
    * @param string $algorithm - the used algorithm
    * @return string
    * @access public
    * @throws InvalidArgumentException - if the algorithm provided isn't supported
    */
    public static function getAlgorithmSignature($algorithm)
    {
        switch($algorithm)
        {
            case 'std_des':
                $signature = '';
                break;
            case 'ext_des':
                $signature = '_';
                break;
            case 'md5':
                $signature = '$1$';
                break;
            case 'blowfish':
                $signature = '$2a$';
                break;
            case 'sha256':
                $signature = '$5$';
                break;
            case 'sha512':
                $signature = '$6$';
                break;
            default:
                throw new InvalidArgumentException('Invalid algorithm, must be one of the following: std_des(standard DES), ext_des(extended DES), 
                    md5, blowfish, sha256, sha512');
        }

        return $signature;
    }

    /**
    * Get the string that specifies the number of iterations that should be applied
    *
    * @param string $algorithm - the algorithm used
    * @param int $count - the number of iterations
    * @return string
    * @throws InvalidArgumentException - if the algorithm provided isn't supported
    */
    public static function getRoundsSignature($algorithm, $count)
    {
        switch($algorithm)
        {
            case 'std_des':
                $signature = '';
                break;
            case 'ext_des':
                $signature = self::getIterationsDesFormat($count);
                break;
            case 'md5':
                $signature = '';
                break;
            case 'blowfish':
                $signature = sprintf('%02d$', $count);
                break;
            case 'sha256':
                $signature = 'rounds=' . $count . '$';
                break;
            case 'sha512':
                $signature = 'rounds=' . $count . '$';
                break;
            default:
                throw new InvalidArgumentException('Invalid algorithm, must be one of the following: std_des(standard DES), ext_des(extended DES), 
                    md5, blowfish, sha256, sha512');
        }

        return $signature;
    }

    /**
    * Generate the full salt that is used in the crypt function
    *
    * @return string
    * @access public
    */
    public function getFullSalt()
    {
        $salt = self::getAlgorithmSignature($this->algorithm); 
        $salt = $salt . self::getRoundsSignature($this->algorithm, $this->iterations);
        $salt = $salt . $this->getSalt();

        if ( in_array($this->algorithm, array('md5', 'blowfish', 'sha256', 'sha512')) )
        {
            $salt = $salt . '$'; 
        }
        
        return $salt;
    }

    /**
    * Get the iterations in the format needed for extended des
    *
    * @param int $iterations
    * @return string
    * @access public
    */
    public static function getIterationsDesFormat($iterations)
    {
        if ( $iterations % 2 == 0 )
        {
            $iterations--;
        }

        $alphabet = self::A64;

        $tmp = $alphabet[$iterations & 63];
        $tmp .= $alphabet[($iterations >> 6) & 63];
        $tmp .= $alphabet[($iterations >> 12) & 63];
        $tmp .= $alphabet[($iterations >> 18) & 63];

        return $tmp;
    }

    /**
    * Check if a key corresponds to a given hash
    *
    * @param string $key
    * @param string $hash
    * @return boolean
    * @access public
    */
    public function checkKey($key, $hash)
    {
        return $hash == crypt($key, $hash);
    }
}
