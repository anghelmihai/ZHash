Classes for dealing with password hashing and authenticating the users.
There are 2 classes : ZHash\_Password for hashing the password and ZHash\_Auth\_Adapter\_Db which extends Zend\_Auth\_Adapter\_Db and this one can be used only with Zend Framework

ZHash\_Password usage is pretty simple, for example:

    $obj = new ZHash_Password(array('algorithm' => 'sha512', 'iterations' => 20000, 'key' => 'mypass'));
    $hash = $obj->hashKey()->getHash();
The hashing is done using the crypt function from php : [crypt](http://www.php.net/manual/en/function.crypt.php "crypt") . For information on why you shouldn't store passwords in the database using just sha1 or md5 with a static salt(or without) please see here [How to manage a PHP application's users and passwords](http://www.openwall.com/articles/PHP-Users-Passwords) and this webinar [Strong Cryptography in PHP](http://www.zend.com/en/webinar/PHP/70170000000bWL2-strong-cryptographie-20110630.flv)

The usual Zend\_Auth\_Adapter\_Db can't be used with passwords that are generated like this so I created the ZHash\_Auth\_Adapter\_Db which can be used exactly like the parent class with the some small exceptions.If you set the credential treatment than don't use the ? character.The reason is that the user can't be retrieved in a single query, first it searches for the username and after that it checks the password.Also, you should set a dummy salt corresponding to the algorithm and number of iterations you use in your application.
