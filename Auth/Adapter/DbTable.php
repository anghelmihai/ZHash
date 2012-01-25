<?php

class ZHash_Auth_Adapter_DbTable extends Zend_Auth_Adapter_DbTable
{
    /**
    * A dummy hash used in _authenticateValidateResultSet
    * It's important not to use the default value
    * but use one that matches the algorithm and iterations that you use
    * in your application
    *
    * @var string
    * @access protected
    */
    protected $dummySalt = '$6$rounds=30000$YXHvzmVVstW6zJ0o$VCix7vFOjbEltjD.rKnikit0Q6vnGt1yyG7CeuUD78KSjcwg9Ji2HWk0qlzwDtQx9NcNcXeT8BcjRuL./joXk/';

    /**
     * __construct() - Sets configuration options
     *
     * @param  Zend_Db_Adapter_Abstract $zendDb If null, default database adapter assumed
     * @param  string                   $tableName
     * @param  string                   $identityColumn
     * @param  string                   $credentialColumn
     * @param  string                   $credentialTreatment
     * @return void
     */
    public function __construct(Zend_Db_Adapter_Abstract $zendDb = null, $tableName = null, $identityColumn = null,
                                $credentialColumn = null, $credentialTreatment = null, $dummySalt = null)
    {
        if (null !== $dummySalt) {
            $this->setDummySalt($dummySalt);
        }

        parent::__construct($zendDb, $tableName, $identityColumn, $credentialColumn, $credentialTreatment);
    }

    /**
    * Set a dummy salt
    *
    * @access public
    * @return ZHash_Auth_Adapter_DbTable provides fluent interface
    */
    public function setDummySalt($dummySalt)
    {
        $this->dummySalt = $dummySalt;

        return $this;
    }

    /**
    * Return the dummy salt
    *
    * @return string
    * @access public
    */
    public function getDummySalt()
    {
        return $this->dummySalt;
    }

    /**
     * This method overwrites the method from the parent class
     * I couldn't find a better solution because I don't want the credential query
     * to contain anything about the password
     *
     * _authenticateCreateSelect() - This method creates a Zend_Db_Select object that
     * is completely configured to be queried against the database.
     *
     * @return Zend_Db_Select
     */
    protected function _authenticateCreateSelect()
    {
        // build credential expression
        if (!empty($this->_credentialTreatment)) {
            $credentialExpression = new Zend_Db_Expr(
                '(CASE WHEN ' . $this->_credentialTreatment
                . ' THEN 1 ELSE 0 END) AS '
                . $this->_zendDb->quoteIdentifier(
                    $this->_zendDb->foldCase('zend_auth_credential_match')
                    )
                );
        }
        else
        {
            $credentialExpression = new Zend_Db_Expr(
                "1 AS " . $this->_zendDb->quoteIdentifier( $this->_zendDb->foldCase('zend_auth_credential_match') )
            );
        }

        // get select
        $dbSelect = clone $this->getDbSelect();
        $dbSelect->from($this->_tableName, array('*', $credentialExpression))
                 ->where($this->_zendDb->quoteIdentifier($this->_identityColumn, true) . ' = ?', $this->_identity);

        return $dbSelect;
    }

    /**
     * This method extends the method from the parent class by
     * checking the password
     *
     * @param array $resultIdentity
     * @return Zend_Auth_Result
    */
    protected function _authenticateValidateResult($resultIdentity)
    {
        //the password that was entered by the user
        $providedPassword = $this->_credential;
        //the hash that is stored in the database
        $hash = $resultIdentity[$this->_credentialColumn];
        if(!ZHash_Password::checkKey($providedPassword, $hash)){
            $this->_authenticateResultInfo['code'] = Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID;
            $this->_authenticateResultInfo['messages'][] = 'Supplied credential is invalid.';
            return $this->_authenticateCreateAuthResult();
        }

        return parent::_authenticateValidateResult($resultIdentity);
    }

    /**
     * This method extends the one from the parent class
     * It adds a single thing:
     * if the identity isn't found than it performs a check on a dummy password
     * to decrease the probability of a succesfull timing attack;
     * after that it just calls the parent function
     *
     * @param array $resultIdentities
     * @return true|Zend_Auth_Result
     */
    protected function _authenticateValidateResultSet(array $resultIdentities)
    {

        if (count($resultIdentities) < 1) {
            ZHash_Password::checkKey($this->_credential, $this->dummySalt);
        } 

        return parent::_authenticateValidateResultSet($resultIdentities);
    }
}
