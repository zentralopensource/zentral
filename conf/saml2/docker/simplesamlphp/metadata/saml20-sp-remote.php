<?php
/**
 * SAML 2.0 remote SP metadata for SimpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote
 */

/*
 * Example SimpleSAMLphp SAML 2.0 SP
 */
$metadata['https://zentral/saml2/metadata/'] = array(
	'AssertionConsumerService' => 'https://zentral/saml2/acs/',
	'SingleLogoutService' => 'https://zentral/saml2/ls/',
);
