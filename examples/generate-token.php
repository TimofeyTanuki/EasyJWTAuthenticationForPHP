<?php
	require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/services/jwt-authenticator.php';

	// Secret key used to sign JWT.
	$Secret = '8i^BsP@3-a+*jJk&t7~WY?B:guCU!c#wJDmxMdj^MY?BFxn:;X/LhZC~O>e5R!t+';

	// Available algorithms: HS256 (sha256), HS384 (sha384), HS512 (sha512).
	$Algorithm = 'HS256';

	// JWT lifetime in seconds.
	$Lifetime = 900;

	$JWTAuthenticator = new \Tanuki\Services\JWTAuthenticator($Secret, $Algorithm, $Lifetime);

	// Any claims.
	$Payload =
	[
		'sub' => '123',
		'myclaim' => 'example'
	];

	$Timestamp = time();

	$Token = $JWTAuthenticator->Encode($Payload, $Timestamp);

	$Output =
	[
		'token' => $Token
	];

	header('Content-Type:application/json;charset=utf-8');
	echo json_encode($Output, JSON_PRETTY_PRINT);