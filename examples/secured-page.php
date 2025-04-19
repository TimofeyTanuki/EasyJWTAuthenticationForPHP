<?php
	// If there is no authentication, it will return HTTP 403 (Unauthorized) and exit the script.
	require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/modules/jwt-authentication.php';

	echo 'This page requires JWT authentication.' . PHP_EOL;

	echo 'Your "sub" claim: ' . JWTAuthentication['sub'] . PHP_EOL; 

	echo 'Your token payload:' . PHP_EOL;
	var_dump(JWTAuthentication);
