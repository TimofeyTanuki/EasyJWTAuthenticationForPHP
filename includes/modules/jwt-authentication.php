<?php

namespace Tanuki\Modules;

require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/services/jwt-authenticator.php';

function Main()
{
	$Headers = apache_request_headers();
	
	if (empty($Headers['Authorization']))
	{
		http_response_code(401);
		exit;
	}

	$Authorization = explode(' ', $Headers['Authorization']);
	if (count($Authorization) != 2)
	{
		http_response_code(401);
		exit;
	}

	if ($Authorization[0] !== 'Bearer')
	{
		http_response_code(401);
		exit;
	}

	// Setting the secret when creating an instance of the authenticator class.
	$JWTAuthenticator = new Tanuki\Services\JWTAuthenticator('8i^BsP@3-a+*jJk&t7~WY?B:guCU!c#wJDmxMdj^MY?BFxn:;X/LhZC~O>e5R!t+', 'HS256', 900);
	$Payload = $JWTAuthenticator->Decode($Authorization[1], true, $_SERVER['REQUEST_TIME']);

	if ($Payload === null)
	{
		http_response_code(401);
		exit;
	}

	define('JWTAuthentication', $Payload);
}

Main();