<?php
	namespace Tanuki\Services;

	class JWTAuthenticator
	{
		protected string $Secret;
		protected string $Algorithm;
		protected int $Lifetime;

		protected const Algorithms =
		[
			'HS256' => 'sha256',
			'HS384' => 'sha384',
			'HS512' => 'sha512'
		];

		public function __construct(string $Secret, string $Algorithm = 'HS256', $Lifetime = 900)
		{
			$this->Secret = $Secret;
			$this->Algorithm = $Algorithm;
			$this->Lifetime = $Lifetime;
		}

		protected function Sign(string $Content) : string
		{
			return \hash_hmac(self::Algorithms[$this->Algorithm], $Content, $this->Secret, true);
		}

		protected function Verify(string $Algorithm, string $Content, $Sign) : bool
		{
			return \hash_equals(self::UrlEncode(\hash_hmac($Algorithm, $Content, $this->Secret, true)), $Sign);
		}

		public function Encode(array $Payload = [], int $Timestamp) : string
		{
			$Header =
			[
				'alg' => $this->Algorithm,
				'typ' => 'JWT'
			];

			$Payload['exp'] = $Timestamp + $this->Lifetime;

			$Content = self::UrlEncode(\json_encode($Header)) . '.' . self::UrlEncode(\json_encode($Payload));
			return $Content . '.' . self::UrlEncode($this->Sign($Content));
		}

		public function Decode(string $Token, bool $VerifySign = false, int $Timestamp = 0) : ?array
		{
			$Blocks = \explode('.', $Token, 3);

			if (count($Blocks) < 2)
				return null;

			$Headers = self::UrlDecode($Blocks[0]);

			if (empty($Headers['alg']))
				return null;

			if (!isset(self::Algorithms[$Headers['alg']]))
				return null;

			$Algorithm = self::Algorithms[$Headers['alg']];

			if (!$this->Verify($Algorithm, $Blocks[0] . '.' . $Blocks[1], $Blocks[2]))
				return null;

			$Payload = self::UrlDecode($Blocks[1]);

			if ($Timestamp == 0)
				return $Payload;

			if (empty($Payload['exp']))
				return null;

			$ExpiryAt = intval($Payload['exp']);

			if ($ExpiryAt < $Timestamp)
				return null;

			return $Payload;
		}

		protected static function UrlEncode(string $Raw) : string
		{
			return \rtrim(\strtr(\base64_encode($Raw), '+/', '-_'), '=');
		}

		protected static function UrlDecode(string $Encoded) : ?array
		{
			$JSON = \base64_decode(\strtr($Encoded, '-_', '+/'));
			$Decoded = \json_decode($JSON, true);

			if (\json_last_error() !== \JSON_ERROR_NONE)
				return null;

			return $Decoded;
		}
	}