<?php
declare(strict_types=1);

namespace Happyr\Auth0Bundle\Model\Authentication;

use Firebase\JWT\JWT;

class Claims
{
    /**
     * @var array
     */
    protected $claims;

    /**
     * Claims constructor.
     */
    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    public static function createFromJWT(string $jwt, string $key)
    {
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = 5;
        $claims = JWT::decode($jwt, $key, ['HS256', 'HS384', 'HS512', 'RS256']);
        JWT::$leeway = $previousLeeway;
        return new static((array)$claims);
    }

    public function hasClaim(string $claim): bool
    {
        return isset($this->claims[$claim]);
    }

    public function getClaim(string $claim)
    {
        return $this->claims[$claim];
    }
}