<?php

namespace Happyr\Auth0Bundle\Security\Authentication\Token;

use Happyr\Auth0Bundle\Model\Authentication\Claims;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Role\Role;

class SSOToken extends AbstractToken
{
    /** @var bool  */
    private $createdFromRefreshToken = false;

    /** @var  string|null */
    private $accessToken;

    /** @var \DateTime|null */
    private $expiresAt;

    /** @var  string|null */
    private $refreshToken;

    /** @var string[] */
    private $storedRoles = [];

    /** @var Claims|null */
    private $claims;

    public function getUsername()
    {
        if ($this->getUser()) {
            return parent::getUsername();
        }

        if ($this->claims && $this->claims->hasClaim('sub')) {
            return $this->claims->getClaim('sub');
        }

        return $this->accessToken;
    }

    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }

    /**
     * @param mixed $accessToken
     *
     * @return SSOToken
     */
    public function setAccessToken($accessToken): SSOToken
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * @return mixed
     */
    public function getExpiresAt(): ?\DateTimeInterface
    {
        return $this->expiresAt;
    }

    /**
     * @param mixed $expiresAt
     *
     * @return SSOToken
     */
    public function setExpiresAt(\DateTimeInterface $expiresAt): SSOToken
    {
        $this->expiresAt = $expiresAt;

        return $this;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(?string $refreshToken): SSOToken
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    public function getIdToken(): ?Claims
    {
        return $this->claims;
    }

    public function setIdToken(?Claims $claims): SSOToken
    {
        $this->claims = $claims;

        return $this;
    }

    public function wasCreatedFromRefreshToken(): bool
    {
        return $this->createdFromRefreshToken;
    }

    public function setCreatedFromRefreshToken(bool $createdFromRefreshToken): SSOToken
    {
        $this->createdFromRefreshToken = $createdFromRefreshToken;

        return $this;
    }

    /**
     * @return boolean
     */
    public function isExpired()
    {
        if (!($expiration = $this->getExpiresAt())) {
            return true;
        }

        return $expiration <= (new \DateTime());
    }

    public function getCredentials()
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        $user = $this->getUser();

        return serialize(
            [
                is_object($user) ? clone $user : $user,
                is_object($this->claims) ? clone $this->claims : $this->claims,
                $this->isAuthenticated(),
                $this->getRoles(),
                $this->getAttributes(),
                $this->accessToken,
                $this->expiresAt,
                $this->refreshToken,
                $this->createdFromRefreshToken,
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list($user, $this->claims, $isAuthenticated, $this->storedRoles, $attributes, $this->accessToken, $this->expiresAt, $this->refreshToken, $this->createdFromRefreshToken) = unserialize($serialized);
        if ($user) {
            $this->setUser($user);
        }
        $this->setAuthenticated($isAuthenticated);
        $this->setAttributes($attributes);
    }

    public function getRoles()
    {
        $allRoles = array_merge(parent::getRoles(), $this->storedRoles);
        $uniqueRoles = [];

        /** @var Role $role */
        foreach ($allRoles as $role) {
            $uniqueRoles[$role->getRole()] = $role;
        }

        return array_values($uniqueRoles);
    }
}
