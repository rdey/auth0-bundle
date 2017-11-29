<?php
declare(strict_types=1);

namespace Happyr\Auth0Bundle\Security\Firewall;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\LogoutListener;

final class Auth0LogoutListener extends LogoutListener
{
    /** @var  string */
    private $auth0Domain;

    public function setAuth0Domain(string $auth0Domain)
    {
        $this->auth0Domain = $auth0Domain;
    }

    public function handle(GetResponseEvent $event)
    {
        parent::handle($event);

        if ($event->hasResponse()) {
            $request = $event->getRequest();
            $response = $event->getResponse();
            if (!$response instanceof RedirectResponse) {
                throw new \UnexpectedValueException("Auth0 Logout listener expects response to be a RedirectResponse. Perhaps the bundle is incompatible with your Symfony version?");
            }

            $targetUrl = $response->getTargetUrl();
            if (0 !== strpos($targetUrl, 'http')) {
                $targetUrl = $request->getUriForPath($targetUrl);
            }

            $auth0LogoutUrl = sprintf("https://%s/v2/logout?returnTo=%s", $this->auth0Domain, urlencode($targetUrl));

            $response->setTargetUrl($auth0LogoutUrl);
        }
    }
}