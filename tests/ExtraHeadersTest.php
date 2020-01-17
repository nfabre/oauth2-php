<?php

namespace OAuth2\Tests;

use OAuth2\OAuth2;
use OAuth2\Model\OAuth2Client;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use OAuth2\Tests\Fixtures\OAuth2GrantUserStub;

/**
 * Extra Headers test case.
 */
class ExtraHeadersTest extends TestCase
{
    public function testErrorResponseContainsExtraHeaders(): void
    {
        $config = array(
            OAuth2::CONFIG_RESPONSE_EXTRA_HEADERS => [
                'Access-Control-Allow-Origin' => 'http://www.foo.com',
                'X-Extra-Header-1' => 'Foo-Bar',
            ],
        );
        $stub = new OAuth2GrantUserStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->addUser('foo', 'bar');
        $stub->setAllowedGrantTypes(array('authorization_code', 'password'));

        $oauth2 = new OAuth2($stub, $config);

        $response = $oauth2->grantAccessToken(new Request(array(
            'grant_type' => 'password',
            'client_id' => 'cid',
            'client_secret' => 'cpass',
            'username' => 'foo',
            'password' => 'bar',
        )));
        $this->assertSame('http://www.foo.com', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertSame('Foo-Bar', $response->headers->get('X-Extra-Header-1'));
    }
}
