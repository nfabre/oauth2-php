<?php

namespace OAuth2\Tests;

use OAuth2\OAuth2;
use OAuth2\Model\OAuth2AuthCode;
use OAuth2\Model\OAuth2Client;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use OAuth2\IOAuth2GrantCode;

/**
 * OAuth2 test cases that involve capturing output.
 */
class OAuth2OutputTest extends TestCase
{
    /**
     * @var OAuth2
     */
    private $fixture;

    /**
     * Tests OAuth2->grantAccessToken() with successful Auth code grant
     *
     */
    public function testGrantAccessTokenWithGrantAuthCodeSuccess(): void
    {
        $request = new Request(
            [
                'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE,
                'redirect_uri' => 'http://www.example.com/my/subdir',
                'client_id' => 'my_little_app',
                'client_secret' => 'b',
                'code'=> 'foo'
            ]
        );
        $storedToken = new OAuth2AuthCode('my_little_app', '', time() + 60, null, null, 'http://www.example.com');

        $mockStorage = $this->createBaseMock(IOAuth2GrantCode::class);
        $mockStorage->expects($this->any())
            ->method('getAuthCode')
            ->willReturn($storedToken);

        $this->fixture = new OAuth2($mockStorage);
        $response = $this->fixture->grantAccessToken($request);

        // Successful token grant will return a JSON encoded token:
        $this->assertRegExp('/{"access_token":".*","expires_in":\d+,"token_type":"bearer"/', $response->getContent());
    }

    /**
     * Tests OAuth2->grantAccessToken() with successful Auth code grant, but without redreict_uri in the input
     */
    public function testGrantAccessTokenWithGrantAuthCodeSuccessWithoutRedirect(): void
    {
        $request = new Request(
            [
                'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE,
                'client_id' => 'my_little_app',
                'client_secret' => 'b',
                'code'=> 'foo'
            ]
        );
        $storedToken = new OAuth2AuthCode(
            'my_little_app',
            '',
            time() + 60,
            null,
            null,
            'http://www.example.com'
        );

        $mockStorage = $this->createBaseMock(IOAuth2GrantCode::class);
        $mockStorage->expects($this->any())
            ->method('getAuthCode')
            ->willReturn($storedToken);

        $this->fixture = new OAuth2($mockStorage);
        $this->fixture->setVariable(OAuth2::CONFIG_ENFORCE_INPUT_REDIRECT, false);
        $response = $this->fixture->grantAccessToken($request);

        // Successful token grant will return a JSON encoded token:
        $this->assertRegExp('/{"access_token":".*","expires_in":\d+,"token_type":"bearer"/', $response->getContent());
    }

// Utility methods


    protected function createBaseMock(string $interfaceName): MockObject
    {
        $client = new OAuth2Client('my_little_app');

        $mockStorage = $this->getMockBuilder($interfaceName)->getMock();
        $mockStorage->expects($this->any())
            ->method('getClient')
            ->willReturnCallback(function ($id) use ($client) {
                if ('my_little_app' === $id) {
                    return $client;
                }
            });
        $mockStorage->expects($this->any())
            ->method('checkClientCredentials')
            ->willReturn(true); // Always return true for any combination of user/pass
        $mockStorage->expects($this->any())
            ->method('checkRestrictedGrantType')
            ->willReturn(true); // Always return true for any combination of user/pass

         return $mockStorage;
    }
}
