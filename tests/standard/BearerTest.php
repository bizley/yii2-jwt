<?php

declare(strict_types=1);

namespace bizley\tests\standard;

use bizley\jwt;
use bizley\tests\ConsecutiveCalls;
use bizley\tests\stubs;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;
use yii\log\Logger;
use yii\rest\Controller;
use yii\web;

#[CoversClass(jwt\JwtHttpBearerAuth::class)]
#[CoversClass(jwt\Jwt::class)]
#[CoversClass(jwt\JwtTools::class)]
class BearerTest extends TestCase
{
    protected function setUp(): void
    {
        new web\Application(
            [
                'id' => 'test',
                'basePath' => __DIR__,
                'vendorPath' => __DIR__ . '/../vendor',
                'components' => [
                    'user' => [
                        'identityClass' => stubs\UserIdentity::class,
                        'enableSession' => false,
                    ],
                    'request' => [
                        'enableCookieValidation' => false,
                        'scriptFile' => __DIR__ . '/index.php',
                        'scriptUrl' => '/index.php',
                    ],
                    'jwt' => [
                        'class' => jwt\Jwt::class,
                        'signer' => jwt\Jwt::HS256,
                        'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M',
                    ],
                ],
                'controllerMap' => [
                    'test-auth' => stubs\TestAuthController::class,
                    'test-stub' => stubs\TestStubController::class,
                    'test-stub2' => stubs\TestStub2Controller::class,
                ],
            ]
        );
    }

    protected function getJwt(): jwt\Jwt
    {
        return \Yii::$app->jwt;
    }

    #[Test]
    public function emptyPattern(): void
    {
        $this->expectException(InvalidConfigException::class);
        $controller = \Yii::$app->createController('test-stub')[0];
        $controller->run('test');
    }

    #[Test]
    public function nonCallableAuth(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('The "auth" property must be a valid callable or null!');

        /* @var $controller stubs\TestAuthController */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = 'notExistingFunction';
        $controller->run('filtered');
    }

    #[Test]
    public function httpBearerAuthNoHeader(): void
    {
        $this->expectException(web\UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        /* @var $controller Controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    #[Test]
    public function httpBearerAuthInvalidToken(): void
    {
        $this->expectException(Token\InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        \Yii::$app->request->headers->set('Authorization', 'Bearer InvalidToken');

        /* @var $controller Controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    #[Test]
    public function httpBearerAuthInvalidHeader(): void
    {
        $this->expectException(web\UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        \Yii::$app->request->headers->set('Authorization', 'InvalidHeaderValue');

        /* @var $controller Controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    #[Test]
    public function httpBearerAuthExpiredToken(): void
    {
        $this->expectException(web\UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        $now = new \DateTimeImmutable();

        $this->getJwt()->setValidationConstraints(
            new LooseValidAt(SystemClock::fromSystemTimezone())
        );

        $token = $this->getJwt()->getBuilder()
            ->issuedAt($now->modify('-10 minutes'))
            ->expiresAt($now->modify('-5 minutes'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        \Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /* @var $controller Controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    #[Test]
    public function httpBearerAuth(): void
    {
        $now = new \DateTimeImmutable();

        $this->getJwt()->setValidationConstraints(
            new LooseValidAt(SystemClock::fromSystemTimezone()),
            new IssuedBy('test')
        );

        $token = $this->getJwt()->getBuilder()
            ->issuedAt($now)
            ->issuedBy('test')
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        stubs\UserIdentity::$token = $token;

        \Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /** @var Controller $controller */
        $controller = \Yii::$app->createController('test-auth')[0];

        self::assertEquals('test', $controller->run('filtered'));
    }

    #[Test]
    public function httpBearerAuthCustom(): void
    {
        $now = new \DateTimeImmutable();

        $this->getJwt()->setValidationConstraints(
            new LooseValidAt(SystemClock::fromSystemTimezone())
        );

        $token = $this->getJwt()->getBuilder()
            ->relatedTo('test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey());

        $JWT = $token->toString();

        \Yii::$app->request->headers->set('Authorization', "Bearer $JWT");

        /** @var stubs\TestAuthController $controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = static function (Token $token) {
            $identity = stubs\UserIdentity::findIdentity($token->claims()->get('sub'));
            \Yii::$app->user->switchIdentity($identity);
            return $identity;
        };

        self::assertEquals('test', $controller->run('filtered'));
    }

    #[Test]
    public function httpBearerAuthCustomNoIdentity(): void
    {
        $this->expectException(web\UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        $now = new \DateTimeImmutable();

        $this->getJwt()->setValidationConstraints(new LooseValidAt(SystemClock::fromSystemTimezone()));

        $token = $this->getJwt()->getBuilder()
            ->relatedTo('test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey());

        $JWT = $token->toString();

        \Yii::$app->request->headers->set('Authorization', "Bearer $JWT");

        /** @var stubs\TestAuthController $controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = static function (Token $token) {
            return null;
        };
        $controller->run('filtered');
    }

    #[Test]
    public function httpBearerAuthCustomNotIdentityInterface(): void
    {
        $this->expectException(web\UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        $now = new \DateTimeImmutable();

        $this->getJwt()->setValidationConstraints(new LooseValidAt(SystemClock::fromSystemTimezone()));

        $token = $this->getJwt()->getBuilder()
            ->relatedTo('test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey());

        $JWT = $token->toString();

        \Yii::$app->request->headers->set('Authorization', "Bearer $JWT");

        /** @var stubs\TestAuthController $controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = static function (Token $token) {
            return new \stdClass();
        };
        $controller->run('filtered');
    }

    #[Test]
    public function methodsVisibility(): void
    {
        $filter = new jwt\JwtHttpBearerAuth(['jwt' => $this->getJwt()]);

        $jwt = $filter->getJwtComponent();
        $jwt->getConfiguration()->setValidationConstraints(new IssuedBy('test'));
        self::assertNotEmpty($filter->processToken(
            $jwt->getBuilder()->issuedBy('test')->getToken(
                $jwt->getConfiguration()->signer(),
                $jwt->getConfiguration()->signingKey()
            )->toString()
        ));
    }

    #[Test]
    public function failVisibility(): void
    {
        $filter = new stubs\TestJwtHttpBearerAuth(['jwt' => $this->getJwt()]);
        $filter->fail($this->createMock(web\Response::class));

        self::assertSame(2, $filter->flag);
    }

    #[Test]
    public function failedToken(): void
    {
        $this->expectException(NoConstraintsGiven::class);

        $logger = $this->createMock(Logger::class);
        $logger
            ->expects($this->exactly(2))
            ->method('log')
            ->with(
                new ConsecutiveCalls('Route to run: test-stub2/test', 'No constraint given.'),
                new ConsecutiveCalls(8, 2),
                new ConsecutiveCalls('yii\base\Controller::runAction', 'JwtHttpBearerAuth')
            );
        \Yii::setLogger($logger);

        $token = $this->getJwt()->getBuilder()
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        \Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /* @var $controller Controller */
        $controller = \Yii::$app->createController('test-stub2')[0];
        $controller->run('test');
        self::assertSame(14, $controller->flag);
    }

    #[Test]
    public function silentException(): void
    {
        $this->expectException(web\UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');
        // instead of 'The JWT string must have two dots'

        \Yii::$app->request->headers->set('Authorization', 'Bearer InvalidToken');

        /* @var $controller Controller */
        $controller = \Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['throwException'] = false;
        $controller->run('filtered');
    }
}
