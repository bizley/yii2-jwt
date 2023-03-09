<?php

declare(strict_types=1);

namespace bizley\tests\standard;

use bizley\jwt\Jwt;
use bizley\jwt\JwtHttpBearerAuth;
use bizley\tests\ConsecutiveCalls;
use bizley\tests\stubs\TestAuthController;
use bizley\tests\stubs\TestJwtHttpBearerAuth;
use bizley\tests\stubs\TestStub2Controller;
use bizley\tests\stubs\TestStubController;
use bizley\tests\stubs\UserIdentity;
use DateTimeImmutable;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use PHPUnit\Framework\TestCase;
use stdClass;
use Yii;
use yii\base\InvalidConfigException;
use yii\log\Logger;
use yii\rest\Controller;
use yii\web\Application;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;

class BearerTest extends TestCase
{
    protected function setUp(): void
    {
        new Application(
            [
                'id' => 'test',
                'basePath' => __DIR__,
                'vendorPath' => __DIR__ . '/../vendor',
                'components' => [
                    'user' => [
                        'identityClass' => UserIdentity::class,
                        'enableSession' => false,
                    ],
                    'request' => [
                        'enableCookieValidation' => false,
                        'scriptFile' => __DIR__ . '/index.php',
                        'scriptUrl' => '/index.php',
                    ],
                    'jwt' => [
                        'class' => Jwt::class,
                        'signer' => Jwt::HS256,
                        'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M',
                    ],
                ],
                'controllerMap' => [
                    'test-auth' => TestAuthController::class,
                    'test-stub' => TestStubController::class,
                    'test-stub2' => TestStub2Controller::class,
                ],
            ]
        );
    }

    protected function getJwt(): Jwt
    {
        return Yii::$app->jwt;
    }

    public function testEmptyPattern(): void
    {
        $this->expectException(InvalidConfigException::class);
        $controller = Yii::$app->createController('test-stub')[0];
        $controller->run('test');
    }

    public function testHttpBearerAuthNoHeader(): void
    {
        $this->expectException(UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    public function testHttpBearerAuthInvalidToken(): void
    {
        $this->expectException(Token\InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        Yii::$app->request->headers->set('Authorization', 'Bearer InvalidToken');

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    public function testHttpBearerAuthInvalidHeader(): void
    {
        $this->expectException(UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        Yii::$app->request->headers->set('Authorization', 'InvalidHeaderValue');

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    public function testHttpBearerAuthExpiredToken(): void
    {
        $this->expectException(UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(
            new LooseValidAt(SystemClock::fromSystemTimezone())
        );

        $token = $this->getJwt()->getBuilder()
            ->issuedAt($now->modify('-10 minutes'))
            ->expiresAt($now->modify('-5 minutes'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->run('filtered');
    }

    public function testHttpBearerAuth(): void
    {
        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(
            new LooseValidAt(SystemClock::fromSystemTimezone()),
            new IssuedBy('test')
        );

        $token = $this->getJwt()->getBuilder()
            ->issuedAt($now)
            ->issuedBy('test')
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        UserIdentity::$token = $token;

        Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /** @var Controller $controller */
        $controller = Yii::$app->createController('test-auth')[0];

        self::assertEquals('test', $controller->run('filtered'));
    }

    public function testHttpBearerAuthCustom(): void
    {
        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(
            new LooseValidAt(SystemClock::fromSystemTimezone())
        );

        $token = $this->getJwt()->getBuilder()
            ->relatedTo('test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey());

        $JWT = $token->toString();

        Yii::$app->request->headers->set('Authorization', "Bearer $JWT");

        /** @var TestAuthController $controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = static function (Token $token) {
            $identity = UserIdentity::findIdentity($token->claims()->get('sub'));
            Yii::$app->user->switchIdentity($identity);
            return $identity;
        };

        self::assertEquals('test', $controller->run('filtered'));
    }

    public function testHttpBearerAuthCustomNoIdentity(): void
    {
        $this->expectException(UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(new LooseValidAt(SystemClock::fromSystemTimezone()));

        $token = $this->getJwt()->getBuilder()
            ->relatedTo('test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey());

        $JWT = $token->toString();

        Yii::$app->request->headers->set('Authorization', "Bearer $JWT");

        /** @var TestAuthController $controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = static function (Token $token) {
            return null;
        };
        $controller->run('filtered');
    }

    public function testHttpBearerAuthCustomNotIdentityInterface(): void
    {
        $this->expectException(UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');

        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(new LooseValidAt(SystemClock::fromSystemTimezone()));

        $token = $this->getJwt()->getBuilder()
            ->relatedTo('test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey());

        $JWT = $token->toString();

        Yii::$app->request->headers->set('Authorization', "Bearer $JWT");

        /** @var TestAuthController $controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = static function (Token $token) {
            return new stdClass();
        };
        $controller->run('filtered');
    }

    public function testMethodsVisibility(): void
    {
        $filter = new JwtHttpBearerAuth(['jwt' => $this->getJwt()]);

        $jwt = $filter->getJwtComponent();
        $jwt->getConfiguration()->setValidationConstraints(new IssuedBy('test'));
        self::assertNotEmpty($filter->processToken(
            $jwt->getBuilder()->issuedBy('test')->getToken(
                $jwt->getConfiguration()->signer(),
                $jwt->getConfiguration()->signingKey()
            )->toString()
        ));
    }

    public function testFailVisibility(): void
    {
        $filter = new TestJwtHttpBearerAuth(['jwt' => $this->getJwt()]);
        $filter->fail($this->createMock(Response::class));

        self::assertSame(2, $filter->flag);
    }

    public function testFailedToken(): void
    {
        $this->expectException(NoConstraintsGiven::class);

        $logger = $this->createMock(Logger::class);
        $logger->expects(self::exactly(2))->method('log')->willReturnCallback(
            new ConsecutiveCalls([
                ['Route to run: test-stub2/test', 8, 'yii\base\Controller::runAction'],
                ['No constraint given.', 2, 'JwtHttpBearerAuth'],
            ], ConsecutiveCalls::NEVER)
        );
        Yii::setLogger($logger);

        $token = $this->getJwt()->getBuilder()
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-stub2')[0];
        $controller->run('test');
        self::assertSame(14, $controller->flag);
    }

    public function testSilentException(): void
    {
        $this->expectException(UnauthorizedHttpException::class);
        $this->expectExceptionMessage('Your request was made with invalid or expired JSON Web Token.');
        // instead of 'The JWT string must have two dots'

        Yii::$app->request->headers->set('Authorization', 'Bearer InvalidToken');

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['throwException'] = false;
        $controller->run('filtered');
    }
}
