<?php

declare(strict_types=1);

namespace bizley\tests\standard;

use bizley\jwt\Jwt;
use bizley\jwt\JwtTools;
use bizley\tests\stubs\JwtStub;
use Lcobucci\JWT as BaseJwt;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;
use yii\log\Logger;

#[Attributes\CoversClass(Jwt::class)]
#[Attributes\CoversClass(JwtTools::class)]
class JwtTest extends TestCase
{
    private function getJwt(): Jwt
    {
        return new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M',
            ]
        );
    }

    #[Attributes\Test]
    public function availableAlgorithmTypes(): void
    {
        self::assertSame(
            [
                Jwt::SYMMETRIC => [
                    Jwt::HS256,
                    Jwt::HS384,
                    Jwt::HS512,
                    Jwt::BLAKE2B,
                ],
                Jwt::ASYMMETRIC => [
                    Jwt::RS256,
                    Jwt::RS384,
                    Jwt::RS512,
                    Jwt::ES256,
                    Jwt::ES384,
                    Jwt::ES512,
                    Jwt::EDDSA,
                ],
            ],
            $this->getJwt()->algorithmTypes,
        );
    }

    #[Attributes\Test]
    public function noInit(): void
    {
        $this->expectException(InvalidConfigException::class);
        $jwtStub = new JwtStub();
        $jwtStub->getConfiguration();
    }

    #[Attributes\Test]
    public function validateSuccess(): void
    {
        $jwt = $this->getJwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey());
        self::assertTrue($jwt->validate($token));
    }

    #[Attributes\Test]
    public function validateSuccessWithStringToken(): void
    {
        $jwt = $this->getJwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $config->signer(),
            $config->signingKey()
        )->toString();
        self::assertTrue($jwt->validate($token));
    }

    #[Attributes\Test]
    public function validateFail(): void
    {
        $jwt = $this->getJwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('def')->getToken($config->signer(), $config->signingKey());
        self::assertFalse($jwt->validate($token));
    }

    #[Attributes\DoesNotPerformAssertions]
    #[Attributes\Test]
    public function assertSuccess(): void
    {
        $jwt = $this->getJwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey());
        $jwt->assert($token);
    }

    #[Attributes\DoesNotPerformAssertions]
    #[Attributes\Test]
    public function assertSuccessWithStringToken(): void
    {
        $jwt = $this->getJwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $config->signer(),
            $config->signingKey()
        )->toString();
        $jwt->assert($token);
    }

    #[Attributes\Test]
    public function assertFail(): void
    {
        $jwt = $this->getJwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('def')->getToken($config->signer(), $config->signingKey());
        $this->expectException(RequiredConstraintsViolated::class);
        $jwt->assert($token);
    }

    public static function providerForInvalidKey(): iterable
    {
        yield 'object' => [new \stdClass(), 'Invalid key configuration!'];
        yield 'int value' => [[Jwt::KEY => 1], 'Invalid key value!'];
        yield 'array value' => [[Jwt::KEY => []], 'Invalid key value!'];
        yield 'object value' => [[Jwt::KEY => new \stdClass()], 'Invalid key value!'];
        yield 'method' => [[Jwt::KEY => 'k', Jwt::METHOD => ''], 'Invalid key method!'];
        yield 'int pass' => [[Jwt::KEY => 'k', Jwt::PASSPHRASE => 1], 'Invalid key passphrase!'];
        yield 'array pass' => [[Jwt::KEY => 'k', Jwt::PASSPHRASE => []], 'Invalid key passphrase!'];
        yield 'object pass' => [[Jwt::KEY => 'k', Jwt::PASSPHRASE => new \stdClass()], 'Invalid key passphrase!'];
        yield 'empty string' => [[Jwt::KEY => ''], 'Invalid key value!'];
        yield '@ file' => [[Jwt::KEY => '@', Jwt::METHOD => Jwt::METHOD_FILE], 'Invalid path alias: @'];
        yield 'unknown alias file' => [
            [Jwt::KEY => '@unknownAlias/key', Jwt::METHOD => Jwt::METHOD_FILE],
            'Invalid path alias: @unknownAlias/key'
        ];
        yield 'empty alias' => [[Jwt::KEY => '@emptyString'], 'Yii alias was resolved as an invalid key value!'];
    }

    #[Attributes\DataProvider('providerForInvalidKey')]
    #[Attributes\Test]
    public function invalidKey($key, string $message): void
    {
        $this->expectExceptionMessage($message);
        \Yii::setAlias('@emptyString', '');
        new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => $key
            ]
        );
    }

    #[Attributes\Test]
    public function plainKeyStartingWithAtThatIsNotAliasIsUsedAsIs(): void
    {
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => [Jwt::KEY => '@secret1secret1secret1secret1secret1', Jwt::METHOD => Jwt::METHOD_PLAIN],
            ]
        );
        self::assertSame('@secret1secret1secret1secret1secret1', $jwt->getConfiguration()->signingKey()->contents());
    }

    #[Attributes\Test]
    public function base64KeyIsDecoded(): void
    {
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => [
                    Jwt::KEY => \base64_encode('secret1secret1secret1secret1secret1'),
                    Jwt::METHOD => Jwt::METHOD_BASE64,
                ],
            ]
        );
        self::assertSame('secret1secret1secret1secret1secret1', $jwt->getConfiguration()->signingKey()->contents());
    }

    #[Attributes\Test]
    public function plainKeyAliasIsResolved(): void
    {
        \Yii::setAlias('@plainSecret', 'secret1secret1secret1secret1secret1');
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => [Jwt::KEY => '@plainSecret', Jwt::METHOD => Jwt::METHOD_PLAIN],
            ]
        );
        self::assertSame('secret1secret1secret1secret1secret1', $jwt->getConfiguration()->signingKey()->contents());
    }

    #[Attributes\Test]
    public function validateWithRuntimeConstraints(): void
    {
        $jwt = $this->getJwt();
        $jwt->setValidationConstraints(new IdentifiedBy('abc'));
        $config = $jwt->getConfiguration();
        self::assertTrue(
            $jwt->validate($jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey()))
        );
        self::assertFalse(
            $jwt->validate($jwt->getBuilder()->identifiedBy('def')->getToken($config->signer(), $config->signingKey()))
        );
    }

    #[Attributes\Test]
    public function runtimeConstraintsReplaceConfiguredOnes(): void
    {
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M',
                'validationConstraints' => [new IdentifiedBy('def')],
            ]
        );
        $jwt->setValidationConstraints(new IdentifiedBy('abc'));
        $config = $jwt->getConfiguration();
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey());
        self::assertTrue($jwt->validate($token));
    }

    #[Attributes\Test]
    public function deprecatedConfigurationConstraintsTakePrecedenceAndLogWarning(): void
    {
        $logger = new Logger();
        \Yii::setLogger($logger);

        $jwt = $this->getJwt();
        $jwt->setValidationConstraints(new IdentifiedBy('def'));
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey());
        self::assertTrue($jwt->validate($token));

        $warnings = \array_values(\array_filter(
            $logger->messages,
            static fn (array $message): bool => $message[1] === Logger::LEVEL_WARNING && $message[2] === Jwt::class
        ));
        self::assertCount(1, $warnings);
        self::assertSame(
            'Providing validation constraints with Lcobucci\JWT\Configuration::setValidationConstraints() is '
            . 'deprecated since 4.2.0 and will be removed in 5.0.0. Use bizley\jwt\Jwt::setValidationConstraints() '
            . 'or the "validationConstraints" property instead.',
            $warnings[0][0]
        );
    }

    #[Attributes\Test]
    public function noWarningWithoutConfigurationConstraints(): void
    {
        $logger = new Logger();
        \Yii::setLogger($logger);

        $jwt = $this->getJwt();
        $jwt->setValidationConstraints(new IdentifiedBy('abc'));
        $config = $jwt->getConfiguration();
        $jwt->validate($jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey()));

        self::assertSame([], $logger->messages);
    }

    #[Attributes\Test]
    public function customEncoder(): void
    {
        $encoder = $this->createMock(BaseJwt\Encoder::class);
        $encoder->expects($this->exactly(3))->method('base64UrlEncode');

        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M',
                'encoder' => $encoder,
            ]
        );
        $jwt->getBuilder()->getToken($jwt->getConfiguration()->signer(), $jwt->getConfiguration()->signingKey());
    }

    #[Attributes\Test]
    public function customDecoder(): void
    {
        $decoder = $this->createMock(BaseJwt\Decoder::class);
        $decoder->method('jsonDecode')->willReturn([]);
        $decoder->expects($this->exactly(3))->method('base64UrlDecode');

        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M',
                'decoder' => $decoder,
            ]
        );
        $jwt->parse(
            $jwt->getBuilder()->getToken(
                $jwt->getConfiguration()->signer(),
                $jwt->getConfiguration()->signingKey()
            )->toString()
        );
    }

    #[Attributes\Test]
    public function methodsVisibility(): void
    {
        $jwt = $this->getJwt();
        self::assertNotEmpty($jwt->getConfiguration());
        self::assertNotEmpty($jwt->getBuilder());
        self::assertNotEmpty($jwt->getParser());
    }

    public static function providerForWrongKeyNames(): iterable
    {
        yield '@' => ['_@bizley/tests/data/rs256.key'];
        yield 'file://' => ['_file://' . __DIR__ . '/data/rs256.key'];
    }

    #[Attributes\DataProvider('providerForWrongKeyNames')]
    #[Attributes\Test]
    public function wrongFileKeyNameStartingCharacters(string $key): void
    {
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => $key
            ]
        );
        // name instead of file content
        self::assertSame($key, $jwt->getConfiguration()->signingKey()->contents());
    }

    public static function providerForRightKeyNames(): iterable
    {
        yield '@' => ['@bizley/tests/data/rs256.key'];
        yield '@ in array' => [[
            Jwt::KEY => '@bizley/tests/data/rs256.key',
            Jwt::METHOD => Jwt::METHOD_FILE,
        ]];
        yield 'file://' => ['file://' . __DIR__ . '/../data/rs256.key'];
    }

    #[Attributes\DataProvider('providerForRightKeyNames')]
    #[Attributes\Test]
    public function rightFileKeyNameStartingCharacters(string|array $key): void
    {
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => $key
            ]
        );
        // content instead of file name
        self::assertSame(
            '-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
',
            $jwt->getConfiguration()->signingKey()->contents()
        );
    }

    public static function providerForSignerSignatureConverter(): iterable
    {
        yield Jwt::ES256 => [Jwt::ES256];
        yield Jwt::ES384 => [Jwt::ES384];
        yield Jwt::ES512 => [Jwt::ES512];
    }

    #[Attributes\DataProvider('providerForSignerSignatureConverter')]
    #[Attributes\Test]
    public function prepareSignatureConverter(string $signerId): void
    {
        new Jwt(['signer' => $signerId, 'signingKey' => ' ', 'verifyingKey' => ' ']);
        $this->assertInstanceOf(
            BaseJwt\Signer\Ecdsa\MultibyteStringConverter::class,
            \Yii::$container->get(BaseJwt\Signer\Ecdsa\SignatureConverter::class)
        );
    }

    #[Attributes\DataProvider('providerForSignerSignatureConverter')]
    #[Attributes\Test]
    public function customSignatureConverterIsRespected(string $signerId): void
    {
        $converter = $this->createStub(BaseJwt\Signer\Ecdsa\SignatureConverter::class);
        \Yii::$container->setSingleton(BaseJwt\Signer\Ecdsa\SignatureConverter::class, $converter);
        try {
            new Jwt(['signer' => $signerId, 'signingKey' => ' ', 'verifyingKey' => ' ']);
            $this->assertSame($converter, \Yii::$container->get(BaseJwt\Signer\Ecdsa\SignatureConverter::class));
        } finally {
            \Yii::$container->clear(BaseJwt\Signer\Ecdsa\SignatureConverter::class);
        }
    }
}
