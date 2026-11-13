<?php

declare(strict_types=1);

namespace bizley\tests\toolset;

use bizley\jwt\Jwt;
use bizley\jwt\JwtTools;
use Lcobucci\JWT as BaseJwt;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;

#[Attributes\CoversClass(Jwt::class)]
#[Attributes\CoversClass(JwtTools::class)]
class JwtToolsTest extends TestCase
{
    private function getJwt(): JwtTools
    {
        return new JwtTools();
    }

    #[Attributes\Test]
    public function availableSigners(): void
    {
        self::assertSame(
            [
                Jwt::HS256 => [BaseJwt\Signer\Hmac\Sha256::class],
                Jwt::HS384 => [BaseJwt\Signer\Hmac\Sha384::class],
                Jwt::HS512 => [BaseJwt\Signer\Hmac\Sha512::class],
                Jwt::RS256 => [BaseJwt\Signer\Rsa\Sha256::class],
                Jwt::RS384 => [BaseJwt\Signer\Rsa\Sha384::class],
                Jwt::RS512 => [BaseJwt\Signer\Rsa\Sha512::class],
                Jwt::ES256 => [BaseJwt\Signer\Ecdsa\Sha256::class],
                Jwt::ES384 => [BaseJwt\Signer\Ecdsa\Sha384::class],
                Jwt::ES512 => [BaseJwt\Signer\Ecdsa\Sha512::class],
                Jwt::EDDSA => [BaseJwt\Signer\Eddsa::class],
                Jwt::BLAKE2B => [BaseJwt\Signer\Blake2b::class],
            ],
            $this->getJwt()->signers,
        );
    }

    #[Attributes\Test]
    public function validateSuccess(): void
    {
        $jwt = $this->getJwt();
        $jwt->validationConstraints = [new IdentifiedBy('abc')];
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
        self::assertTrue($jwt->validate($token));
    }

    #[Attributes\Test]
    public function validateSuccessWithStringToken(): void
    {
        $jwt = $this->getJwt();
        $jwt->validationConstraints = [new IdentifiedBy('abc')];
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        )->toString();
        self::assertTrue($jwt->validate($token));
    }

    #[Attributes\Test]
    public function validateFail(): void
    {
        $jwt = $this->getJwt();
        $jwt->validationConstraints = [new IdentifiedBy('abc')];
        $token = $jwt->getBuilder()->identifiedBy('def')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
        self::assertFalse($jwt->validate($token));
    }

    #[Attributes\DoesNotPerformAssertions]
    #[Attributes\Test]
    public function assertSuccess(): void
    {
        $jwt = $this->getJwt();
        $jwt->validationConstraints = [new IdentifiedBy('abc')];
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
        $jwt->assert($token);
    }

    #[Attributes\DoesNotPerformAssertions]
    #[Attributes\Test]
    public function assertSuccessWithStringToken(): void
    {
        $jwt = $this->getJwt();
        $jwt->validationConstraints = [new IdentifiedBy('abc')];
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        )->toString();
        $jwt->assert($token);
    }

    #[Attributes\Test]
    public function assertFail(): void
    {
        $jwt = $this->getJwt();
        $jwt->validationConstraints = [new IdentifiedBy('abc')];
        $token = $jwt->getBuilder()->identifiedBy('def')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
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
        yield 'empty alias' => [[Jwt::KEY => '@emptyString'], 'Yii alias was resolved as an invalid key value!'];
    }

    #[Attributes\DataProvider('providerForInvalidKey')]
    #[Attributes\Test]
    public function invalidKey($key, string $message): void
    {
        $this->expectExceptionMessage($message);
        \Yii::setAlias('@emptyString', '');
        (new JwtTools())->buildKey($key);
    }

    #[Attributes\Test]
    public function customEncoder(): void
    {
        $encoder = $this->createMock(BaseJwt\Encoder::class);
        $encoder->expects($this->exactly(3))->method('base64UrlEncode');

        $jwt = new JwtTools(['encoder' => $encoder]);
        $jwt->getBuilder()->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
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
                $jwt->buildSigner(Jwt::HS256),
                $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
            )->toString()
        );
    }

    #[Attributes\Test]
    public function methodsVisibility(): void
    {
        $jwt = $this->getJwt();
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
        \Yii::$container->clear(BaseJwt\Signer\Ecdsa\SignatureConverter::class);
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
            $this->getJwt()->buildSigner($signerId);
            $this->assertSame($converter, \Yii::$container->get(BaseJwt\Signer\Ecdsa\SignatureConverter::class));
        } finally {
            \Yii::$container->clear(BaseJwt\Signer\Ecdsa\SignatureConverter::class);
        }
    }

    public static function providerForSignerConfigurationArrays(): iterable
    {
        yield 'type with params' => [[BaseJwt\Signer\Hmac\Sha384::class], BaseJwt\Signer\Hmac\Sha384::class];
        yield 'Yii-style' => [['class' => BaseJwt\Signer\Hmac\Sha512::class], BaseJwt\Signer\Hmac\Sha512::class];
        yield 'ECDSA' => [[BaseJwt\Signer\Ecdsa\Sha256::class], BaseJwt\Signer\Ecdsa\Sha256::class];
    }

    #[Attributes\DataProvider('providerForSignerConfigurationArrays')]
    #[Attributes\Test]
    public function signerFromConfigurationArray(array $config, string $expectedClass): void
    {
        \Yii::$container->clear(BaseJwt\Signer\Ecdsa\SignatureConverter::class);
        self::assertInstanceOf($expectedClass, $this->getJwt()->buildSigner($config));
    }

    #[Attributes\Test]
    public function signerConfigurationArrayNotResolvingToSigner(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Signer configuration must resolve to an instance of Lcobucci\JWT\Signer!');
        $this->getJwt()->buildSigner([\stdClass::class]);
    }

    #[Attributes\Test]
    public function invalidSignerType(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Invalid signer ID!');
        $this->getJwt()->buildSigner(1);
    }

    #[Attributes\Test]
    public function setValidationConstraintsReplacesConstraints(): void
    {
        $jwt = $this->getJwt();
        $jwt->validationConstraints = [new IdentifiedBy('def')];
        $constraint = new IdentifiedBy('abc');
        $jwt->setValidationConstraints($constraint);
        self::assertSame([$constraint], $jwt->validationConstraints);

        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
        self::assertTrue($jwt->validate($token));
    }

    private function issuedAtFromToken(JwtTools $jwt, ?BaseJwt\ClaimsFormatter $formatter = null): mixed
    {
        $token = $jwt->getBuilder($formatter)
            ->issuedAt(new \DateTimeImmutable('2024-01-01 12:00:00.5', new \DateTimeZone('UTC')))
            ->getToken(
                $jwt->buildSigner(Jwt::HS256),
                $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
            )
            ->toString();

        return \json_decode(
            \base64_decode(\strtr(\explode('.', $token)[1], '-_', '+/')),
            true,
            512,
            \JSON_THROW_ON_ERROR
        )['iat'];
    }

    #[Attributes\Test]
    public function defaultClaimsFormatterUsesMicroseconds(): void
    {
        self::assertSame(1704110400.5, $this->issuedAtFromToken($this->getJwt()));
    }

    public static function providerForClaimsFormatterConfig(): iterable
    {
        yield 'instance' => [BaseJwt\Encoding\ChainedFormatter::withUnixTimestampDates()];
        yield 'configuration array' => [['class' => BaseJwt\Encoding\UnixTimestampDates::class]];
    }

    #[Attributes\DataProvider('providerForClaimsFormatterConfig')]
    #[Attributes\Test]
    public function configuredClaimsFormatter(BaseJwt\ClaimsFormatter|array $formatter): void
    {
        $toolset = new JwtTools(['claimsFormatter' => $formatter]);
        self::assertSame(1704110400, $this->issuedAtFromToken($toolset));

        $standard = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M',
                'claimsFormatter' => $formatter,
            ]
        );
        self::assertSame(1704110400, $this->issuedAtFromToken($standard));
    }

    #[Attributes\Test]
    public function claimsFormatterPassedDirectlyTakesPrecedence(): void
    {
        $config = ['claimsFormatter' => BaseJwt\Encoding\ChainedFormatter::withUnixTimestampDates()];
        $default = BaseJwt\Encoding\ChainedFormatter::default();

        self::assertSame(1704110400.5, $this->issuedAtFromToken(new JwtTools($config), $default));
        self::assertSame(
            1704110400.5,
            $this->issuedAtFromToken(
                new Jwt(
                    \array_merge(
                        $config,
                        ['signer' => Jwt::HS256, 'signingKey' => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M']
                    )
                ),
                $default
            )
        );
    }

    #[Attributes\Test]
    public function claimsFormatterIsResolvedOnce(): void
    {
        $jwt = new JwtTools(['claimsFormatter' => BaseJwt\Encoding\ChainedFormatter::withUnixTimestampDates()]);
        $this->issuedAtFromToken($jwt);
        $jwt->claimsFormatter = BaseJwt\Encoding\ChainedFormatter::default();
        self::assertSame(1704110400, $this->issuedAtFromToken($jwt));
    }

    #[Attributes\Test]
    public function builderWithCustomClaimsFormatter(): void
    {
        $formatter = $this->createMock(BaseJwt\ClaimsFormatter::class);
        $formatter->expects($this->once())->method('formatClaims');
        $this->getJwt()->getBuilder($formatter)->getToken(
            $this->getJwt()->buildSigner(Jwt::HS256),
            $this->getJwt()->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
    }
}
