<?php

declare(strict_types=1);

namespace bizley\tests\standard;

use bizley\jwt\Jwt;
use bizley\jwt\JwtTools;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\Attributes;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;

#[Attributes\CoversClass(Jwt::class)]
#[Attributes\CoversClass(JwtTools::class)]
class SignerTest extends TestCase
{
    public function getJwt(array $config = []): Jwt
    {
        /** @var Jwt $jwt */
        $jwt = \Yii::createObject(
            \array_merge(
                ['class' => Jwt::class],
                $config
            )
        );

        return $jwt;
    }

    public static function providerForSigners(): iterable
    {
        yield 'Direct signer provided' => [
            [
                'signer' => new Sha256(),
                'signingKey' => 'secret1secret1secret1secret1secret1secret1',
            ],
            Jwt::HS256
        ];
        yield 'Direct key provided' => [
            [
                'signer' => Jwt::HS256,
                'signingKey' => InMemory::plainText('secret1secret1secret1secret1secret1secret1')
            ],
            Jwt::HS256
        ];
        yield 'HS256' => [
            [
                'signer' => Jwt::HS256,
                'signingKey' => 'secret1secret1secret1secret1secret1secret1',
            ],
            Jwt::HS256
        ];
        yield 'Signer configuration array' => [
            [
                'signer' => [Sha256::class],
                'signingKey' => 'secret1secret1secret1secret1secret1secret1',
            ],
            Jwt::HS256
        ];
        yield 'Signer Yii-style configuration array' => [
            [
                'signer' => ['class' => Sha256::class],
                'signingKey' => 'secret1secret1secret1secret1secret1secret1',
            ],
            Jwt::HS256
        ];
        yield 'BLAKE2B (symmetric, no verifying key)' => [
            [
                'signer' => Jwt::BLAKE2B,
                'signingKey' => 'secret1secret1secret1secret1secret1secret1',
            ],
            Jwt::BLAKE2B
        ];
        yield 'ES256 configuration array' => [
            [
                'signer' => [EcdsaSha256::class],
                'signingKey' => '@bizley/tests/data/es256.key',
                'verifyingKey' => '@bizley/tests/data/es256.key.pub',
            ],
            Jwt::ES256
        ];
        yield 'HS256 base64' => [
            [
                'signer' => Jwt::HS256,
                'signingKey' => [
                    Jwt::KEY => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0MXNlY3JldDFzZWNyZXQx',
                    Jwt::METHOD => JWT::METHOD_BASE64
                ],
            ],
            Jwt::HS256
        ];
        yield 'HS384' => [
            [
                'signer' => Jwt::HS384,
                'signingKey' => 'secret1secret1secret1secret1secret1secret1secret1',
            ],
            Jwt::HS384
        ];
        yield 'HS512' => [
            [
                'signer' => Jwt::HS512,
                'signingKey' => 'secret1secret1secret1secret1secret1secret1secret1secret1secret1secret1',
            ],
            Jwt::HS512
        ];
        yield 'HS256 pass' => [
            [
                'signer' => Jwt::HS256,
                'signingKey' => [
                    Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1',
                    Jwt::PASSPHRASE => 'passphrase'
                ],
            ],
            Jwt::HS256
        ];
        yield 'HS384 pass' => [
            [
                'signer' => Jwt::HS384,
                'signingKey' => [
                    Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1',
                    Jwt::PASSPHRASE => 'passphrase'
                ],
            ],
            Jwt::HS384
        ];
        yield 'HS512 pass' => [
            [
                'signer' => Jwt::HS512,
                'signingKey' => [
                    Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1secret1secret1secret1',
                    Jwt::PASSPHRASE => 'passphrase'
                ],
            ],
            Jwt::HS512
        ];
        yield 'RS256' => [
            [
                'signer' => Jwt::RS256,
                'signingKey' => '@bizley/tests/data/rs256.key',
                'verifyingKey' => '@bizley/tests/data/rs256.key.pub',
            ],
            Jwt::RS256
        ];
        yield 'RS256 with file handler' => [
            [
                'signer' => Jwt::RS256,
                'signingKey' => 'file://' . __DIR__ . '/../data/rs256.key',
                'verifyingKey' => 'file://' . __DIR__ . '/../data/rs256.key.pub',
            ],
            Jwt::RS256
        ];
        yield 'RS256 with in-memory file' => [
            [
                'signer' => Jwt::RS256,
                'signingKey' => [
                    Jwt::KEY => 'file://' . __DIR__ . '/../data/rs256.key',
                    Jwt::METHOD => Jwt::METHOD_FILE,
                ],
                'verifyingKey' => 'file://' . __DIR__ . '/../data/rs256.key.pub',
            ],
            Jwt::RS256
        ];
        yield 'RS384' => [
            [
                'signer' => Jwt::RS384,
                'signingKey' => '@bizley/tests/data/rs384.key',
                'verifyingKey' => '@bizley/tests/data/rs384.key.pub',
            ],
            Jwt::RS384
        ];
        yield 'RS512' => [
            [
                'signer' => Jwt::RS512,
                'signingKey' => '@bizley/tests/data/rs512.key',
                'verifyingKey' => '@bizley/tests/data/rs512.key.pub',
            ],
            Jwt::RS512
        ];
        yield 'ES256' => [
            [
                'signer' => Jwt::ES256,
                'signingKey' => '@bizley/tests/data/es256.key',
                'verifyingKey' => '@bizley/tests/data/es256.key.pub',
            ],
            Jwt::ES256
        ];
        yield 'ES384' => [
            [
                'signer' => Jwt::ES384,
                'signingKey' => '@bizley/tests/data/es384.key',
                'verifyingKey' => '@bizley/tests/data/es384.key.pub',
            ],
            Jwt::ES384
        ];
        yield 'ES512' => [
            [
                'signer' => Jwt::ES512,
                'signingKey' => '@bizley/tests/data/es512.key',
                'verifyingKey' => '@bizley/tests/data/es512.key.pub',
            ],
            Jwt::ES512
        ];
        yield 'OpenSSL3 ES256' => [
            [
                'signer' => Jwt::ES256,
                'signingKey' => '@bizley/tests/data/es256.openssl3.private.pem',
                'verifyingKey' => '@bizley/tests/data/es256.openssl3.public.pem',
            ],
            Jwt::ES256
        ];
    }

    #[Attributes\DataProvider('providerForSigners')]
    #[Attributes\Test]
    public function parseTokenWithSignature(array $config, string $algorithm): void
    {
        $jwt = $this->getJwt($config);
        $signer = $jwt->getConfiguration()->signer();
        $token = $jwt->getBuilder()->getToken($signer, $jwt->getConfiguration()->signingKey());
        $tokenParsed = $jwt->parse($token->toString());
        self::assertSame('JWT', $tokenParsed->headers()->get('typ'));
        self::assertSame($algorithm, $tokenParsed->headers()->get('alg'));

        self::assertTrue($jwt->getConfiguration()->validator()->validate(
            $tokenParsed,
            new SignedWith($signer, $jwt->getConfiguration()->verificationKey()))
        );
    }

    #[Attributes\Test]
    public function invalidSignerId(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Invalid signer ID!');
        $this->getJwt(['signer' => 'Invalid']);
    }

    #[Attributes\Test]
    public function customSignerIdIsCheckedAgainstAlgorithmTypes(): void
    {
        $jwt = $this->getJwt(
            [
                'signers' => ['custom' => [Sha256::class]],
                'algorithmTypes' => [Jwt::SYMMETRIC => ['custom'], Jwt::ASYMMETRIC => []],
                'signer' => 'custom',
                'signingKey' => 'secret1secret1secret1secret1secret1secret1',
            ]
        );
        self::assertInstanceOf(Sha256::class, $jwt->getConfiguration()->signer());
    }

    #[Attributes\Test]
    public function signerConfigurationArrayWithUnknownAlgorithm(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Invalid signer ID!');
        $this->getJwt(
            [
                'algorithmTypes' => [Jwt::SYMMETRIC => [], Jwt::ASYMMETRIC => []],
                'signer' => [Sha256::class],
                'signingKey' => 'secret1secret1secret1secret1secret1secret1',
            ]
        );
    }

    #[Attributes\Test]
    public function emptyKey(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Empty string used as a key configuration!');
        $this->getJwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => '',
            ]
        );
    }

    #[Attributes\Test]
    public function invalidKeyWithNotEnoughBits(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 256 bits, only 56 bits provided');
        $jwt = $this->getJwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => 'secret1',
            ]
        );
        $signer = $jwt->getConfiguration()->signer();
        $token = $jwt->getBuilder()->getToken($signer, $jwt->getConfiguration()->signingKey());
        $jwt->parse($token->toString());
    }
}
