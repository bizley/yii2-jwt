<?php

declare(strict_types=1);

namespace bizley\tests\standard;

use bizley\jwt\Jwt;
use bizley\jwt\JwtTools;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\SignedWithOneInSet;
use PHPUnit\Framework\Attributes;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;

#[Attributes\CoversClass(Jwt::class)]
#[Attributes\CoversClass(JwtTools::class)]
class IssueTest extends TestCase
{
    private const CURRENT_SECRET = 'current-secret-current-secret-current-secret';
    private const PREVIOUS_SECRET = 'previous-secret-previous-secret-previous-secret';

    private function getJwt(array $config = []): Jwt
    {
        return new Jwt(
            \array_merge(
                [
                    'signer' => Jwt::HS256,
                    'signingKey' => self::CURRENT_SECRET,
                ],
                $config
            )
        );
    }

    private function getPayload(string $token): array
    {
        $parts = \explode('.', $token);

        return \json_decode(\base64_decode(\strtr($parts[1], '-_', '+/')), true, 512, \JSON_THROW_ON_ERROR);
    }

    #[Attributes\Test]
    public function issueWithDefaults(): void
    {
        $now = new \DateTimeImmutable('2024-01-01 12:00:00', new \DateTimeZone('UTC'));
        $jwt = $this->getJwt(['clock' => new FrozenClock($now)]);
        $token = $jwt->issue(static fn (Builder $builder): Builder => $builder->withClaim('uid', 5));

        self::assertEquals($now, $token->claims()->get('iat'));
        self::assertEquals($now, $token->claims()->get('nbf'));
        self::assertEquals($now->modify('+5 minutes'), $token->claims()->get('exp'));
        self::assertSame(5, $token->claims()->get('uid'));
        self::assertTrue(
            $jwt->getValidator()->validate($jwt->parse($token->toString()), $jwt->getSignedWithConstraint())
        );
    }

    #[Attributes\Test]
    public function issueCallbackReceivesClockTime(): void
    {
        $now = new \DateTimeImmutable('2024-01-01 12:00:00', new \DateTimeZone('UTC'));
        $jwt = $this->getJwt(['clock' => new FrozenClock($now)]);
        $received = null;
        $jwt->issue(static function (Builder $builder, \DateTimeImmutable $time) use (&$received): Builder {
            $received = $time;

            return $builder;
        });

        self::assertSame($now, $received);
    }

    #[Attributes\Test]
    public function issueCallbackCanOverrideExpiration(): void
    {
        $now = new \DateTimeImmutable('2024-01-01 12:00:00', new \DateTimeZone('UTC'));
        $jwt = $this->getJwt(['clock' => new FrozenClock($now)]);
        $token = $jwt->issue(
            static fn (Builder $builder, \DateTimeImmutable $now): Builder => $builder->expiresAt($now->modify('+1 day'))
        );

        self::assertEquals($now->modify('+1 day'), $token->claims()->get('exp'));
    }

    public static function providerForTokenLifetime(): iterable
    {
        yield 'ISO 8601 string' => ['PT1H'];
        yield 'DateInterval' => [new \DateInterval('PT1H')];
    }

    #[Attributes\DataProvider('providerForTokenLifetime')]
    #[Attributes\Test]
    public function issueWithCustomLifetime(string|\DateInterval $lifetime): void
    {
        $now = new \DateTimeImmutable('2024-01-01 12:00:00', new \DateTimeZone('UTC'));
        $jwt = $this->getJwt(['clock' => new FrozenClock($now), 'tokenLifetime' => $lifetime]);
        $token = $jwt->issue(static fn (Builder $builder): Builder => $builder);

        self::assertEquals($now->modify('+1 hour'), $token->claims()->get('exp'));
    }

    public static function providerForInvalidTokenLifetime(): iterable
    {
        yield 'invalid string' => ['5 minutes'];
        yield 'int' => [300];
    }

    #[Attributes\DataProvider('providerForInvalidTokenLifetime')]
    #[Attributes\Test]
    public function issueWithInvalidLifetime(mixed $lifetime): void
    {
        $jwt = $this->getJwt(['tokenLifetime' => $lifetime]);

        try {
            $jwt->issue(static fn (Builder $builder): Builder => $builder);
            self::fail('Exception has not been thrown.');
        } catch (InvalidConfigException $exception) {
            self::assertSame('Invalid token lifetime!', $exception->getMessage());
            self::assertInstanceOf(\Throwable::class, $exception->getPrevious());
        }
    }

    #[Attributes\Test]
    public function issueWithSystemClock(): void
    {
        $before = new \DateTimeImmutable('-1 second');
        $token = $this->getJwt()->issue(static fn (Builder $builder): Builder => $builder);
        $after = new \DateTimeImmutable('+1 second');

        $issuedAt = $token->claims()->get('iat');
        self::assertGreaterThanOrEqual($before, $issuedAt);
        self::assertLessThanOrEqual($after, $issuedAt);
    }

    #[Attributes\Test]
    public function clockIsResolvedOnce(): void
    {
        $jwt = $this->getJwt(
            ['clock' => new FrozenClock(new \DateTimeImmutable('2024-01-01 12:00:00', new \DateTimeZone('UTC')))]
        );
        $first = $jwt->issue(static fn (Builder $builder): Builder => $builder);
        $jwt->clock = new FrozenClock(new \DateTimeImmutable('2025-01-01 12:00:00', new \DateTimeZone('UTC')));
        $second = $jwt->issue(static fn (Builder $builder): Builder => $builder);

        self::assertEquals($first->claims()->get('iat'), $second->claims()->get('iat'));
    }

    #[Attributes\Test]
    public function issueUsesConfiguredClaimsFormatter(): void
    {
        $now = new \DateTimeImmutable('2024-01-01 12:00:00.5', new \DateTimeZone('UTC'));
        $jwt = $this->getJwt(
            [
                'clock' => new FrozenClock($now),
                'claimsFormatter' => ChainedFormatter::withUnixTimestampDates(),
            ]
        );

        self::assertSame(
            1704110400,
            $this->getPayload($jwt->issue(static fn (Builder $builder): Builder => $builder)->toString())['iat']
        );
    }

    #[Attributes\Test]
    public function signedWithConstraintWithoutPreviousKeys(): void
    {
        $constraint = $this->getJwt()->getSignedWithConstraint();
        self::assertInstanceOf(SignedWith::class, $constraint);
    }

    private function tokenSignedWith(Jwt $jwt, string $secret): string
    {
        return $jwt->getBuilder()->getToken(
            $jwt->getConfiguration()->signer(),
            InMemory::plainText($secret)
        )->toString();
    }

    public static function providerForValidUntil(): iterable
    {
        yield 'string' => ['2024-01-10 00:00:00 UTC'];
        yield 'DateTimeImmutable' => [new \DateTimeImmutable('2024-01-10 00:00:00', new \DateTimeZone('UTC'))];
    }

    #[Attributes\DataProvider('providerForValidUntil')]
    #[Attributes\Test]
    public function previousKeyIsAcceptedUntilItsDate(string|\DateTimeImmutable $validUntil): void
    {
        $clock = new FrozenClock(new \DateTimeImmutable('2024-01-05 00:00:00', new \DateTimeZone('UTC')));
        $jwt = $this->getJwt(
            [
                'clock' => $clock,
                'previousVerifyingKeys' => [
                    [Jwt::KEY => self::PREVIOUS_SECRET, Jwt::VALID_UNTIL => $validUntil],
                ],
            ]
        );

        $constraint = $jwt->getSignedWithConstraint();
        self::assertInstanceOf(SignedWithOneInSet::class, $constraint);

        $validator = $jwt->getValidator();
        self::assertTrue($validator->validate($jwt->parse($this->tokenSignedWith($jwt, self::CURRENT_SECRET)), $constraint));
        self::assertTrue($validator->validate($jwt->parse($this->tokenSignedWith($jwt, self::PREVIOUS_SECRET)), $constraint));
        self::assertFalse(
            $validator->validate($jwt->parse($this->tokenSignedWith($jwt, 'unknown-secret-unknown-secret-unknown')), $constraint)
        );

        $clock->setTo(new \DateTimeImmutable('2024-01-11 00:00:00', new \DateTimeZone('UTC')));
        self::assertTrue($validator->validate($jwt->parse($this->tokenSignedWith($jwt, self::CURRENT_SECRET)), $constraint));
        self::assertFalse($validator->validate($jwt->parse($this->tokenSignedWith($jwt, self::PREVIOUS_SECRET)), $constraint));
    }

    #[Attributes\Test]
    public function multiplePreviousKeys(): void
    {
        $clock = new FrozenClock(new \DateTimeImmutable('2024-01-05 00:00:00', new \DateTimeZone('UTC')));
        $older = 'older-secret-older-secret-older-secret-older';
        $jwt = $this->getJwt(
            [
                'clock' => $clock,
                'previousVerifyingKeys' => [
                    [Jwt::KEY => self::PREVIOUS_SECRET, Jwt::VALID_UNTIL => '2024-01-10 00:00:00 UTC'],
                    [Jwt::KEY => [Jwt::KEY => $older], Jwt::VALID_UNTIL => '2024-01-08 00:00:00 UTC'],
                ],
            ]
        );
        $constraint = $jwt->getSignedWithConstraint();
        $validator = $jwt->getValidator();

        self::assertTrue($validator->validate($jwt->parse($this->tokenSignedWith($jwt, $older)), $constraint));
        $clock->setTo(new \DateTimeImmutable('2024-01-09 00:00:00', new \DateTimeZone('UTC')));
        self::assertFalse($validator->validate($jwt->parse($this->tokenSignedWith($jwt, $older)), $constraint));
        self::assertTrue($validator->validate($jwt->parse($this->tokenSignedWith($jwt, self::PREVIOUS_SECRET)), $constraint));
    }

    #[Attributes\Test]
    public function previousKeyForAsymmetricSigner(): void
    {
        $previous = new Jwt(
            [
                'signer' => Jwt::RS256,
                'signingKey' => '@bizley/tests/data/rs384.key',
                'verifyingKey' => '@bizley/tests/data/rs384.key.pub',
            ]
        );
        $oldToken = $previous->issue(static fn (Builder $builder): Builder => $builder)->toString();

        $jwt = new Jwt(
            [
                'signer' => Jwt::RS256,
                'signingKey' => '@bizley/tests/data/rs256.key',
                'verifyingKey' => '@bizley/tests/data/rs256.key.pub',
                'previousVerifyingKeys' => [
                    [Jwt::KEY => '@bizley/tests/data/rs384.key.pub', Jwt::VALID_UNTIL => '+1 day'],
                ],
            ]
        );
        $newToken = $jwt->issue(static fn (Builder $builder): Builder => $builder)->toString();

        $constraint = $jwt->getSignedWithConstraint();
        self::assertTrue($jwt->getValidator()->validate($jwt->parse($oldToken), $constraint));
        self::assertTrue($jwt->getValidator()->validate($jwt->parse($newToken), $constraint));
    }

    public static function providerForInvalidPreviousKeys(): iterable
    {
        $message = 'Previous verifying key must be an array with "key" and "validUntil" elements!';
        yield 'not array' => ['key', $message];
        yield 'no key' => [[Jwt::VALID_UNTIL => '+1 day'], $message];
        yield 'no validUntil' => [[Jwt::KEY => self::PREVIOUS_SECRET], $message];
        $dateMessage = 'Invalid previous verifying key validity date!';
        yield 'invalid date string' => [[Jwt::KEY => self::PREVIOUS_SECRET, Jwt::VALID_UNTIL => 'not a date'], $dateMessage];
        yield 'empty date string' => [[Jwt::KEY => self::PREVIOUS_SECRET, Jwt::VALID_UNTIL => ''], $dateMessage];
        yield 'int date' => [[Jwt::KEY => self::PREVIOUS_SECRET, Jwt::VALID_UNTIL => 1704067200], $dateMessage];
        yield 'mutable date' => [[Jwt::KEY => self::PREVIOUS_SECRET, Jwt::VALID_UNTIL => new \DateTime()], $dateMessage];
        yield 'invalid key' => [[Jwt::KEY => '', Jwt::VALID_UNTIL => '+1 day'], 'Empty string used as a key configuration!'];
    }

    #[Attributes\DataProvider('providerForInvalidPreviousKeys')]
    #[Attributes\Test]
    public function invalidPreviousKey(mixed $previousKey, string $message): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage($message);
        $this->getJwt(['previousVerifyingKeys' => [$previousKey]])->getSignedWithConstraint();
    }

    #[Attributes\Test]
    public function invalidDateStringKeepsPreviousException(): void
    {
        try {
            $this->getJwt(
                ['previousVerifyingKeys' => [[Jwt::KEY => self::PREVIOUS_SECRET, Jwt::VALID_UNTIL => 'not a date']]]
            )->getSignedWithConstraint();
            self::fail('Exception has not been thrown.');
        } catch (InvalidConfigException $exception) {
            self::assertInstanceOf(\Throwable::class, $exception->getPrevious());
        }
    }
}
