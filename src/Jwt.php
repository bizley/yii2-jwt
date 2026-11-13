<?php

declare(strict_types=1);

namespace bizley\jwt;

use Lcobucci\JWT as BaseJwt;
use Psr\Clock\ClockInterface;
use yii\base\InvalidConfigException;
use yii\di\Instance;

/**
 * JSON Web Token implementation based on lcobucci/jwt library v5.
 * @see https://github.com/lcobucci/jwt
 *
 * This implementation is based on the \Lcobucci\JWT\Configuration setup which requires both signing and verifying keys
 * to be defined (the standard way). If you need only some JWT tools, please use \bizley\jwt\JwtTools directly.
 *
 * @author Paweł Bizley Brzozowski <pawel.bizley@gmail.com> since 2.0 (fork)
 * @author Dmitriy Demin <sizemail@gmail.com> original package
 */
class Jwt extends JwtTools
{
    public const HS256 = 'HS256';
    public const HS384 = 'HS384';
    public const HS512 = 'HS512';
    public const RS256 = 'RS256';
    public const RS384 = 'RS384';
    public const RS512 = 'RS512';
    public const ES256 = 'ES256';
    public const ES384 = 'ES384';
    public const ES512 = 'ES512';
    public const EDDSA = 'EdDSA';
    public const BLAKE2B = 'BLAKE2B';

    public const METHOD_PLAIN = 'plain';
    public const METHOD_BASE64 = 'base64';
    public const METHOD_FILE = 'file';

    public const SYMMETRIC = 'symmetric';
    public const ASYMMETRIC = 'asymmetric';

    public const KEY = 'key';
    public const METHOD = 'method';
    public const PASSPHRASE = 'passphrase';
    public const VALID_UNTIL = 'validUntil';

    /**
     * @var string|array<string, string>|BaseJwt\Signer\Key Signing key definition.
     * This can be a simple string, an instance of Key, or a configuration array.
     * The configuration takes the following array keys:
     * - 'key'        => Key's value or path to the key file.
     * - 'method'     => `Jwt::METHOD_PLAIN`, `Jwt::METHOD_BASE64`, or `Jwt::METHOD_FILE` - whether the key is a plain
     *                   text, base64 encoded text, or a file.
     * - 'passphrase' => Key's passphrase.
     * In case a simple string is provided (and it does not start with 'file://' or '@') the following configuration
     * is assumed:
     * [
     *      'key' => // the original given value,
     *      'method' => Jwt::METHOD_PLAIN,
     *      'passphrase' => '',
     * ]
     * In case a simple string is provided, and it does start with 'file://' (direct file path) or '@' (Yii alias)
     * the following configuration is assumed:
     * [
     *      'key' => // the original given value,
     *      'method' => Jwt::METHOD_FILE,
     *      'passphrase' => '',
     * ]
     * If you want to override the assumed configuration, you must provide it directly.
     * @since 3.0.0
     */
    public $signingKey = '';

    /**
     * @var string|array<string, string>|BaseJwt\Signer\Key Verifying key definition.
     * $signingKey documentation you can find above applies here as well.
     * Symmetric algorithms (like HMAC) use a single key to sign and verify tokens so this property is ignored in that
     * case. Asymmetric algorithms (like RSA and ECDSA) use a private key to sign and a public key to verify.
     * @since 3.0.0
     */
    public $verifyingKey = '';

    /**
     * @var string|array<mixed>|BaseJwt\Signer Signer ID, Signer instance, or Signer configuration array (since 4.2.0)
     * to be used for signing/verifying.
     * See $signers for available IDs. Since 4.0.0 it cannot be empty anymore.
     * @since 3.0.0
     */
    public $signer = '';

    /**
     * @var array<string, array<int, string>> Algorithm types.
     * @since 3.0.0
     */
    public array $algorithmTypes = [
        self::SYMMETRIC => [
            self::HS256,
            self::HS384,
            self::HS512,
            self::BLAKE2B,
        ],
        self::ASYMMETRIC => [
            self::RS256,
            self::RS384,
            self::RS512,
            self::ES256,
            self::ES384,
            self::ES512,
            self::EDDSA,
        ],
    ];

    /**
     * @var string|array<string, mixed>|ClockInterface|null PSR-20 clock used by issue() and getSignedWithConstraint().
     * It can be component's ID, configuration array, or instance of ClockInterface.
     * When not set, the system clock in the PHP default time zone is used.
     * @since 4.2.0
     */
    public $clock;

    /**
     * @var string|\DateInterval Lifetime of the tokens issued with issue() - ISO 8601 duration (like 'PT5M' for
     * 5 minutes, 'PT1H' for 1 hour) or DateInterval instance. It sets the expiration time of the token, which can still
     * be changed in the issue() callback.
     * @since 4.2.0
     */
    public $tokenLifetime = 'PT5M';

    /**
     * @var array<mixed> Previous verifying keys that should still be accepted by getSignedWithConstraint() until
     * the specified date - useful for the keys rotation. Each element must be an array with the following keys:
     * - 'key'        => key definition (see $signingKey for the details),
     * - 'validUntil' => date until which the key is accepted, either DateTimeImmutable instance or string that can be
     *                   used to create it (i.e. '2030-01-31 12:00:00', time zone is the PHP default one unless
     *                   specified in the string).
     * Tokens must be signed with the same signer. For symmetric signers provide the previous signing (secret) keys.
     * @since 4.2.0
     */
    public array $previousVerifyingKeys = [];

    private ?BaseJwt\Configuration $configuration = null;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        $signer = $this->buildSigner($this->signer);
        $signerId = \is_string($this->signer) ? $this->signer : $signer->algorithmId();
        if (\in_array($signerId, $this->algorithmTypes[self::SYMMETRIC], true)) {
            $this->configuration = BaseJwt\Configuration::forSymmetricSigner(
                $signer,
                $this->buildKey($this->signingKey),
                $this->prepareEncoder(),
                $this->prepareDecoder()
            );
        } elseif (\in_array($signerId, $this->algorithmTypes[self::ASYMMETRIC], true)) {
            $this->configuration = BaseJwt\Configuration::forAsymmetricSigner(
                $signer,
                $this->buildKey($this->signingKey),
                $this->buildKey($this->verifyingKey),
                $this->prepareEncoder(),
                $this->prepareDecoder()
            );
        } else {
            throw new InvalidConfigException('Invalid signer ID!');
        }
    }

    /**
     * @throws InvalidConfigException
     * @since 3.0.0
     */
    public function getConfiguration(): BaseJwt\Configuration
    {
        if ($this->configuration === null) {
            throw new InvalidConfigException('Configuration has not been set up. Did you call init()?');
        }

        return $this->configuration;
    }

    /**
     * Please note that since 4.0.0 Builder object is immutable.
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/ for details of using the builder.
     * @throws InvalidConfigException
     */
    public function getBuilder(?BaseJwt\ClaimsFormatter $claimFormatter = null): BaseJwt\Builder
    {
        return $this->getConfiguration()->builder($claimFormatter ?? $this->prepareClaimsFormatter());
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/parsing-tokens/ for details of using the parser.
     * @throws InvalidConfigException
     */
    public function getParser(): BaseJwt\Parser
    {
        return $this->getConfiguration()->parser();
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/stable/validating-tokens/ for details of using the validator.
     * @throws InvalidConfigException
     */
    public function getValidator(): BaseJwt\Validator
    {
        return $this->getConfiguration()->validator();
    }

    /**
     * Constraints set directly in the Lcobucci configuration (with
     * `Yii::$app->jwt->getConfiguration()->setValidationConstraints(...)`) take precedence over the component's
     * constraints. This way of providing constraints is deprecated since 4.2.0 (the Lcobucci method itself is
     * deprecated since lcobucci/jwt 5.5) and will be removed in 5.0.0 - use setValidationConstraints() or
     * $validationConstraints of this component instead.
     * @deprecated since 4.2.0 This override exists only to support constraints set in the Lcobucci configuration and
     * will be removed in 5.0.0 together with that support; JwtTools::prepareValidationConstraints() will be used.
     * @return BaseJwt\Validation\Constraint[]
     * @throws InvalidConfigException
     */
    protected function prepareValidationConstraints(): array
    {
        $configuredConstraints = $this->getConfiguration()->validationConstraints();
        if (!empty($configuredConstraints)) {
            \Yii::warning(
                'Providing validation constraints with Lcobucci\JWT\Configuration::setValidationConstraints() is deprecated since 4.2.0 and will be removed in 5.0.0. Use bizley\jwt\Jwt::setValidationConstraints() or the "validationConstraints" property instead.',
                self::class
            );

            return $configuredConstraints;
        }

        return parent::prepareValidationConstraints();
    }

    /**
     * Issues new token signed with the configured signer and signing key.
     * The token has already set the issue time (iat) and the time it can be used from (nbf) to the current time, and
     * the expiration time (exp) to the current time + $tokenLifetime. The callback can add more claims and headers, and
     * change the preset ones. Its signature is
     * `function (\Lcobucci\JWT\Builder $builder, \DateTimeImmutable $now): \Lcobucci\JWT\Builder`
     * where $now is the current time taken from $clock.
     * @param \Closure(BaseJwt\Builder, \DateTimeImmutable): BaseJwt\Builder $customiseBuilder
     * @throws InvalidConfigException
     * @since 4.2.0
     */
    public function issue(\Closure $customiseBuilder): BaseJwt\UnencryptedToken
    {
        $configuration = $this->getConfiguration();
        $now = $this->prepareClock()->now();
        $builder = $this->getBuilder()
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->add($this->prepareTokenLifetime()));

        return $customiseBuilder($builder, $now)->getToken($configuration->signer(), $configuration->signingKey());
    }

    /**
     * Returns the constraint that verifies the token's signature with the configured signer and verifying key.
     * When $previousVerifyingKeys are set, the returned constraint also accepts tokens signed with these keys until
     * their validity dates pass.
     * @throws InvalidConfigException
     * @since 4.2.0
     */
    public function getSignedWithConstraint(): BaseJwt\Validation\SignedWith
    {
        $configuration = $this->getConfiguration();
        if ($this->previousVerifyingKeys === []) {
            return new BaseJwt\Validation\Constraint\SignedWith(
                $configuration->signer(),
                $configuration->verificationKey()
            );
        }

        $clock = $this->prepareClock();
        $constraints = [
            new BaseJwt\Validation\Constraint\SignedWithUntilDate(
                $configuration->signer(),
                $configuration->verificationKey(),
                new \DateTimeImmutable('9999-12-31 23:59:59'),
                $clock
            ),
        ];
        foreach ($this->previousVerifyingKeys as $previousKey) {
            if (
                !\is_array($previousKey)
                || !\array_key_exists(self::KEY, $previousKey)
                || !\array_key_exists(self::VALID_UNTIL, $previousKey)
            ) {
                throw new InvalidConfigException(
                    'Previous verifying key must be an array with "key" and "validUntil" elements!'
                );
            }
            /** @var string|array<string, mixed>|BaseJwt\Signer\Key $keyDefinition */
            $keyDefinition = $previousKey[self::KEY];
            $constraints[] = new BaseJwt\Validation\Constraint\SignedWithUntilDate(
                $configuration->signer(),
                $this->buildKey($keyDefinition),
                $this->prepareValidUntil($previousKey[self::VALID_UNTIL]),
                $clock
            );
        }

        return new BaseJwt\Validation\Constraint\SignedWithOneInSet(...$constraints);
    }

    private ?ClockInterface $builtClock = null;

    /**
     * @throws InvalidConfigException
     * @since 4.2.0
     */
    private function prepareClock(): ClockInterface
    {
        if ($this->builtClock === null) {
            if ($this->clock === null) {
                $this->builtClock = new class () implements ClockInterface {
                    public function now(): \DateTimeImmutable
                    {
                        return new \DateTimeImmutable();
                    }
                };
            } else {
                /** @var ClockInterface $clock */
                $clock = Instance::ensure($this->clock, ClockInterface::class);
                $this->builtClock = $clock;
            }
        }

        return $this->builtClock;
    }

    /**
     * @throws InvalidConfigException
     */
    private function prepareTokenLifetime(): \DateInterval
    {
        if ($this->tokenLifetime instanceof \DateInterval) {
            return $this->tokenLifetime;
        }

        try {
            return new \DateInterval($this->tokenLifetime);
        } catch (\Throwable $exception) {
            throw new InvalidConfigException('Invalid token lifetime!', previous: $exception);
        }
    }

    /**
     * @throws InvalidConfigException
     */
    private function prepareValidUntil(mixed $validUntil): \DateTimeImmutable
    {
        if ($validUntil instanceof \DateTimeImmutable) {
            return $validUntil;
        }

        if (\is_string($validUntil) && $validUntil !== '') {
            try {
                return new \DateTimeImmutable($validUntil);
            } catch (\Throwable $exception) {
                throw new InvalidConfigException('Invalid previous verifying key validity date!', previous: $exception);
            }
        }

        throw new InvalidConfigException('Invalid previous verifying key validity date!');
    }
}
