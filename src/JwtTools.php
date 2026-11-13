<?php

declare(strict_types=1);

namespace bizley\jwt;

use Lcobucci\JWT as BaseJwt;
use Lcobucci\JWT\Encoding;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

/**
 * JSON Web Token implementation based on lcobucci/jwt library v5.
 * @see https://github.com/lcobucci/jwt
 *
 * This implementation allows developer to pick & choose JWT tools to use for example in order to only validate
 * a token (without issuing it first, so signing key does not need to be defined).
 *
 * @author Paweł Bizley Brzozowski <pawel.bizley@gmail.com>
 * @since 4.1.0
 */
class JwtTools extends Component
{
    /**
     * @var array<string, string[]> Default signers configuration. When instantiated it will use selected array to
     * spread into `Yii::createObject($type, array $params = [])` method so the first array element is $type, and
     * the second is $params.
     */
    public array $signers = [
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
    ];

    /**
     * @var string|array<string, mixed>|BaseJwt\Encoder|null Custom encoder.
     * It can be component's ID, configuration array, or instance of Encoder.
     * In case it's not an instance, it must be resolvable to an Encoder's instance.
     */
    public $encoder;

    /**
     * @var string|array<string, mixed>|BaseJwt\Decoder|null Custom decoder.
     * It can be component's ID, configuration array, or instance of Decoder.
     * In case it's not an instance, it must be resolvable to a Decoder's instance.
     */
    public $decoder;

    /**
     * @var string|array<string, mixed>|BaseJwt\ClaimsFormatter|null Custom claims formatter used by getBuilder() when
     * no formatter is passed to it directly.
     * It can be component's ID, configuration array, or instance of ClaimsFormatter.
     * When not set, Lcobucci\JWT\Encoding\ChainedFormatter::default() is used which stores dates (iat, nbf, exp) as
     * numbers with microseconds. Use Lcobucci\JWT\Encoding\ChainedFormatter::withUnixTimestampDates() to store them as
     * integer UNIX timestamps (better interoperability with other JWT libraries).
     * @since 4.2.0
     */
    public $claimsFormatter;

    /**
     * @var array<BaseJwt\Validation\Constraint|array<mixed>>|(callable(JwtTools): array<BaseJwt\Validation\Constraint>)|null
     * List of constraints that will be used to validate against or an anonymous function that can be resolved as such
     * list. The signature of the function should be `function(\bizley\jwt\JwtTools|\bizley\jwt\Jwt $jwt)` where $jwt
     * will be an instance of this component.
     * For the constraints you can use instances of Lcobucci\JWT\Validation\Constraint or configuration arrays to be
     * resolved as such.
     * The constraints can also be replaced at runtime with setValidationConstraints().
     */
    public $validationConstraints;

    /**
     * @param array<mixed> $config
     * @throws InvalidConfigException
     */
    private function buildObjectFromArray(array $config): object
    {
        $keys = \array_keys($config);
        if (\is_string(\reset($keys))) {
            // most probably Yii-style config
            /** @var array{class: class-string} $config */
            return \Yii::createObject($config);
        }

        /** @var array{0: class-string, 1?: array<mixed>} $config */
        return \Yii::createObject(...$config);
    }

    /**
     * Replaces the validation constraints used by validate() and assert().
     * This is the replacement for the deprecated `Lcobucci\JWT\Configuration::setValidationConstraints()` usage
     * (`Yii::$app->jwt->getConfiguration()->setValidationConstraints(...)`).
     * @since 4.2.0
     */
    public function setValidationConstraints(BaseJwt\Validation\Constraint ...$constraints): void
    {
        $this->validationConstraints = $constraints;
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/ for details of using the builder.
     * @throws InvalidConfigException
     */
    public function getBuilder(?BaseJwt\ClaimsFormatter $claimFormatter = null): BaseJwt\Builder
    {
        return new BaseJwt\Token\Builder($this->prepareEncoder(), $claimFormatter ?? $this->prepareClaimsFormatter());
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/parsing-tokens/ for details of using the parser.
     * @throws InvalidConfigException
     */
    public function getParser(): BaseJwt\Parser
    {
        return new BaseJwt\Token\Parser($this->prepareDecoder());
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/stable/validating-tokens/ for details of using the validator.
     */
    public function getValidator(): BaseJwt\Validator
    {
        return new BaseJwt\Validation\Validator();
    }

    /**
     * @param non-empty-string $jwt
     * @throws Encoding\CannotDecodeContent When something goes wrong while decoding.
     * @throws BaseJwt\Token\InvalidTokenStructure When token string structure is invalid.
     * @throws BaseJwt\Token\UnsupportedHeaderFound When parsed token has an unsupported header.
     * @throws InvalidConfigException
     */
    public function parse(string $jwt): BaseJwt\Token
    {
        return $this->getParser()->parse($jwt);
    }

    /**
     * This method goes through every single constraint in the set, groups all the violations, and throws an exception
     * with the grouped violations.
     * @param non-empty-string|BaseJwt\Token $jwt JWT string or instance of Token
     * @throws BaseJwt\Validation\RequiredConstraintsViolated When constraint is violated
     * @throws BaseJwt\Validation\NoConstraintsGiven When no constraints are provided
     * @throws InvalidConfigException
     */
    public function assert($jwt): void
    {
        $token = $jwt instanceof BaseJwt\Token ? $jwt : $this->parse($jwt);
        $constraints = $this->prepareValidationConstraints();
        $this->getValidator()->assert($token, ...$constraints);
    }

    /**
     * This method return false on first constraint violation
     * @param non-empty-string|BaseJwt\Token $jwt JWT string or instance of Token
     * @throws InvalidConfigException
     */
    public function validate($jwt): bool
    {
        $token = $jwt instanceof BaseJwt\Token ? $jwt : $this->parse($jwt);
        $constraints = $this->prepareValidationConstraints();

        return $this->getValidator()->validate($token, ...$constraints);
    }

    /**
     * Returns the key based on the definition.
     * Key value starting with '@' is resolved as Yii alias. For the METHOD_FILE the alias must be valid, for the other
     * methods the value is used as is when it cannot be resolved as an alias.
     * @param string|array<string, mixed>|BaseJwt\Signer\Key $key
     * @throws InvalidConfigException
     */
    public function buildKey(#[\SensitiveParameter] $key): BaseJwt\Signer\Key
    {
        if ($key instanceof BaseJwt\Signer\Key) {
            return $key;
        }

        if (\is_string($key)) {
            if ($key === '') {
                throw new InvalidConfigException('Empty string used as a key configuration!');
            }
            if (\str_starts_with($key, '@') || \str_starts_with($key, 'file://')) {
                $keyConfig = [
                    Jwt::KEY => $key,
                    Jwt::METHOD => Jwt::METHOD_FILE,
                ];
            } else {
                $keyConfig = [
                    Jwt::KEY => $key,
                    Jwt::METHOD => Jwt::METHOD_PLAIN,
                ];
            }
        } elseif (\is_array($key)) {
            $keyConfig = $key;
        } else {
            throw new InvalidConfigException('Invalid key configuration!');
        }

        $value = $keyConfig[Jwt::KEY] ?? '';
        $method = $keyConfig[Jwt::METHOD] ?? Jwt::METHOD_PLAIN;
        $passphrase = $keyConfig[Jwt::PASSPHRASE] ?? '';

        if (!\in_array($method, [Jwt::METHOD_PLAIN, Jwt::METHOD_BASE64, Jwt::METHOD_FILE], true)) {
            throw new InvalidConfigException('Invalid key method!');
        }
        if (!\is_string($passphrase)) {
            throw new InvalidConfigException('Invalid key passphrase!');
        }
        if (!\is_string($value) || $value === '') {
            throw new InvalidConfigException('Invalid key value!');
        }
        /** @var string|false $resolvedValue */
        $resolvedValue = \Yii::getAlias($value, $method === Jwt::METHOD_FILE);
        if ($resolvedValue !== false) {
            $value = $resolvedValue;
        }
        if ($value === '') {
            throw new InvalidConfigException('Yii alias was resolved as an invalid key value!');
        }

        if ($method === Jwt::METHOD_BASE64) {
            return BaseJwt\Signer\Key\InMemory::base64Encoded($value, $passphrase);
        }
        if ($method === Jwt::METHOD_FILE) {
            return BaseJwt\Signer\Key\InMemory::file($value, $passphrase);
        }

        return BaseJwt\Signer\Key\InMemory::plainText($value, $passphrase);
    }

    /**
     * Returns the signer based on the definition.
     * Signer can be provided as a signer ID (see $signers), an instance of Signer, or a configuration array that can be
     * resolved as Signer instance (since 4.2.0).
     * @param string|array<mixed>|BaseJwt\Signer $signer
     * @throws InvalidConfigException
     */
    public function buildSigner($signer): BaseJwt\Signer
    {
        if ($signer instanceof BaseJwt\Signer) {
            return $signer;
        }

        if (\is_array($signer)) {
            $this->prepareSignatureConverter();

            return $this->buildSignerFromArray($signer);
        }

        if (!\array_key_exists($signer, $this->signers)) {
            throw new InvalidConfigException('Invalid signer ID!');
        }

        if (\in_array($signer, [Jwt::ES256, Jwt::ES384, Jwt::ES512], true)) {
            $this->prepareSignatureConverter();
        }

        return $this->buildSignerFromArray($this->signers[$signer]);
    }

    /**
     * @param array<mixed> $config
     * @throws InvalidConfigException
     */
    private function buildSignerFromArray(array $config): BaseJwt\Signer
    {
        $signer = $this->buildObjectFromArray($config);
        if (!$signer instanceof BaseJwt\Signer) {
            throw new InvalidConfigException('Signer configuration must resolve to an instance of Lcobucci\JWT\Signer!');
        }

        return $signer;
    }

    /**
     * ECDSA signers require SignatureConverter to be resolvable by Yii DI container. The default converter is
     * registered only when there is no other definition so your own converter is respected.
     */
    private function prepareSignatureConverter(): void
    {
        if (!\Yii::$container->has(BaseJwt\Signer\Ecdsa\SignatureConverter::class)) {
            \Yii::$container->set(
                BaseJwt\Signer\Ecdsa\SignatureConverter::class,
                BaseJwt\Signer\Ecdsa\MultibyteStringConverter::class
            );
        }
    }

    /**
     * @return BaseJwt\Validation\Constraint[]
     * @throws InvalidConfigException
     */
    protected function prepareValidationConstraints(): array
    {
        if (\is_array($this->validationConstraints)) {
            $constraints = [];

            foreach ($this->validationConstraints as $constraint) {
                if ($constraint instanceof BaseJwt\Validation\Constraint) {
                    $constraints[] = $constraint;
                } else {
                    /** @var array<mixed> $constraint */
                    /** @var BaseJwt\Validation\Constraint $constraintInstance */
                    $constraintInstance = $this->buildObjectFromArray($constraint);
                    $constraints[] = $constraintInstance;
                }
            }

            return $constraints;
        }

        if (\is_callable($this->validationConstraints)) {
            return \call_user_func($this->validationConstraints, $this);
        }

        return [];
    }

    private ?BaseJwt\Encoder $builtEncoder = null;

    /**
     * @throws InvalidConfigException
     */
    protected function prepareEncoder(): BaseJwt\Encoder
    {
        if ($this->builtEncoder === null) {
            if ($this->encoder === null) {
                $this->builtEncoder = new Encoding\JoseEncoder();
            } else {
                /** @var BaseJwt\Encoder $encoder */
                $encoder = Instance::ensure($this->encoder, BaseJwt\Encoder::class);
                $this->builtEncoder = $encoder;
            }
        }

        return $this->builtEncoder;
    }

    private ?BaseJwt\Decoder $builtDecoder = null;

    /**
     * @throws InvalidConfigException
     */
    protected function prepareDecoder(): BaseJwt\Decoder
    {
        if ($this->builtDecoder === null) {
            if ($this->decoder === null) {
                $this->builtDecoder = new Encoding\JoseEncoder();
            } else {
                /** @var BaseJwt\Decoder $decoder */
                $decoder = Instance::ensure($this->decoder, BaseJwt\Decoder::class);
                $this->builtDecoder = $decoder;
            }
        }

        return $this->builtDecoder;
    }

    private ?BaseJwt\ClaimsFormatter $builtClaimsFormatter = null;

    /**
     * @throws InvalidConfigException
     * @since 4.2.0
     */
    protected function prepareClaimsFormatter(): BaseJwt\ClaimsFormatter
    {
        if ($this->builtClaimsFormatter === null) {
            if ($this->claimsFormatter === null) {
                $this->builtClaimsFormatter = Encoding\ChainedFormatter::default();
            } else {
                /** @var BaseJwt\ClaimsFormatter $claimsFormatter */
                $claimsFormatter = Instance::ensure($this->claimsFormatter, BaseJwt\ClaimsFormatter::class);
                $this->builtClaimsFormatter = $claimsFormatter;
            }
        }

        return $this->builtClaimsFormatter;
    }
}
