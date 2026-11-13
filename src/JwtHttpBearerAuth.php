<?php

declare(strict_types=1);

namespace bizley\jwt;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation;
use yii\base\InvalidConfigException;
use yii\di\Instance;
use yii\filters\auth\HttpBearerAuth;
use yii\web;

/**
 * JwtHttpBearerAuth is an action filter that supports the authentication method based on HTTP Bearer JSON Web Token.
 *
 * You can use JwtHttpBearerAuth by attaching it as a behavior to a controller or a module, like in the following:
 *
 * ```php
 * public function behaviors()
 * {
 *     return [
 *         'JWTBearerAuth' => [
 *             'class' => \bizley\jwt\JwtHttpBearerAuth::class,
 *         ],
 *     ];
 * }
 * ```
 *
 * @author Paweł Bizley Brzozowski <pawel.bizley@gmail.com> since 2.0 (fork)
 * @author Dmitriy Demin <sizemail@gmail.com> original package
 */
class JwtHttpBearerAuth extends HttpBearerAuth
{
    /**
     * @var string|array<string, mixed>|JwtTools|Jwt application component ID of the JWT handler, configuration array,
     * or JWT handler object itself. By default, it assumes that component of ID "jwt" has been configured.
     */
    public $jwt = 'jwt';

    /**
     * @var (callable(Token): mixed)|null anonymous function that should return identity of the user authenticated with
     * the JWT payload information. It should have the following signature:
     *
     * ```php
     * function (Token $token)
     * ```
     *
     * where $token is the JSON Web Token provided in the HTTP header.
     * If $auth is not provided, method User::loginByAccessToken() will be called instead.
     */
    public $auth;
    
    /**
     * @var bool Whether the filter should throw an exception i.e. if the token has an invalid format. If there are
     * multiple auth filters (CompositeAuth) it can make sense to "silent fail" and pass the validation process to
     * the next filter on the composite auth list. Default is true.
     * @since 3.3.0
     */
    public bool $throwException = true;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        if (empty($this->pattern)) {
            throw new InvalidConfigException('You must provide pattern to use to extract the HTTP authentication value!');
        }
        // the property's type comes from PHPDoc only, so the actual configured value must be verified here
        // @phpstan-ignore booleanAnd.alwaysFalse, booleanNot.alwaysFalse
        if ($this->auth !== null && !\is_callable($this->auth)) {
            throw new InvalidConfigException('The "auth" property must be a valid callable or null!');
        }
    }

    private Jwt|JwtTools|null $JWTComponent = null;

    public function getJwtComponent(): Jwt|JwtTools
    {
        if ($this->JWTComponent === null) {
            /** @var Jwt|JwtTools $jwt */
            $jwt = Instance::ensure($this->jwt, JwtTools::class);
            $this->JWTComponent = $jwt;
        }

        return $this->JWTComponent;
    }

    /**
     * Authenticates the current user.
     * @param web\User $user
     * @param web\Request $request
     * @param web\Response $response
     * @return web\IdentityInterface|null the authenticated user identity. If authentication information is not provided, null will be returned.
     * @throws InvalidConfigException When JWT configuration has not been properly initialized.
     * @throws CannotDecodeContent When something goes wrong while decoding token.
     * @throws Token\InvalidTokenStructure When token string structure is invalid.
     * @throws Token\UnsupportedHeaderFound When parsed token has an unsupported header.
     * @throws Validation\RequiredConstraintsViolated When constraint is not present in token.
     * @throws Validation\NoConstraintsGiven When no constraints are provided.
     * @throws Validation\ConstraintViolation When constraint is violated.
     * @throws web\UnauthorizedHttpException if authentication information is provided but is invalid.
     */
    public function authenticate($user, $request, $response): ?web\IdentityInterface // BC signature
    {
        /** @var string|null $authHeader */
        $authHeader = $request->getHeaders()->get($this->header);

        if ($authHeader === null || !preg_match($this->pattern, $authHeader, $matches)) {
            return null;
        }

        $identity = null;
        $token = null;
        $data = $matches[1];

        try {
            if (!empty($data)) {
                $token = $this->processToken($data);
            }
        } catch (\Throwable $exception) {
            \Yii::warning($exception->getMessage(), 'JwtHttpBearerAuth');
            if (!$this->throwException) {
                return null;
            }
            throw $exception;
        }

        if ($token !== null) {
            if ($this->auth !== null) {
                $identity = \call_user_func($this->auth, $token);
            } else {
                $identity = $user->loginByAccessToken($token->toString(), \get_class($this));
            }
        }

        if (!$identity instanceof web\IdentityInterface) {
            return null;
        }

        return $identity;
    }

    /**
     * Parses and validates the JWT token.
     * @param non-empty-string $data data provided in HTTP header, presumably JWT
     * @throws InvalidConfigException
     */
    public function processToken(string $data): ?Token
    {
        $token = $this->getJwtComponent()->parse($data);

        return $this->getJwtComponent()->validate($token) ? $token : null;
    }

    /**
     * @throws web\UnauthorizedHttpException
     */
    public function fail(web\Response $response): void
    {
        $this->challenge($response);
        $this->handleFailure($response);
    }

    /**
     * Handles authentication failure.
     * @param web\Response $response
     * @throws web\UnauthorizedHttpException
     */
    public function handleFailure($response): void // BC signature
    {
        throw new web\UnauthorizedHttpException('Your request was made with invalid or expired JSON Web Token.');
    }
}
