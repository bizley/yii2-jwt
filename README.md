![Latest Stable Version](https://img.shields.io/packagist/v/bizley/jwt.svg)
[![Total Downloads](https://img.shields.io/packagist/dt/bizley/jwt.svg)](https://packagist.org/packages/bizley/jwt)
![License](https://img.shields.io/packagist/l/bizley/jwt.svg)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fbizley%2Fyii2-jwt%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/bizley/yii2-jwt/master)

# JWT Integration For Yii 2

This extension provides the [JWT](https://github.com/lcobucci/jwt) integration for [Yii 2 framework](https://www.yiiframework.com).

> This is a fork of [sizeg/yii2-jwt](https://github.com/sizeg/yii2-jwt) package

# Available versions

| bizley/yii2-jwt | lcobucci/jwt |   php   |
|:---------------:|:------------:|:-------:|
|     `^4.0`      |    `^5.0`    | `>=8.1` |
|     `^3.0`      |    `^4.0`    | `>=7.4` |
|     `^2.0`      |    `^3.0`    | `>=7.1` |

See [lcobucci/jwt](https://github.com/lcobucci/jwt) repo for details about the version.

## Installation

Add the package to your `composer.json`:

```json
{
    "require": {
        "bizley/jwt": "^4.0"
    }
}
```

and run `composer update` or alternatively run `composer require bizley/jwt:^4.0`

## Basic usage

Add `jwt` component to your configuration file.

If your application is both the issuer and the consumer of JWT (the common case, a.k.a. Standard version) 
use `bizley\jwt\Jwt` component:

```php
[
    'components' => [
        'jwt' => [
            'class' => \bizley\jwt\Jwt::class,
            'signer' => ... // Signer ID, or signer object, or signer configuration, see "Available signers" below
            'signingKey' => ... // Secret key string or path to the signing key file, see "Keys" below
            // ... any additional configuration here
        ],
    ],
],
```

If your application just needs some special JWT tools (like validator or parser, a.k.a. Toolset version) 
use `bizley\jwt\JwtTools` component:

```php
[
    'components' => [
        'jwt' => [
            'class' => \bizley\jwt\JwtTools::class,
            // ... any additional configuration here
        ],
    ],
],
```

Of course, if you are already using the Standard version component, you don't need to define the Toolset version 
component, since the former already provides all the tools.

If you are struggling with the concept of API JWT, here is an [EXAMPLE](INSTRUCTION.md) of how to quickly put all 
pieces together.

### Available signers

Symmetric:
- HMAC (HS256, HS384, HS512)
- BLAKE2B (since 3.4.0; treated as symmetric since 4.2.0, so `verifyingKey` is not required anymore)

Asymmetric:
- RSA (RS256, RS384, RS512)
- ECDSA (ES256, ES384, ES512)
- EdDSA (since 3.1.0)

Signer IDs are available as constants (like Jwt::HS256).

You can also provide your own signer:
- as an instance of `Lcobucci\JWT\Signer`,
- as a configuration array resolvable to `Lcobucci\JWT\Signer` instance (since 4.2.0), like 
  `[\Lcobucci\JWT\Signer\Hmac\Sha256::class]` or `['class' => \Lcobucci\JWT\Signer\Hmac\Sha256::class]` - 
  the signer's `algorithmId()` must be listed in `algorithmTypes`,
- by adding its config to `signers` and `algorithmTypes` and using its ID for `signer`.

ECDSA signers require `Lcobucci\JWT\Signer\Ecdsa\SignatureConverter` to be resolvable by Yii DI container. 
`Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter` is registered there automatically, unless you have already 
registered your own converter (since 4.2.0).

> As stated in `lcobucci/jwt` documentation: Although BLAKE2B is fantastic due to its performance, it's not JWT standard 
> and won't necessarily be offered by other libraries.

### Note on signers and minimum bits requirement

Since `lcobucci/jwt 4.2.0` signers require the minimum key length to make sure those are properly secured, otherwise 
the `InvalidKeyProvided` is thrown.

### Keys

For symmetric signers `signingKey` is required. For asymmetric ones you also need to set `verifyingKey`. Keys can be 
provided as simple strings, configuration arrays, or instances of `Lcobucci\JWT\Signer\Key`.

Configuration array can be as the following:

```php
[
    'key' => /* key content */,
    'passphrase' => /* key passphrase */,
    'method' => /* method type */,
]
```

- key (`bizley\jwt\Jwt::KEY`) - _string_, default `''`, start it with `@` if it's Yii alias,
- passphrase (`bizley\jwt\Jwt::PASSPHRASE`) - _string_, default `''`,
- method (`bizley\jwt\Jwt::METHOD`) - _string_, default `bizley\jwt\Jwt::METHOD_PLAIN`,
  available: `bizley\jwt\Jwt::METHOD_PLAIN`, `bizley\jwt\Jwt::METHOD_BASE64`, `bizley\jwt\Jwt::METHOD_FILE` 
  (see https://lcobucci-jwt.readthedocs.io/en/latest/configuration/)
  
Simple string keys are shortcuts to the following array configs:
- key starts with `@` or `file://`:
  ```php
  [
      'key' => /* given key itself */,
      'passphrase' => '',
      'method' => \bizley\jwt\Jwt::METHOD_FILE,
  ]
  ```
  Detecting `@` at the beginning assumes Yii alias has been provided, so it will be resolved with `Yii::getAlias()`.
  For `METHOD_FILE` the alias must be valid, otherwise an exception is thrown. For `METHOD_PLAIN` and `METHOD_BASE64` 
  a key value starting with `@` that is not a valid alias is used as is (since 4.2.0).

- key doesn't start with `@` nor `file://`:
  ```php
  [
      'key' => /* given key itself */,
      'passphrase' => '',
      'method' => \bizley\jwt\Jwt::METHOD_PLAIN,
  ]
  ```

### Issuing a token example:

Standard version:

```php
$now = new \DateTimeImmutable();
/** @var \Lcobucci\JWT\Token\UnencryptedToken $token */
$token = Yii::$app->jwt->getBuilder()
    // Configures the issuer (iss claim)
    ->issuedBy('http://example.com')
    // Configures the audience (aud claim)
    ->permittedFor('http://example.org')
    // Configures the id (jti claim)
    ->identifiedBy('4f1g23a12aa')
    // Configures the time that the token was issued (iat claim)
    ->issuedAt($now)
    // Configures the time that the token can be used (nbf claim)
    ->canOnlyBeUsedAfter($now->modify('+1 minute'))
    // Configures the expiration time of the token (exp claim)
    ->expiresAt($now->modify('+1 hour'))
    // Configures a new claim, called "uid"
    ->withClaim('uid', 1)
    // Configures a new header, called "foo"
    ->withHeader('foo', 'bar')
    // Builds a new token
    ->getToken(
        Yii::$app->jwt->getConfiguration()->signer(),
        Yii::$app->jwt->getConfiguration()->signingKey()
    );
$tokenString = $token->toString();
```

The same in Toolset version:

```php
$now = new \DateTimeImmutable();
/** @var \Lcobucci\JWT\Token\UnencryptedToken $token */
$token = Yii::$app->jwt->getBuilder()
    ->issuedBy('http://example.com')
    ->permittedFor('http://example.org')
    ->identifiedBy('4f1g23a12aa')
    ->issuedAt($now)
    ->canOnlyBeUsedAfter($now->modify('+1 minute'))
    ->expiresAt($now->modify('+1 hour'))
    ->withClaim('uid', 1)
    ->withHeader('foo', 'bar')
    ->getToken(
        Yii::$app->jwt->buildSigner(/* signer definition */),
        Yii::$app->jwt->buildKey(/* signing key definition */)
    );
$tokenString = $token->toString();
```

See https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/ for more info.

### Parsing a token

```php
/** @var non-empty-string $jwt */
/** @var \Lcobucci\JWT\Token $token */
$token = Yii::$app->jwt->parse($jwt);
```

See https://lcobucci-jwt.readthedocs.io/en/latest/parsing-tokens/ for more info.

### Validating a token

You can validate a token or perform an assertion on it (see https://lcobucci-jwt.readthedocs.io/en/latest/validating-tokens/).

For validation use:
```php
/** @var \Lcobucci\JWT\Token | non-empty-string $token */                                      
/** @var bool $result */
$result = Yii::$app->jwt->validate($token);
```

For assertion use:
```php
/** @var \Lcobucci\JWT\Token | string $token */                                      
Yii::$app->jwt->assert($token);
```

You **MUST** provide at least one constraint, otherwise `Lcobucci\JWT\Validation\NoConstraintsGiven` exception will be 
thrown. There are several ways to provide constraints:

- directly (since 4.2.0, it replaces the constraints configured before):
  ```php
  Yii::$app->jwt->setValidationConstraints(/* constraints here */);
  ```

- through component configuration:
  ```php
  [
      'validationConstraints' => /*
          array of instances of Lcobucci\JWT\Validation\Constraint
          
          or
          array of configuration arrays that can be resolved as Constraint instances
          
          or
          anonymous function that can be resolved as array of Constraint instances with signature
          `function(\bizley\jwt\Jwt|\bizley\jwt\JwtTools $jwt)` where $jwt will be an instance of used component
      */,
  ]
  ```

> [!WARNING]
> By default, this package is not adding any constraints out-of-the-box, you must configure them yourself like 
> in the examples above. **Signature is verified only when you add the `Lcobucci\JWT\Validation\Constraint\SignedWith` 
> constraint** (or `SignedWithOneInSet` / `SignedWithUntilDate`), and expiration time is verified only with 
> `StrictValidAt` or `LooseValidAt` constraint. Without them, any token with valid structure that matches the remaining 
> constraints is accepted - including tokens signed with a different key or not signed at all.

> [!NOTE]
> Setting constraints with `Yii::$app->jwt->getConfiguration()->setValidationConstraints(...)` is deprecated since 
> 4.2.0 (the method itself is deprecated since `lcobucci/jwt` 5.5), and support for it will be removed in 5.0.0. 
> It still works and takes precedence over the component's constraints, but a warning is logged each time such 
> constraints are used. Replace it with `Yii::$app->jwt->setValidationConstraints(...)`.

## Using component for REST authentication

Configure the `authenticator` behavior in the controller.

```php
class ExampleController extends Controller
{
    public function behaviors()
    {
        $behaviors = parent::behaviors();
        
        $behaviors['authenticator'] = [
            'class' => \bizley\jwt\JwtHttpBearerAuth::class,
        ];

        return $behaviors;
    }
}
```

There are special options available:
- jwt - _string_ ID of component (default with `'jwt'`), component configuration _array_, or an instance of `bizley\jwt\Jwt` 
  or `bizley\jwt\JwtTools`,
- auth - callable or `null` (default) - anonymous function with signature `function (\Lcobucci\JWT\Token $token)` that 
  should return identity of user authenticated with the JWT payload information. If $auth is not provided method 
  `yii\web\User::loginByAccessToken()` will be called instead. Since 4.2.0 an `InvalidConfigException` is thrown 
  when a value that is not callable is provided.
- throwException - _bool_ (default `true`) - whether the filter should throw an exception i.e. if the token has 
  an invalid format. If there are multiple auth filters (CompositeAuth) it can make sense to "silent fail" and pass 
  the validation process to the next filter on the composite auth list.

For other configuration options refer to the [Yii 2 Guide](https://www.yiiframework.com/doc/guide/2.0/en/rest-authentication).

## JWT Usage

Please refer to the [lcobucci/jwt Documentation](https://lcobucci-jwt.readthedocs.io/en/latest/).

## JSON Web Tokens

- https://jwt.io
