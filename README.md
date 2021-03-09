![Latest Stable Version](https://img.shields.io/packagist/v/bizley/jwt.svg)
[![Total Downloads](https://img.shields.io/packagist/dt/bizley/jwt.svg)](https://packagist.org/packages/bizley/jwt)
![License](https://img.shields.io/packagist/l/bizley/jwt.svg)

# JWT Integration For Yii 2

This extension provides the [JWT](https://github.com/lcobucci/jwt) integration for 
[Yii 2 framework](https://www.yiiframework.com).

> This is fork of [sizeg/yii2-jwt](https://github.com/sizeg/yii2-jwt) package

This package is compatible with lcobucci/jwt v3.3 or v3.4.
- For v3.2 and older install `bizley/jwt:<2.1`.
- For v4 install `bizley/jwt:^3.0`.

## Installation

Add the package to your `composer.json`:

    {
        "require": {
            "bizley/jwt": "^2.1"
        }
    }

and run `composer update` or alternatively run `composer require bizley/jwt:^2.1`

## Basic usage

Add `jwt` component to your configuration file:

    [
        'components' => [
            'jwt' => [
                'class' => \bizley\jwt\Jwt::class,
                'key' => ... // Secret key string or path to the public key file
            ],
        ],
    ],


Now you have got access to JWT library through `Yii::$app->jwt` and some helper methods like `getBuilder()`, 
`getParser()`, and `getValidationData()`. You can validate your JSON Web Token by using `validateToken()` method and 
check its signature with `verifyToken()`.

### REST authentication

Configure the `authenticator` behavior in controller.

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


For other configuration options refer to the [Yii 2 Guide](https://www.yiiframework.com/doc/guide/2.0/en/rest-authentication).

### JWT Basic Usage

Please refer to the [lcobucci/jwt Documentation](https://lcobucci-jwt.readthedocs.io/en/3.4.0/).

## JSON Web Tokens

- https://jwt.io
