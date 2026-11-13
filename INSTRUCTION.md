# INSTRUCTION

Here is an example of using this package to secure your API. 

This package is a wrapper of the [lcobucci/jwt](https://github.com/lcobucci/jwt) so for the details of using it 
I recommend reading [its documentation](https://lcobucci-jwt.readthedocs.io/en/latest/).

I'm using here ECDSA asymmetric key with elliptic curve size 256 - the code of this key is `ES256`.

## Step 1: Generating the keys

On Linux run

```sh
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
```

This creates a file with your private key named `private.pem`. Next run

```sh
openssl ec -in private.pem -pubout -out public.pem
```

You will get a file with your public key named `public.pem`. Private and public keys are different hence the type - 
asymmetric. You can name the files differently if you want.

Place the files somewhere where they cannot be accessed through the web (IMPORTANT!) but are still readable by your 
application. You can place them in your application structure but usually above the `web` or `public` folder - again, 
it all depends on your server configuration.

For other OS please refer to the online guides about generating SSH keys.

## Step 2: Configuration

Add `jwt` component to your configuration file:

```php
[
    'components' => [
        'jwt' => [
            'class' => \bizley\jwt\Jwt::class,
            'signer' => \bizley\jwt\Jwt::ES256,
            'signingKey' => [
                'key' => '...', // path to your PRIVATE key, you can start the path with @ to indicate this is a Yii alias
                'method' => \bizley\jwt\Jwt::METHOD_FILE,
            ],
            'verifyingKey' => [ // required for asymmetric keys
                'key' => '...', // path to your PUBLIC key, you can start the path with @ to indicate this is a Yii alias
                'method' => \bizley\jwt\Jwt::METHOD_FILE,
            ],
            'clock' => new \Lcobucci\Clock\SystemClock(new \DateTimeZone('UTC')),
            'tokenLifetime' => 'PT1H', // tokens issued with issue() expire after 1 hour
            'validationConstraints' => static function (\bizley\jwt\Jwt $jwt) {
                return [
                    $jwt->getSignedWithConstraint(),
                    new \Lcobucci\JWT\Validation\Constraint\LooseValidAt(
                        new \Lcobucci\Clock\SystemClock(new \DateTimeZone('UTC')),
                        new \DateInterval('PT10S')
                    ),
                ];
            }
        ],
    ],
],
```

Validation constraints used here are:
 - `SignedWith` (returned by `getSignedWithConstraint()`) - this will make sure that received token is indeed signed 
   with the chosen signer and can be verified with the provided verification key,
 - `LooseValidAt` - this will make sure that token is not expired yet allowing 10 seconds leeway (in case of some delays
   between the server and the client).

The `clock` option sets the clock used when issuing tokens with `issue()`.

*NOTE*: The above implementation requires to install `lcobucci/clock` library first (run `composer req lcobucci/clock`).
If you prefer other PSR-20 clock implementation you must change the above `\Lcobucci\Clock\SystemClock()` usage.

You can also add here any other constraint that you find necessary. The available list is at
https://github.com/lcobucci/jwt/tree/5.5.x/src/Validation/Constraint, and you can always write your own constraint as 
long as it implements `Lcobucci\JWT\Validation\Constraint`.

For other ways to add constraints please refer to the README file.

## Step 3: Issuing the token

New access token should be given to the API client after successful authentication, which usually is done through 
providing valid username and password. I'm assuming you have prepared a controller (or similar) to handle the user input 
and validation - the next step, after we know that the user is indeed someone that can access our API, is to generate 
the token and return it to the user.  
We can generate new token with:

```php
$token = \Yii::$app->jwt->issue(
    // Configures a new claim, called "uid", with user ID, assuming $user is the authenticated user object
    static fn (\Lcobucci\JWT\Builder $builder) => $builder->withClaim('uid', $user->id)
);
$tokenString = $token->toString();
```

`issue()` signs the token with the configured signer and signing key, sets the time the token was issued and the time 
it can be used from to the current time, and the expiration time to the current time + `tokenLifetime` (1 hour here).

Now it's a matter of returning this value back to the client, for example:

```php
return ['token' => $tokenString];
```

## Step 4: Passing the token

API client should use the given token and send it with the API requests to authorize the user.  
In order to do that client must send `Authorization` header with value `Bearer xxx`, where `xxx` is the token string 
itself.

## Step 5: Validating the token

In the API controller we can add authorization filter:

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

The first thing `JwtHttpBearerAuth` does is to validate the given token, so it must be properly signed and not expired.  
The second thing is to find the user, the token was issued for. To do that let's modify the `User` class, the one 
configured in `user` component (the one implementing `yii\web\IdentityInterface`).  
This class must have `findIdentityByAccessToken` static method I will use.

```php
public static function findIdentityByAccessToken($token, $type = null)
{
    if ($type !== \bizley\jwt\JwtHttpBearerAuth::class) {
        // this method can be called by other authentication methods as well, i.e. when using CompositeAuth,
        // in which case the token has not been validated yet
        if (!\Yii::$app->jwt->validate($token)) {
            return null;
        }
    }

    $parsedToken = \Yii::$app->jwt->parse($token);
    if (!$parsedToken instanceof \Lcobucci\JWT\UnencryptedToken) {
        return null;
    }
    $uid = $parsedToken->claims()->get('uid');
    if (!is_numeric($uid)) {
        throw new \yii\web\ForbiddenHttpException('Invalid token provided');
    }

    return static::findOne(['id' => $uid]);
}
```

`JwtHttpBearerAuth` validates the token before calling this method and passes its class name as `$type`. When the 
method is called by any other authentication method, the token must be validated here, otherwise a forged token would 
be accepted.

If the method above returns User object, `user` component uses it (`Yii::$app->user->identity`) so the application 
further on can rely on this information and act accordingly.
