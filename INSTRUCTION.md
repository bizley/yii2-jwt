# INSTRUCTION

Here is an example of using this package to secure your API. 

This package is a wrapper of the [lcobucci/jwt](https://github.com/lcobucci/jwt) so for the details of using it 
I recommend reading [its documentation](https://lcobucci-jwt.readthedocs.io/en/latest/).

I'm using here secp384r1 asymmetric key with elliptic curve size 384 and a passphrase - the code of this key is `ES384`.

## Step 1: Generating the keys

On your operating system, install openssl and then run the following commands to generate key pair

```sh
openssl ecparam -name secp384r1 -genkey -noout -out jwt-private.pem
openssl ec -in jwt-private.pem -pubout > jwt-public.pem
```

Enter the folder where you would like your keys to be generated and the name of the key and provide the passphrase 
(if you want). In this example I'm using passphrase `stopwars`.  
You will get two files: `jwt-private.pem` which is the private key, and `jwt-public.pem` extension which is 
the public key (keys are different hence the type - asymmetric).  
Place the files somewhere where they cannot be accessed through the web (IMPORTANT!) but are still readable by your 
application. You can place them in your application structure but usually above the `web` or `public` folder - again, 
it all depends on your server configuration. 

## Step 1: Configuration

Add `jwt` component to your configuration file:

```php
[
    'components' => [
        'jwt' => [
            'class' => \bizley\jwt\Jwt::class,
            'signer' => \bizley\jwt\Jwt::ES384,
            'signingKey' => [
                'key' => '', // path to your PRIVATE key, you can start the path with @ to indicate this is a Yii alias
                'passphrase' => 'stopwars', // omit it if you are not adding any passphrase
                'method' => \bizley\jwt\Jwt::METHOD_FILE,
            ],
            'verifyingKey' => [ // required for asymmetric keys
                'key' => '', // path to your PUBLIC key, you can start the path with @ to indicate this is a Yii alias
                'passphrase' => 'stopwars', // omit it if you are not adding any passphrase
                'method' => \bizley\jwt\Jwt::METHOD_FILE,
            ],
            'validationConstraints' => static fn (\bizley\jwt\Jwt $jwt) {
                $config = $jwt->getConfiguration();
                return [
                    new \Lcobucci\JWT\Validation\Constraint\SignedWith($config->signer(), $config->verificationKey()),
                    new \Lcobucci\JWT\Validation\Constraint\LooseValidAt(
                        new \Lcobucci\Clock\SystemClock(new \DateTimeZone(\Yii::$app->timeZone)),
                        new \DateInterval('PT10S')
                    ),
                ];
            }
        ],
    ],
],
```

Validation constraints used here are:
 - `SignedWith` - this will make sure that received token is indeed signed with the chosen signer and can be verified 
   with the provided verification key,
 - `LooseValidAt` - this will make sure that token is not expired yet allowing 10 seconds leeway (in case of some delays
   between the server and the client), we are here also setting the same time zone that is used in the application.

*NOTE*: The above implementation requires to install `lcobucci/clock` library first (run `composer req lcobucci/clock`).
If you prefer other PSR-20 clock implementation you must change the above `\Lcobucci\Clock\SystemClock()` usage.

You can also add here any other constraint that you find necessary. The available list is at 
https://github.com/lcobucci/jwt/tree/4.1.x/src/Validation/Constraint, and you can always write your own constraint as 
long as it implements `Lcobucci\JWT\Validation\Constraint`.

For other ways to add constraints please refer to the README file.

## Step 2: Issuing the token

New access token should be given to the API client after successful authentication, which usually is done through 
providing valid username and password. I'm assuming you have prepared a controller (or similar) to handle the user input 
and validation - the next step, after we know that the user is indeed someone that can access our API, is to generate 
the token and return it to the user.  
We can generate new token with:

```php
$now = new \DateTimeImmutable('now', new \DateTimeZone(\Yii::$app->timeZone));
$token = \Yii::$app->jwt->getBuilder()
    // Configures the time that the token was issued
    ->issuedAt($now)
    // Configures the time that the token can be used
    ->canOnlyBeUsedAfter($now)
    // Configures the expiration time of the token
    ->expiresAt($now->modify('+1 hour'))
    // Configures a new claim, called "uid", with user ID, assuming $user is the authenticated user object
    ->withClaim('uid', $user->id)
    // Builds a new token
    ->getToken(
        \Yii::$app->jwt->getConfiguration()->signer(),
        \Yii::$app->jwt->getConfiguration()->signingKey()
    );
$tokenString = $token->toString();
```

Now it's a matter of returning this value back to the client, for example:

```php
return ['token' => $tokenString];
```

## Step 3: Passing the token

API client should use the given token and send it with the API requests to authorize the user.  
In order to do that client must send `Authorization` header with value `Bearer xxx`, where `xxx` is the token string 
itself.

## Step 4: Validating the token

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
    $claims = \Yii::$app->jwt->parse($token)->claims();
    $uid = $claims->get('uid');
    if (!is_numeric($uid)) {
        throw new ForbiddenHttpException('Invalid token provided');
    }

    return static::findOne(['id' => $uid]);
}
```

If the method above returns User object, `user` component uses it (`Yii::$app->user->identity`) so the application 
further on can rely on this information and act accordingly.
