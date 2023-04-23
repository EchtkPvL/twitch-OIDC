<?php
error_reporting(E_ALL);
ini_set('display_errors', 'On');
session_start();

define('CLIENT_ID', 'abcdefghijklmnopqrstuvwxyz1234');
define('CLIENT_SECRET', 'abcdefghijklmnopqrstuvwxyz1234');
define('REDIRECT_URL', 'https://domain.tld/oidc.php');

if(!empty($_GET['error']))
{
    printf('Error: %s' . PHP_EOL, $_GET['error']);
    printf('%s' . PHP_EOL, $_GET['error_description']);
    die;
}

if(isset($_GET['logout']))
{
    session_start();
    $_SESSION = array();
    session_destroy();
    header('Location: ?');
    die;
}

if(empty($_GET['code']) && empty($_SESSION['auth']))
{
    $claims = (object) array(
        'id_token' => array(
            'email' => null,
            'email_verified' => null
        ),
        'userinfo' => array(
            'picture' => null,
            'preferred_username' => null,
            'updated_at' => null
        )
    );
    $scopes = array('openid', 'user:read:email', 'user:read:subscriptions');
    $url = sprintf('https://id.twitch.tv/oauth2/authorize?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&claims=%s',
        CLIENT_ID, REDIRECT_URL, implode($scopes, '+'), urlencode(json_encode($claims)));
    header('Location: ' . $url);
    die;
}

header('Content-Type: text/plain');

if(empty($_SESSION['auth']))
{
    // https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/#oidc-authorization-code-grant-flow
    $url = sprintf('https://id.twitch.tv/oauth2/token?client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s',
        CLIENT_ID, CLIENT_SECRET, $_GET["code"], REDIRECT_URL);
    $oauth = doCurl($url, 'POST');
    $oauth = json_decode($oauth, true);

    $userinfo = doCurl('https://id.twitch.tv/oauth2/userinfo', 'GET',
        array('Content-Type: application/json', 'Authorization: Bearer ' . $oauth['access_token']));
    $userinfo = json_decode($userinfo, true);
    if(empty($userinfo['preferred_username']))
    {
        throw new Exception('Error');
    }

    // https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/#requesting-claims
    $_SESSION['jwt'] = json_decode(
        base64_decode(
            str_replace(['_', '-'], ['/', '+'],
                explode('.', $oauth['id_token'])[1]
            )
        ), true
    );

    unset($oauth['expires_in'], $oauth['id_token']);
    $_SESSION['auth'] = $oauth;

    header('Location: ?login=success');
    die;
} else {
    $validate = doCurl('https://id.twitch.tv/oauth2/validate',
        'GET', array('Content-Type: application/json', 'Authorization: Bearer ' . $_SESSION['auth']['access_token']));
    $validate = json_decode($validate, true);

    if(empty($validate['expires_in']) || $validate['expires_in'] <= 60)
    {
        // https://dev.twitch.tv/docs/authentication/refresh-tokens/
        $refresh = doCurl(
            'https://id.twitch.tv/oauth2/token',
            'POST',
            array('Content-Type: application/x-www-form-urlencoded'),
            sprintf('grant_type=refresh_token&refresh_token=%s&client_id=%s&client_secret=%s',
                $_SESSION['auth']['refresh_token'], CLIENT_ID, CLIENT_SECRET)
        );
        $refresh = json_decode($refresh, true);
        
        if(empty($refresh['access_token']))
        {
            throw new Exception('Token could not be refreshed');
        }

        unset($refresh['expires_in']);
        $_SESSION['auth'] = $refresh;
    }
}

$oidc = doCurl(
    'https://id.twitch.tv/oauth2/userinfo',
    'GET',
    array('Content-Type: application/json', 'Authorization: Bearer ' . $_SESSION['auth']['access_token'])
);
$oidc = json_decode($oidc, true);
$_SESSION['oidc'] = $oidc;
print_r($_SESSION);

print_r(
    json_decode(
        doCurl(
            sprintf('https://api.twitch.tv/helix/subscriptions/user?broadcaster_id=%s&user_id=%s', '35884167', $_SESSION['jwt']['sub']),
            'GET',
            array('Authorization: Bearer ' . $_SESSION['auth']['access_token'], 'Client-Id: ' . CLIENT_ID)
        )
    , true)
);

print_r(
    json_decode(
        doCurl(
            sprintf('https://api.twitch.tv/helix/subscriptions/user?broadcaster_id=%s&user_id=%s', '12875057', $_SESSION['jwt']['sub']),
            'GET',
            array('Authorization: Bearer ' . $_SESSION['auth']['access_token'], 'Client-Id: ' . CLIENT_ID)
        )
    , true)
);


/**
 * 
 * 
 */
function doCurl(string $url, string $type = 'GET', array $headers = [], $post_fields = [], string $user_agent = '', string $referrer = '', bool $follow = true, bool $use_ssl = false, int $con_timeout = 10, int $timeout = 40)
{
    $crl = curl_init($url);
    curl_setopt($crl, CURLOPT_CUSTOMREQUEST, $type);
    curl_setopt($crl, CURLOPT_USERAGENT, $user_agent);
    curl_setopt($crl, CURLOPT_REFERER, $referrer);
    if ($type == 'POST') {
        curl_setopt($crl, CURLOPT_POST, true);
        if (!empty($post_fields)) {
            curl_setopt($crl, CURLOPT_POSTFIELDS, $post_fields);
        }
    }
    if (!empty($headers)) {
        curl_setopt($crl, CURLOPT_HTTPHEADER, $headers);
    }
    curl_setopt($crl, CURLOPT_FOLLOWLOCATION, $follow);
    curl_setopt($crl, CURLOPT_CONNECTTIMEOUT, $con_timeout);
    curl_setopt($crl, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($crl, CURLOPT_SSL_VERIFYHOST, $use_ssl);
    curl_setopt($crl, CURLOPT_SSL_VERIFYPEER, $use_ssl);
    curl_setopt($crl, CURLOPT_ENCODING, 'gzip,deflate'); 
    curl_setopt($crl, CURLOPT_RETURNTRANSFER, true);
    $call_response = curl_exec($crl);
    if (curl_errno($crl)) {
        echo 'Error:' . curl_error($crl);
    }
    curl_close($crl);
    return $call_response;
}
