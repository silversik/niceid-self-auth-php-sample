<?php
include_once "env.php";

if (!function_exists('session_start_samesite')) {
    function session_start_modify_cookie()
    {
        $headers = headers_list();
        krsort($headers);
        foreach ($headers as $header) {
            if (!preg_match('~^Set-Cookie: PHPSESSID=~', $header)) continue;
            $header = preg_replace('~; secure(; HttpOnly)?$~', '', $header) . '; secure; SameSite=None';
            header($header, false);
            break;
        }
    }

    function session_start_samesite($options = [])
    {
        $res = session_start($options);
        session_start_modify_cookie();
        return $res;
    }

    function session_regenerate_id_samesite($delete_old_session = false)
    {
        $res = session_regenerate_id($delete_old_session);
        session_start_modify_cookie();
        return $res;
    }
}

// 기관 토큰 발급(최초 1회만 호출)
function getClientToken($clientId, $clientSecret)
{
    $url = "https://svc.niceapi.co.kr:22001/digital/niceid/oauth/oauth/token";

    $authorization = "Basic " . base64_encode($clientId . ':' . $clientSecret);

    $curl = curl_init();

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER, array(
        "Content-Type: application/x-www-form-urlencoded",
        "Authorization: $authorization"
    ));
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, "grant_type=client_credentials&scope&default");

    $response = curl_exec($curl);
    curl_close($curl);

    $data = json_decode($response, true);

    if (!$data['dataBody']) {
        return null;
    }

    return $data['dataBody']['access_token'];
}

// 암호화 토큰 발급
function getCryptoTokenData($clientId, $productId, $accessToken, $dtim, $reqNo)
{
    $url = "https://svc.niceapi.co.kr:22001/digital/niceid/api/v1.0/common/crypto/token";

    $datetime = new DateTime();
    $current_timestamp = $datetime->getTimestamp();
    $authorization = "bearer " . base64_encode($accessToken . ":" . $current_timestamp . ":" . $clientId);

    $curl = curl_init();

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER, array(
        "Content-Type: application/json",
        "Authorization: $authorization",
        "productID: $productId",
    ));
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode(array(
        "dataHeader" => array("CNTY_CD" => "ko"),
        "dataBody" => array(
            'req_dtim' => $dtim,
            'req_no' => $reqNo,
            'enc_mode' => '1'
        ))));

    $response = curl_exec($curl);
    curl_close($curl);

    $data = json_decode($response, true);

    if (!$data['dataBody']) {
        return null;
    }

    return array(
        'token' => $data['dataBody']['token_val'],
        'siteCode' => $data['dataBody']['site_code'],
        'tokenVersionId' => $data['dataBody']['token_version_id']
    );
}

// 대칭키 생성
function generateSymmetricKey($dtim, $reqNo, $cryptoToken)
{
    $hashed_value = hash("sha256", $dtim . $reqNo . $cryptoToken, true);
    return base64_encode($hashed_value);
}

// 대칭키 파싱
function parseSymetricKey($symmetricKey)
{
    return array(
        'key' => substr($symmetricKey, 0, 16),
        'iv' => substr($symmetricKey, strlen($symmetricKey) - 16, 16),
        'hmacKey' => substr($symmetricKey, 0, 32)
    );
}

// 무결성키 생성
function generateIntegrityValue($encData, $hmacKey)
{
    $hashedValue = hash_hmac("sha256", $encData, $hmacKey, true);
    return base64_encode($hashedValue);
}

// 요청 정보 가져오기
function getRequestData()
{
    global $CLIENT_ID, $CLIENT_SECRET, $CLIENT_TOKEN, $PRODUCT_ID, $RETURN_URL;

    // 변수 선언
    $dtim = date('YmdHis');

    // Todo: 리퀘스트 번호 중복 방지해야 함
    $reqNo = 'REQ' . $dtim . rand(1000, 9999);

    // 기관 토큰 발급
    $clientToken = $CLIENT_TOKEN || getClientToken($CLIENT_ID, $CLIENT_SECRET);

    // 암호화 토큰 발급
    $cryptoTokenData = getCryptoTokenData($CLIENT_ID, $PRODUCT_ID, $clientToken, $dtim, $reqNo);
    $cryptoToken = $cryptoTokenData['token'];
    $siteCode = $cryptoTokenData['siteCode'];
    $tokenVersionId = $cryptoTokenData['tokenVersionId'];

    // 대칭키 생성
    $symmetricKey = generateSymmetricKey($dtim, $reqNo, $cryptoToken);
    $keyData = parseSymetricKey($symmetricKey);

    // 요청 데이터 생성
    $reqData = json_encode(array(
        'requestno' => $reqNo,
        'returnurl' => $RETURN_URL,
        'sitecode' => $siteCode,
        'methodtype' => 'get',
        'authtype' => 'M',
        'popupyn' => 'Y',
    ));

    // 데이터 암호화
    $encData = base64_encode(openssl_encrypt($reqData, "AES-128-CBC", $keyData['key'], OPENSSL_RAW_DATA, $keyData['iv']));

    // 무결성키 생성
    $integrityValue = generateIntegrityValue($encData, $keyData['hmacKey']);

    return array(
        'tokenVersionId' => $tokenVersionId,
        'encData' => $encData,
        'integrityValue' => $integrityValue,
        'symmetricKey' => $symmetricKey
    );
}

// 응답 정보 가져오기
function getResponseData($encData, $integrityValue, $symmetricKey)
{
    $keyData = parseSymetricKey($symmetricKey);
    if ($integrityValue != generateIntegrityValue($encData, $keyData['hmacKey'])) {
        return null;
    }

    // 데이터 복호화
    $decryptedData = openssl_decrypt(base64_decode($encData), 'aes-128-cbc', $keyData['key'], OPENSSL_RAW_DATA, $keyData['iv']);

    // UTF8 인코딩
    $decryptedData = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $decryptedData);

    return json_decode($decryptedData, true);
}