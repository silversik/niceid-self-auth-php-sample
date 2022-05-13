<?php
include_once "function.php";
session_start_samesite();

header("Content-type: text/html; charset=utf-8");

$data = getResponseData($_GET['enc_data'], $_GET['integrity_value'], $_SESSION['NICE_ID_SYMMETRIC_KEY']);
if (!$data) {
    echo '데이터 불러오기 실패';
    return;
}

// var_dump($data);

if ($data['resultcode'] == '0000') {
    $name = urldecode($data['utf8_name']);
    print("<script>opener.document.getElementById('name').value = '{$name}';</script>");
    print("<script>opener.document.getElementById('mobileno').value = '{$data['mobileno']}';</script>");

} else {
    $action = "본인 인증 실패: 결과코드[{$data['resultcode']}]";
    print("<script>opener.alert('{$action}');</script>");
}

print("<script>self.close();</script>");