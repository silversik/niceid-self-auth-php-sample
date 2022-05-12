<?php
include_once "function.php";
session_start_samesite();

header("Content-type: text/html; charset=utf-8");

$data = getRequestData();
if (!$data) {
    echo '데이터 불러오기 실패';
    return;
}
$_SESSION['NICE_ID_SYMMETRIC_KEY'] = $data['symmetricKey'];
?>
<form name="form" id="form">
  <input type="hidden" id="m" name="m" value="service"/>
  <input type="hidden" id="token_version_id" name="token_version_id" value="<?= $data['tokenVersionId']; ?>"/>
  <input type="hidden" id="enc_data" name="enc_data" value="<?= $data['encData']; ?>"/>
  <input type="hidden" id="integrity_value" name="integrity_value" value="<?= $data['integrityValue']; ?>"/>
</form>
<button onclick="checkService()">본인 인증</button>
<div style="margin-top:50px">
  <input type="text" id="name" placeholder="이름" readonly/>
  <input type="text" id="mobileno" placeholder="전화번호" readonly/>
</div>
<script>
  function checkService() {
    window.open('', 'popupChk', 'width=500, height=550, top=100, left=100, fullscreen=no, menubar=no, status=no, toolbar=no, titlebar=yes, location=no, scrollbar=no');
    document.form.action = "https://nice.checkplus.co.kr/CheckPlusSafeModel/service.cb";
    document.form.target = "popupChk";
    document.form.submit();
  }
</script>