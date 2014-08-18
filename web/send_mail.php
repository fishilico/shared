<?php
/*
 * Send an email
 * Documentation: http://php.net/manual/en/function.mail.php
 */
error_reporting(E_ALL);

$from = 'web@example.com';
$to = 'user@example.com';
$subject = 'Testing mails';
$msg = "Is is working?\n";
$msg .= "* File: " . $_SERVER['SCRIPT_FILENAME'] . "\n";
$msg .= "* URI: " . $_SERVER['REQUEST_URI'] . "\n";
$msg .= "* Server: " . $_SERVER['SERVER_SOFTWARE'] . "\n";

$headers = "Return-Path: " . $from . "\n";
$headers .= "From: " . $from . "\n";
$headers .= "Reply-To: " . $from . "\n";
$headers .= "Content-Transfer-Encoding: 8bit\n";
$headers .= "Content-Type: text/plain; charset=utf-8\n";

// For an HTML message, use these headers:
//$headers .= "MIME-Version: 1.0\n";
//$headers .= "Content-type: text/html; charset=utf-8\n";

if (mail($to, $subject, $msg, $headers) === false) {
    die("Failed to send the email!\n");
}
echo "<!doctype html>\n<html><body>\n";
echo "<pre><xmp>Headers:\n" . $headers . "\nMessage:\n" . $msg . "\n</xmp></pre>";
echo "</body></html>\n";
