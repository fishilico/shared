<?php
/*
 * Download a text file using PHP to configure HTTP headers.
 */
$filename = 'my_download.txt';
$cache_duration = 86400;  // a day

// Force browsers to download the output instead of showing it.
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Type: text/plain; charset=utf-8; name="' . $filename . '"');

// For binary data, use:
//header('Content-Type: application/force-download; name="' . $filename . '"');
//header('Content-Transfer-Encoding: binary');

header('Cache-Control: max-age=' . $cache_duration);
header('Expires: ' . gmdate('D, d M Y H:i:s', time() + $cache_duration) . ' GMT');

// Send a file to the client
$filepath = 'download_file.txt';
header('Content-Length: ' . filesize($filepath));
readfile($filepath);
exit;
