<?php
/*
 * These HTTP headers disable caching from clients
 */
$now = gmdate('D, d M Y H:i:s');
header('Last modified: ' . $now . ' GMT');
header('Expire: ' . $now . ' GMT');
header('Cache-control: no-cache, must-revalidate');
header('Pragma: no-cache');
