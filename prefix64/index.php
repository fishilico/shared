<?php
    $srvaddr = strtolower($_SERVER['SERVER_ADDR']);
    $newaddr = null;
    $network = 'an unknown network';
    $matches = null;
    if (preg_match(
        '/^([0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}):/',
        $srvaddr, $matches))
    {
        $network = $matches[1] . '::/64';
        $newaddr = $matches[1];
        $newaddr .= ':' . dechex(rand(0, 0xffff));
        $newaddr .= ':' . dechex(rand(0, 0xffff));
        $newaddr .= ':' . dechex(rand(0, 0xffff));
        $newaddr .= ':' . dechex(rand(0, 0xffff));
    }
?>
<!DOCTYPE html>
<html>
<head>
    <title>IPv6 /64 prefix experiment</title>
</head>
<body>
    <h1>IPv6 /64 prefix experiment</h1>
    <p>
    This page is a proof of concept that one server can listen to 2^64 IPv6 addresses!
    </p>
    <p>
    This server is configured to listen on <code><?php echo $network; ?></code>.
    </p>
    <p>
    My IP address is currently <code><?php echo htmlentities($srvaddr); ?></code>.
<?php if ($newaddr): ?>
    <a href="http://[<?php echo $newaddr; ?>]">Try another one!</a>.
<?php endif; ?>
    </p>
    <p>
    By the way, your IP address is <code><?php echo htmlentities($_SERVER['REMOTE_ADDR']); ?></code>.
    </p>
    <p>
    More information <a href="https://github.com/fishilico/shared/tree/master/prefix64">here</a>.
    </p>
</body>
</html>
