<?php
/*
 * This file show how to make an HTTP redirection using PHP (HTTP headers),
 * HTML (meta tag) and javascript.
 */
// Code from http://php.net/manual/en/function.header.php
$scheme = 'http' . (empty($_SERVER['HTTPS']) ? '' : 's') . '://';
$host = $_SERVER['HTTP_HOST'];
$uri = rtrim(dirname($_SERVER['PHP_SELF']), '/\\') . '/newpage';
$newloc = $scheme . $host . $uri;

// The Location header automatically change the HTTP status code to "302 Found"
header('Location: ' . $newloc);
?>
<!doctype html>
<html>
    <head>
        <title>Redirection</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <!-- It is possible to replace 0 with a number which defines a delay -->
        <meta http-equiv="refresh" content="0;url=<?php echo $newloc; ?>">
        <script language="javascript"><!--
            window.location = "<?php echo $newloc; ?>";
        --></script>
    </head>
    <body>
        <a href="<?php echo $newloc; ?>">Redirecting here...</a>.
    </body>
</html>
