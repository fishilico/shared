<?php
/*
 * Upload a file in an directory, upload/
 *
 * NB. Do not use this file as-is. This is an arbitrary file upload with
 * arbitrary extension, so it would introduce a Remote Code Execution (RCE)
 * vulnerability, because it allows uploading a PHP file ending with .php,
 * .php3, .phtml, etc.
 * If you want to use this file, please evaluate the security of this.
 * If you still want to use this file, you may consider adding a password with
 * something like:
 *
 *     $pwhash = '$6$...';
 *     hash_equals($pwhash, crypt(@$_GET['p'], $pwhash)) or die('Forbidden');
 */
if (!empty($_FILES['file'])) {
    $tmp_file = $_FILES['file']['tmp_name'];
    $new_file = 'upload/' . $_FILES['file']['name'];
    $size = $_FILES['file']['size'];
    $mime_type = $_FILES['file']['type'];

    is_uploaded_file($tmp_file) or die('Upload file not found (' . $tmp_file . ')');
    move_uploaded_file($tmp_file, $new_file) or die('Upload to ' . $new_file . ' failed');
    chmod($new_file, 0644);
}
?>
<!doctype html>
<html lang="en">
    <head>
        <title>Upload</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    </head>
    <body>
<?php if (!empty($_FILES['file'])): ?>
        <p>
            <?php
                echo 'Uploaded <code>' . htmlentities($tmp_file) . '</code>' .
                    ' to <code>' . htmlentities($new_file) . '</code>' .
                    ' (' . $size . ' bytes, ' . htmlentities($mime_type) . ')' . PHP_EOL;
            ?>
        </p>
<?php endif ?>
<?php if (!is_dir('upload')): ?>
        <p>Warning: directory <code>upload/</code> does not exist!</p>
<?php endif ?>
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="POST" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
        <p>php.ini configuration:</p>
        <ul>
<?php
    foreach(array(
        'file_uploads',
        'max_file_uploads',
        'post_max_size',
        'upload_max_filesize',
        'upload_tmp_dir') as $k)
    {
        $v = ini_get($k);
        echo '<li><code>' . $k . '</code> = ' . htmlentities($v) . PHP_EOL;
    }
?>
        </ul>
    </body>
</html>
