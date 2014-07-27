<?php
/*
 * Upload a file in an "upload" directory.
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
<html>
    <head>
        <title>Upload</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    </head>
    <body>
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="POST" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
        <p>php.ini configuration:
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
        echo '<li>' . $k . ' = ' . htmlentities($v) . PHP_EOL;
    }
?>
        </ul>
    </body>
</html>
