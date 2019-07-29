PHP stream wrappers
====================

Filter wrapper
--------------

PHP can open virtual files with ``php://`` scheme using wrappers.
A powerful one is ``php://filter``, which can be used to apply a transformation on a resource.

Examples from the official documentation about stream wrappers (https://www.php.net/manual/en/wrappers.php.php#wrappers.php.filter):

* ``php://filter/resource=http://www.example.com`` reads from a remote URL if ``allow_url_fopen`` configuration is enabled
* ``readfile("php://filter/read=string.toupper|string.rot13/resource=http://www.example.com");`` downloads a page, transforms it in uppercase characters, and encodes using ROT13
* ``file_put_contents("php://filter/write=string.rot13/resource=example.txt", "Hello World");`` encodes the content using ROT13 and writes it into a text file

Other examples:

* ``include("php://filter/convert.base64-encode/resource=index.php")`` displays the source code of ``index.php``, encoded using base64


Data wrapper
------------

Another stream wrapper that can be useful is ``data://`` (https://www.php.net/manual/en/wrappers.data.php).

Example: ``echo file_get_contents('data://text/plain;base64,SSBsb3ZlIFBIUAo=');`` decodes the content with Base64 and prints ``"I love PHP\n"``

The base64 string needs to be URL-encoded (``/`` becomes ``%2f``, ``+`` becomes ``%2b`` and ``=`` becomes ``%3d``) when used in a URL.
This can be used to transform a Local File Inclusion (LFI) vulnerability into a Remote Code Execution (RCE) one, when ``include()`` is used with a user-controlled value.
This has been described in several websites such as https://www.idontplaydarts.com/2011/03/php-remote-file-inclusion-command-shell-using-data-stream/
