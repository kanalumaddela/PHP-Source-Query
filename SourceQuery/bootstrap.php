<?php

/**
 * Library to query servers that implement Source Engine Query protocol.
 *
 * Special thanks to koraktor for his awesome Steam Condenser class,
 * I used it as a reference at some points.
 *
 * @author  Pavel Djundik <sourcequery@xpaw.me>
 *
 * @link    https://xpaw.me
 * @link    https://github.com/xPaw/PHP-Source-Query
 *
 * @license GNU Lesser General Public License, version 2.1
 */

/*
 * Replacement to previous "autoloader".
 *
 * @author kanalumaddela <git@maddela.org>
 */
\spl_autoload_register(function ($class) {
    $namespace = 'xPaw\\SourceQuery\\';

    if (\strncmp($namespace, $class, $length = \strlen($namespace)) !== 0) {
        return;
    }

    $file = __DIR__.DIRECTORY_SEPARATOR.\str_replace('\\', DIRECTORY_SEPARATOR, \substr($class, $length)).'.php';

    if (\file_exists($file)) {
        require_once $file;
    }
});
