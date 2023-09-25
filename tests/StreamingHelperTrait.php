<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

trait StreamingHelperTrait
{
    /**
     * @return resource
     */
    private static function stream(string $data)
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $data);
        rewind($stream);

        return $stream;
    }
}
