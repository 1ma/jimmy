<?php

declare(strict_types=1);

use Bitcoin\Tests\Tx\MockFetcher;
use Bitcoin\Tx\Finder;

require_once __DIR__.'/vendor/autoload.php';

Finder::$fetcher = new MockFetcher();
