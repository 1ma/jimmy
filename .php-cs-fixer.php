<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__.'/src',
        __DIR__.'/tests',
    ]);

return (new PhpCsFixer\Config())
    ->setFinder($finder)
    ->setUsingCache(false)
    ->setRiskyAllowed(true)
    ->setRules([
        '@Symfony'               => true,
        '@Symfony:risky'         => true,
        'array_indentation'      => true,
        'binary_operator_spaces' => ['default' => 'align_single_space_minimal'],
        'declare_strict_types'   => true,
    ]);
