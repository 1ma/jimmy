<?php

declare(strict_types=1);

namespace Bitcoin;

final class MerkleTree
{
    private readonly int $total;
    private mixed $nodes;
    private int $currentDepth;
    private int $currentIndex;

    public function __construct(int $total)
    {
        $this->total        = $total;
        $this->currentIndex = 0;
        $this->currentDepth = 0;
        $maxDepth           = \strlen(decbin($this->total));

        $this->nodes = [];
        for ($depth = 1; $depth <= $maxDepth; ++$depth) {
            $numItems      = $this->total / (2 ** ($maxDepth - $depth));
            $levelHashes   = array_fill(0, $numItems, null);
            $this->nodes[] = $levelHashes;
        }
    }

    public static function fromLeaves(array $leaves): self
    {
        $tree = new self(\count($leaves));

        $depth = \count($tree->nodes);
        $tree->setLevel($depth - 1, $leaves);

        for ($level = $depth - 2; $level >= 0; --$level) {
            $tree->setLevel($level, Hashing::merkleParentLevel($tree->getLevel($level + 1)));
        }

        return $tree;
    }

    public function getLevel(int $level): array
    {
        if (!\array_key_exists($level, $this->nodes)) {
            throw new \InvalidArgumentException('idjit');
        }

        return $this->nodes[$level];
    }

    public function setLevel(int $level, array $items): void
    {
        if (!\array_key_exists($level, $this->nodes) || \count($this->nodes[$level]) !== \count($items)) {
            throw new \InvalidArgumentException('booo you suck');
        }

        $this->nodes[$level] = $items;
    }

    public function __toString(): string
    {
        $result = [];
        foreach ($this->nodes as $i => $node) {
            $items = [];
            foreach ($node as $j => $item) {
                if (null === $item) {
                    $short = 'null';
                } else {
                    $short = substr(bin2hex($item), 0, 8).'...';
                }

                if ($i === $this->currentDepth && $j === $this->currentIndex) {
                    $items[] = '*'.$short.'*';
                } else {
                    $items[] = $short;
                }
            }
            $result[] = implode(', ', $items);
        }

        return implode("\n", $result);
    }
}
