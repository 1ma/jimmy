<?php

declare(strict_types=1);

namespace Bitcoin;

final class MerkleTree
{
    private readonly int $total;
    private readonly int $maxDepth;
    private mixed $nodes;
    private int $currentDepth;
    private int $currentIndex;

    public function __construct(int $total)
    {
        $this->total        = $total;
        $this->currentIndex = 0;
        $this->currentDepth = 0;
        $this->maxDepth     = \strlen(decbin($this->total));

        $this->nodes = [];
        for ($depth = 1; $depth <= $this->maxDepth; ++$depth) {
            $numItems      = (int) floor($this->total / (2 ** ($this->maxDepth - $depth)));
            $levelHashes   = array_fill(0, $numItems, null);
            $this->nodes[] = $levelHashes;
        }
    }

    public function up(): void
    {
        --$this->currentDepth;
        $this->currentIndex = intdiv($this->currentIndex, 2);
    }

    public function left(): void
    {
        ++$this->currentDepth;
        $this->currentIndex *= 2;
    }

    public function right(): void
    {
        ++$this->currentDepth;
        $this->currentIndex *= 2 + 1;
    }

    public function root(): ?string
    {
        return $this->nodes[0][0];
    }

    public function setCurrentNode(string $item): void
    {
        $this->nodes[$this->currentDepth][$this->currentIndex] = $item;
    }

    public function getCurrentNode(array $items): ?string
    {
        return $this->nodes[$this->currentDepth][$this->currentIndex];
    }

    public function getLeftNode(): ?string
    {
        return $this->nodes[$this->currentDepth + 1][$this->currentIndex * 2];
    }

    public function getRightNode(): ?string
    {
        return $this->nodes[$this->currentDepth + 1][$this->currentIndex * 2 + 1];
    }

    public function isLeaf(): bool
    {
        return $this->currentDepth == $this->maxDepth;
    }

    public function rightExists(): bool
    {
        return \count($this->nodes[$this->currentDepth + 1]) > $this->currentIndex * 2 + 1;
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
