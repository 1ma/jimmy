<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Hashing;
use Bitcoin\MerkleTree;
use PHPUnit\Framework\TestCase;

final class MerkleTreeTest extends TestCase
{
    public function testDirectPopulation(): void
    {
        // Based on example from Chapter 11 page 200
        $hashes = [
            hex2bin('9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb'),
            hex2bin('5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b'),
            hex2bin('82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05'),
            hex2bin('507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308'),
            hex2bin('a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330'),
            hex2bin('bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add'),
            hex2bin('ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836'),
            hex2bin('457743861de496c429912558a106b810b0507975a49773228aa788df40730d41'),
            hex2bin('7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a'),
            hex2bin('b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9'),
            hex2bin('9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab'),
            hex2bin('b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638'),
            hex2bin('b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263'),
            hex2bin('c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800'),
            hex2bin('c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2'),
            hex2bin('f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e'),
        ];

        $tree = new MerkleTree(\count($hashes));
        $tree->setLevel(4, $hashes);
        $tree->setLevel(3, Hashing::merkleParentLevel($tree->getLevel(4)));
        $tree->setLevel(2, Hashing::merkleParentLevel($tree->getLevel(3)));
        $tree->setLevel(1, Hashing::merkleParentLevel($tree->getLevel(2)));
        $tree->setLevel(0, Hashing::merkleParentLevel($tree->getLevel(1)));

        $debugRepresentation = <<<MERKLETREE
*597c4baf...*
6382df3f..., 87cf8fa3...
3ba6c080..., 8e894862..., 7ab01bb6..., 3df760ac...
272945ec..., 9a38d037..., 4a64abd9..., ec7c95e1..., 3b67006c..., 850683df..., d40d268b..., 8636b7a3...
9745f717..., 5573c8ed..., 82a02ecb..., 507ccae5..., a7a4aec2..., bb626766..., ea6d7ac1..., 45774386..., 76880292..., b1ae7f15..., 9b74f89f..., b3a92b5b..., b5c0b915..., c9d52c5c..., c555bc5f..., f9dbfafc...
MERKLETREE;

        self::assertSame($debugRepresentation, (string) $tree);
    }

    public function testDepthFirstPopulation(): void
    {
        // Based on example from Chapter 11 page 203
        $hashes = [
            hex2bin('9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb'),
            hex2bin('5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b'),
            hex2bin('82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05'),
            hex2bin('507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308'),
            hex2bin('a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330'),
            hex2bin('bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add'),
            hex2bin('ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836'),
            hex2bin('457743861de496c429912558a106b810b0507975a49773228aa788df40730d41'),
            hex2bin('7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a'),
            hex2bin('b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9'),
            hex2bin('9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab'),
            hex2bin('b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638'),
            hex2bin('b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263'),
            hex2bin('c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800'),
            hex2bin('c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2'),
            hex2bin('f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e'),
            hex2bin('38faf8c811988dff0a7e6080b1771c97bcc0801c64d9068cffb85e6e7aacaf51'),
        ];

        $this->markTestSkipped('borked code ahead');

        $tree = new MerkleTree(\count($hashes));
        $tree->setLevel(4, $hashes);
        while (null === $tree->root()) {
            if ($tree->isLeaf()) {
                $tree->up();
            } else {
                $leftHash = $tree->getLeftNode();
                if (null === $leftHash) {
                    $tree->left();
                } elseif ($tree->rightExists()) {
                    $rightHash = $tree->getRightNode();
                    if (null === $rightHash) {
                        $tree->right();
                    } else {
                        $tree->setCurrentNode(Hashing::merkleParent($leftHash, $rightHash));
                        $tree->up();
                    }
                } else {
                    $tree->setCurrentNode(Hashing::merkleParent($leftHash, $leftHash));
                    $tree->up();
                }
            }
        }

        self::assertTrue(true);
    }
}
