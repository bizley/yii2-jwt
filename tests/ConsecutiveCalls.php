<?php

declare(strict_types=1);

namespace bizley\tests;

use PHPUnit\Framework\Assert;

class ConsecutiveCalls extends Assert
{
    public const NEVER = 'never';
    public const RETURN = 'return';

    /**
     * @param array<mixed[]> $data
     */
    public function __construct(private array $data, private readonly string $mode = self::RETURN)
    {

    }

    /**
     * @param mixed ...$args
     * @return mixed|void|null
     */
    public function __invoke(...$args)
    {
        $testData = \array_shift($this->data);

        if ($this->mode === self::NEVER) {
            self::assertSame($testData, $args);
        } else {
            $returned = $testData ? \array_pop($testData) : null;
            self::assertSame($testData, $args);

            return $returned;
        }
    }
}
