<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

/** The entry fails: its fixture or the code under test disagrees with the expectation. */
final class Fail extends \RuntimeException {}
