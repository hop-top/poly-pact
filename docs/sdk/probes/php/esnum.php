<?php // Shared by the Q4 probes (probe-only): ECMAScript number text for a float, from the shortest round-trip digits (found with sprintf %e, no ini setting is read).
function es_num(float $x): string { // ECMA-262 Number::toString(10)
    if (!is_finite($x)) throw new DomainException('non-finite number');
    if ($x == 0) return '0'; // also -0.0
    $a = abs($x);
    for ($p = 0; $p < 17; $p++) { // p + 1 significant digits: the nearest decimal first, then (binade boundary) the neighbour on the other side of $a
        [$m, $e] = explode('e', sprintf('%.' . $p . 'e', $a)); $D = (int) str_replace('.', '', $m); $E = (int) $e - $p;
        foreach ([$D, (float) ($D . 'e' . $E) > $a ? $D - 1 : $D + 1] as $c) if ((float) ($c . 'e' . $E) === $a) break 2;
    }
    $d = rtrim((string) $c, '0'); $k = strlen($d); $n = $E + strlen((string) $c); // value = 0.d x 10^n
    if ($k <= $n && $n <= 21) $t = $d . str_repeat('0', $n - $k);
    elseif (0 < $n && $n <= 21) $t = substr($d, 0, $n) . '.' . substr($d, $n);
    elseif (-6 < $n && $n <= 0) $t = '0.' . str_repeat('0', -$n) . $d;
    else $t = $d[0] . ($k > 1 ? '.' . substr($d, 1) : '') . 'e' . ($n - 1 < 0 ? '-' : '+') . abs($n - 1);
    return ($x < 0 ? '-' : '') . $t;
}
