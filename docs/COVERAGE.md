# Coverage evidence

The strict gate reads every DA and BRDA production source record emitted by
upstream LLVM LCOV from the same test execution. Each must have positive hits;
there are no production exclusions. Raw JSON and the original JSON diagnostic
checker remain available. This is source coverage, not coverage of every generic
instantiation; LLVM summary counters can retain an uncovered instantiation even
when emitted source records have both outcomes. An empty line report refuses.
A facade with no instrumentable branches still requires every emitted line.

The shared policy checker also requires the same raw JSON file inventory,
complete branch-location inventory and matching upstream summary metadata.
Truncated, duplicate or malformed LCOV records fail before coverage is counted.
