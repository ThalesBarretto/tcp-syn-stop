// SPDX-License-Identifier: GPL-2.0-only
#ifndef COMPILER_H
#define COMPILER_H

/* Branch prediction hints for hot-path conditionals. */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#endif /* COMPILER_H */
