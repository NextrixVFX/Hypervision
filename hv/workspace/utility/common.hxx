#pragma once

constexpr auto page_4kb_size = 0x1000ull;
constexpr auto page_2mb_size = 0x200000ull;
constexpr auto page_4kb_mask = 0xFFFull;
constexpr auto page_2mb_mask = 0x1FFFFFull;
constexpr auto page_shift = 12ull;

constexpr auto host_stack_size = 32ull * 1024ull;
constexpr auto msrpm_size = 0x1800ull;
constexpr auto iopm_size = 0x3000ull;
constexpr auto npt_max_pages = 1024u;
constexpr auto split_max_hooks = 16u;
