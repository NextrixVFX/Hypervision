#pragma once

#define copy_physical 1
#define copy_virtual 2

constexpr auto page_4kb_size = 0x1000ull;
constexpr auto page_2mb_size = 0x200000ull;
constexpr auto page_1gb_size = 0x40000000ull;
constexpr auto page_4kb_mask = 0xFFFull;
constexpr auto page_2mb_mask = 0x1FFFFFull;
constexpr auto page_1gb_mask = 0x3FFFFFFFull;
constexpr auto page_shift = 12ull;
constexpr auto user_address_limit = 0x00007FFFFFFEFFFFull;

constexpr auto host_stack_size = 64ull * 1024ull;
constexpr auto msrpm_size = 0x1800ull;
constexpr auto iopm_size = 0x3000ull;
constexpr auto npt_max_pages = 1024u;
constexpr auto npt_spare_pages = 128u;
constexpr auto split_max_hooks = 16u;
constexpr auto phys_map_chunk = 16ull * 1024ull * 1024ull;
constexpr auto phys_map_max = 4096u;
