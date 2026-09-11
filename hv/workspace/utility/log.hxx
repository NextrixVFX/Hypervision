#pragma once

#define hv_log(fmt, ...) \
	nt::dbg_print("hv: " fmt "\n", ##__VA_ARGS__)
