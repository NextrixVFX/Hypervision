#pragma once

namespace cpu
{
	inline void run_on_each(void (*fn)())
	{
		const ULONG count = nt::ke_query_active_processor_count_ex(ALL_PROCESSOR_GROUPS);
		for (ULONG i = 0; i < count; ++i)
		{
			PROCESSOR_NUMBER number{};
			nt::ke_get_processor_number_from_index(i, &number);

			GROUP_AFFINITY next{};
			GROUP_AFFINITY previous{};
			next.Group = number.Group;
			next.Mask = 1ull << number.Number;
			nt::ke_set_system_group_affinity_thread(&next, &previous);
			fn();
			nt::ke_revert_to_user_group_affinity_thread(&previous);
		}
	}
}
