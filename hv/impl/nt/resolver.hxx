#pragma once

extern "C" std::uint64_t get_nt_base();

namespace nt
{
	inline constexpr std::uint32_t image_scn_mem_execute = 0x20000000;

	class c_resolver
	{
		std::addr_t m_nt_base{};

	public:
		std::addr_t nt_base() const
		{
			return m_nt_base;
		}

		bool setup()
		{
			m_nt_base = get_nt_base();
			if (!m_nt_base)
				return false;

			auto* const dos = reinterpret_cast<dos_header_t*>(m_nt_base);
			auto* const nt = reinterpret_cast<nt_headers_t*>(m_nt_base + dos->m_lfanew);
			return dos->is_valid() && nt->is_valid();
		}

		std::addr_t lookup_export(const char* export_name) const
		{
			if (!m_nt_base || !export_name)
				return {};

			auto* const dos = reinterpret_cast<dos_header_t*>(m_nt_base);
			auto* const headers = reinterpret_cast<nt_headers_t*>(m_nt_base + dos->m_lfanew);
			if (!dos->is_valid() || !headers->is_valid())
				return {};

			auto* const exp_dir = headers->m_export_table.as_rva<export_directory_t*>(m_nt_base);
			if (!exp_dir->m_address_of_functions || !exp_dir->m_address_of_names || !exp_dir->m_address_of_names_ordinals)
				return {};

			auto* const names = reinterpret_cast<std::int32_t*>(m_nt_base + exp_dir->m_address_of_names);
			auto* const funcs = reinterpret_cast<std::int32_t*>(m_nt_base + exp_dir->m_address_of_functions);
			auto* const ords = reinterpret_cast<std::int16_t*>(m_nt_base + exp_dir->m_address_of_names_ordinals);

			for (std::int32_t i = 0; i < exp_dir->m_number_of_names; ++i)
			{
				auto* const cur_name = reinterpret_cast<char*>(m_nt_base + names[i]);
				const std::addr_t cur_func = m_nt_base + funcs[ords[i]];
				if (cur_name && cur_func && crt::strcmp(export_name, cur_name) == 0)
					return cur_func;
			}

			return {};
		}

		std::addr_t get_system_routine(const char* export_name) const
		{
			return lookup_export(export_name);
		}

		template <typename type>
		type get_system_routine(const char* export_name) const
		{
			return reinterpret_cast<type>(lookup_export(export_name));
		}

		template <typename type>
		type get(std::uint64_t offset) const
		{
			return *reinterpret_cast<type*>(m_nt_base + offset);
		}

		template <typename fn_t>
		void for_each_exec_section(fn_t&& fn) const
		{
			auto* const dos = reinterpret_cast<dos_header_t*>(m_nt_base);
			auto* const headers = reinterpret_cast<nt_headers_t*>(m_nt_base + dos->m_lfanew);
			if (!dos->is_valid() || !headers->is_valid())
				return;

			auto* const section = reinterpret_cast<section_header_t*>(
				reinterpret_cast<std::uintptr_t>(headers) + headers->m_size_of_optional_header + 0x18);

			for (std::int16_t i = 0; i < headers->m_number_of_sections; ++i)
			{
				if ((section[i].m_characteristics & image_scn_mem_execute) == 0)
					continue;

				const std::uint64_t base = m_nt_base + section[i].m_virtual_address;
				const std::uint64_t size = static_cast<std::uint64_t>(
					section[i].m_virtual_size ? section[i].m_virtual_size : section[i].m_size_of_raw_data);
				if (base && size)
					fn(base, size);
			}
		}

		bool next_exec_section(std::uint64_t* exec_base, std::uint64_t* exec_size) const
		{
			if (!exec_base || !exec_size)
				return false;

			*exec_base = 0;
			*exec_size = 0;

			auto* const dos = reinterpret_cast<dos_header_t*>(m_nt_base);
			auto* const headers = reinterpret_cast<nt_headers_t*>(m_nt_base + dos->m_lfanew);
			if (!dos->is_valid() || !headers->is_valid())
				return false;

			auto* const section = reinterpret_cast<section_header_t*>(
				reinterpret_cast<std::uintptr_t>(headers) + headers->m_size_of_optional_header + 0x18);

			for (std::int16_t i = 0; i < headers->m_number_of_sections; ++i)
			{
				if (section[i].m_characteristics & image_scn_mem_execute)
				{
					*exec_base = m_nt_base + section[i].m_virtual_address;
					*exec_size = static_cast<std::uint64_t>(section[i].m_virtual_size
						? section[i].m_virtual_size
						: section[i].m_size_of_raw_data);
					return *exec_base && *exec_size;
				}
			}

			return false;
		}

		std::uintptr_t find_signature(std::uintptr_t base, std::size_t size, const std::uint8_t* signature, const char* mask) const
		{
			const auto sig_length = crt::strlen(mask);
			if (!sig_length || size < sig_length)
				return 0;

			for (std::size_t i = 0; i <= size - sig_length; ++i)
			{
				bool found = true;
				for (std::size_t j = 0; j < sig_length; ++j)
				{
					if (mask[j] == 'x' &&
						*reinterpret_cast<const std::uint8_t*>(base + i + j) != signature[j])
					{
						found = false;
						break;
					}
				}
				if (found)
					return base + i;
			}
			return 0;
		}

		std::uintptr_t find_ida_pattern(std::uintptr_t base, std::size_t size, const char* ida_pattern) const
		{
			std::uint8_t pattern[256]{};
			char mask[256]{};
			std::size_t pattern_size = 0;

			const char* ptr = ida_pattern;
			while (*ptr)
			{
				if (*ptr == ' ')
				{
					++ptr;
					continue;
				}

				if (pattern_size >= 255)
					return 0;

				if (*ptr == '?')
				{
					mask[pattern_size] = '?';
					pattern[pattern_size++] = 0;
					++ptr;
					if (*ptr == '?')
						++ptr;
				}
				else
				{
					char byte_str[3] = { ptr[0], ptr[1], 0 };
					pattern[pattern_size] = static_cast<std::uint8_t>(crt::strtoul(byte_str, nullptr, 16));
					mask[pattern_size++] = 'x';
					ptr += 2;
				}
			}

			mask[pattern_size] = 0;
			return find_signature(base, size, pattern, mask);
		}

		std::uintptr_t find_pattern(std::uintptr_t base, std::size_t size, const char* pattern, const char* mask) const
		{
			const auto pattern_length = crt::strlen(mask);
			if (!pattern_length || size < pattern_length)
				return 0;

			for (std::size_t i = 0; i <= size - pattern_length; ++i)
			{
				bool found = true;
				for (std::size_t j = 0; j < pattern_length; ++j)
				{
					if (mask[j] == 'x' &&
						*reinterpret_cast<const unsigned char*>(base + i + j) != static_cast<unsigned char>(pattern[j]))
					{
						found = false;
						break;
					}
				}
				if (found)
					return base + i;
			}
			return 0;
		}

		std::uintptr_t scan_text_section(const char* pattern, const char* mask) const
		{
			std::uint64_t text_base = 0;
			std::uint64_t text_size = 0;
			if (!next_exec_section(&text_base, &text_size))
				return 0;
			return find_pattern(text_base, text_size, pattern, mask);
		}

		std::uintptr_t scan_ida_pattern(const char* ida_pattern) const
		{
			std::uint64_t text_base = 0;
			std::uint64_t text_size = 0;
			if (!next_exec_section(&text_base, &text_size))
				return 0;
			return find_ida_pattern(text_base, text_size, ida_pattern);
		}

		std::uintptr_t find_reference(std::uintptr_t base, std::size_t size, std::uintptr_t target, std::size_t max_refs = 1) const
		{
			std::uintptr_t result = 0;
			std::size_t found = 0;
			if (size < 7)
				return 0;

			for (std::size_t i = 0; i < size - 7; ++i)
			{
				const auto* bytes = reinterpret_cast<const std::uint8_t*>(base + i);
				if (bytes[0] == 0x48 && bytes[1] == 0x8B && bytes[2] == 0x05)
				{
					const std::int32_t offset = *reinterpret_cast<const std::int32_t*>(base + i + 3);
					if (base + i + 7 + offset == target)
					{
						result = base + i;
						if (++found >= max_refs)
							break;
					}
				}

				if (bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x05)
				{
					const std::int32_t offset = *reinterpret_cast<const std::int32_t*>(base + i + 3);
					if (base + i + 7 + offset == target)
					{
						result = base + i;
						if (++found >= max_refs)
							break;
					}
				}
			}

			return result;
		}

		std::uintptr_t find_global_variable(const char* ida_pattern, std::size_t offset_to_rip = 3) const
		{
			std::uint64_t text_base = 0;
			std::uint64_t text_size = 0;
			if (!next_exec_section(&text_base, &text_size))
				return 0;

			const std::uintptr_t pattern_addr = find_ida_pattern(text_base, text_size, ida_pattern);
			if (!pattern_addr)
				return 0;

			const std::int32_t rip_offset = *reinterpret_cast<std::int32_t*>(pattern_addr + offset_to_rip);
			return pattern_addr + offset_to_rip + 4 + rip_offset;
		}
	};

	c_resolver g_resolver;
}
