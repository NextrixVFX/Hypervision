#pragma once

namespace gadgets
{
	enum class gadget_t : std::uint8_t
	{
		POP_RAX_RET,
		POP_RCX_RET,
		POP_RDX_RET,
		POP_RBX_RET,
		POP_RSP_RET,
		POP_RBP_RET,
		POP_RSI_RET,
		POP_RDI_RET,
		POP_R8_RET,
		POP_R9_RET,
		POP_R10_RET,
		POP_R11_RET,
		POP_R12_RET,
		POP_R13_RET,
		POP_R14_RET,
		POP_R15_RET,
		MOV_RAX_IMM64_RET,
		MOV_RCX_IMM64_RET,
		MOV_RDX_IMM64_RET,
		MOV_RBX_IMM64_RET,
		MOV_RSP_IMM64_RET,
		MOV_RBP_IMM64_RET,
		MOV_RSI_IMM64_RET,
		MOV_RDI_IMM64_RET,
		PUSH_IMM32_RET,
		ADD_RAX_IMM32_RET,
		ADD_RCX_IMM32_RET,
	};

	struct descriptor_t
	{
		gadget_t id{};
		const char* name{};
		const std::uint8_t* pattern{};
		std::size_t pattern_len{};
		std::uint32_t imm_offset{};
		std::uint8_t imm_size{};
	};

	struct info_t
	{
		std::uint64_t address;
		gadget_t id;
		std::uint32_t imm_offset;
		std::uint8_t imm_size;
		bool used;
	};

	inline const std::uint8_t pat_pop_rax_ret[] = { 0x58, 0xC3 };
	inline const std::uint8_t pat_pop_rcx_ret[] = { 0x59, 0xC3 };
	inline const std::uint8_t pat_pop_rdx_ret[] = { 0x5A, 0xC3 };
	inline const std::uint8_t pat_pop_rbx_ret[] = { 0x5B, 0xC3 };
	inline const std::uint8_t pat_pop_rsp_ret[] = { 0x5C, 0xC3 };
	inline const std::uint8_t pat_pop_rbp_ret[] = { 0x5D, 0xC3 };
	inline const std::uint8_t pat_pop_rsi_ret[] = { 0x5E, 0xC3 };
	inline const std::uint8_t pat_pop_rdi_ret[] = { 0x5F, 0xC3 };
	inline const std::uint8_t pat_pop_r8_ret[] = { 0x41, 0x58, 0xC3 };
	inline const std::uint8_t pat_pop_r9_ret[] = { 0x41, 0x59, 0xC3 };
	inline const std::uint8_t pat_pop_r10_ret[] = { 0x41, 0x5A, 0xC3 };
	inline const std::uint8_t pat_pop_r11_ret[] = { 0x41, 0x5B, 0xC3 };
	inline const std::uint8_t pat_pop_r12_ret[] = { 0x41, 0x5C, 0xC3 };
	inline const std::uint8_t pat_pop_r13_ret[] = { 0x41, 0x5D, 0xC3 };
	inline const std::uint8_t pat_pop_r14_ret[] = { 0x41, 0x5E, 0xC3 };
	inline const std::uint8_t pat_pop_r15_ret[] = { 0x41, 0x5F, 0xC3 };
	inline const std::uint8_t pat_mov_rax_imm64_ret[] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_mov_rcx_imm64_ret[] = { 0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_mov_rdx_imm64_ret[] = { 0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_mov_rbx_imm64_ret[] = { 0x48, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_mov_rsp_imm64_ret[] = { 0x48, 0xBC, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_mov_rbp_imm64_ret[] = { 0x48, 0xBD, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_mov_rsi_imm64_ret[] = { 0x48, 0xBE, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_mov_rdi_imm64_ret[] = { 0x48, 0xBF, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_push_imm32_ret[] = { 0x68, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_add_rax_imm32_ret[] = { 0x48, 0x05, 0, 0, 0, 0, 0xC3 };
	inline const std::uint8_t pat_add_rcx_imm32_ret[] = { 0x48, 0x81, 0xC1, 0, 0, 0, 0, 0xC3 };

	inline const descriptor_t descriptor_ts[] = {
		{ gadget_t::POP_RAX_RET, "pop rax; ret", pat_pop_rax_ret, 2, 0, 0 },
		{ gadget_t::POP_RCX_RET, "pop rcx; ret", pat_pop_rcx_ret, 2, 0, 0 },
		{ gadget_t::POP_RDX_RET, "pop rdx; ret", pat_pop_rdx_ret, 2, 0, 0 },
		{ gadget_t::POP_RBX_RET, "pop rbx; ret", pat_pop_rbx_ret, 2, 0, 0 },
		{ gadget_t::POP_RSP_RET, "pop rsp; ret", pat_pop_rsp_ret, 2, 0, 0 },
		{ gadget_t::POP_RBP_RET, "pop rbp; ret", pat_pop_rbp_ret, 2, 0, 0 },
		{ gadget_t::POP_RSI_RET, "pop rsi; ret", pat_pop_rsi_ret, 2, 0, 0 },
		{ gadget_t::POP_RDI_RET, "pop rdi; ret", pat_pop_rdi_ret, 2, 0, 0 },
		{ gadget_t::POP_R8_RET, "pop r8; ret", pat_pop_r8_ret, 3, 0, 0 },
		{ gadget_t::POP_R9_RET, "pop r9; ret", pat_pop_r9_ret, 3, 0, 0 },
		{ gadget_t::POP_R10_RET, "pop r10; ret", pat_pop_r10_ret, 3, 0, 0 },
		{ gadget_t::POP_R11_RET, "pop r11; ret", pat_pop_r11_ret, 3, 0, 0 },
		{ gadget_t::POP_R12_RET, "pop r12; ret", pat_pop_r12_ret, 3, 0, 0 },
		{ gadget_t::POP_R13_RET, "pop r13; ret", pat_pop_r13_ret, 3, 0, 0 },
		{ gadget_t::POP_R14_RET, "pop r14; ret", pat_pop_r14_ret, 3, 0, 0 },
		{ gadget_t::POP_R15_RET, "pop r15; ret", pat_pop_r15_ret, 3, 0, 0 },
		{ gadget_t::MOV_RAX_IMM64_RET, "mov rax, imm64; ret", pat_mov_rax_imm64_ret, 11, 2, 8 },
		{ gadget_t::MOV_RCX_IMM64_RET, "mov rcx, imm64; ret", pat_mov_rcx_imm64_ret, 11, 2, 8 },
		{ gadget_t::MOV_RDX_IMM64_RET, "mov rdx, imm64; ret", pat_mov_rdx_imm64_ret, 11, 2, 8 },
		{ gadget_t::MOV_RBX_IMM64_RET, "mov rbx, imm64; ret", pat_mov_rbx_imm64_ret, 11, 2, 8 },
		{ gadget_t::MOV_RSP_IMM64_RET, "mov rsp, imm64; ret", pat_mov_rsp_imm64_ret, 11, 2, 8 },
		{ gadget_t::MOV_RBP_IMM64_RET, "mov rbp, imm64; ret", pat_mov_rbp_imm64_ret, 11, 2, 8 },
		{ gadget_t::MOV_RSI_IMM64_RET, "mov rsi, imm64; ret", pat_mov_rsi_imm64_ret, 11, 2, 8 },
		{ gadget_t::MOV_RDI_IMM64_RET, "mov rdi, imm64; ret", pat_mov_rdi_imm64_ret, 11, 2, 8 },
		{ gadget_t::PUSH_IMM32_RET, "push imm32; ret", pat_push_imm32_ret, 6, 1, 4 },
		{ gadget_t::ADD_RAX_IMM32_RET, "add rax, imm32; ret", pat_add_rax_imm32_ret, 7, 2, 4 },
		{ gadget_t::ADD_RCX_IMM32_RET, "add rcx, imm32; ret", pat_add_rcx_imm32_ret, 8, 3, 4 },
	};

	inline constexpr std::size_t num_descriptor_ts = sizeof(descriptor_ts) / sizeof(descriptor_ts[0]);
	inline constexpr std::uint32_t cache_capacity = 512;

	class c_scanner
	{
		info_t m_cache[cache_capacity];
		std::uint32_t m_count;

		bool matches(const std::uint8_t* bytes, const descriptor_t& desc) const
		{
			for (std::size_t p = 0; p < desc.pattern_len; ++p)
			{
				if (desc.imm_size && p >= desc.imm_offset && p < desc.imm_offset + desc.imm_size)
					continue;
				if (bytes[p] != desc.pattern[p])
					return false;
			}
			return true;
		}

		bool push(std::uint64_t address, const descriptor_t& desc)
		{
			if (m_count >= cache_capacity)
				return false;
			m_cache[m_count++] = { address, desc.id, desc.imm_offset, desc.imm_size, false };
			return true;
		}

	public:
		std::uint32_t count() const
		{
			return m_count;
		}

		const info_t* at(std::uint32_t index) const
		{
			return index < m_count ? &m_cache[index] : nullptr;
		}

		void scan_range(std::uint64_t base, std::uint64_t size)
		{
			if (!base || size < 2)
				return;

			const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
			for (std::uint64_t offset = 0; offset + 2 <= size; ++offset)
			{
				for (std::size_t idx = 0; idx < num_descriptor_ts; ++idx)
				{
					const auto& desc = descriptor_ts[idx];
					if (offset + desc.pattern_len > size)
						continue;
					if (!matches(bytes + offset, desc))
						continue;
					if (!push(base + offset, desc))
						return;
				}
			}
		}

		bool setup()
		{
			if (m_count)
				return true;

			nt::g_resolver.for_each_exec_section([&](std::uint64_t base, std::uint64_t size)
			{
				if (m_count < cache_capacity)
					scan_range(base, size);
			});

			return m_count > 0;
		}

		std::uint64_t find(gadget_t id)
		{
			for (std::uint32_t i = 0; i < m_count; ++i)
			{
				if (m_cache[i].id == id)
					return m_cache[i].address;
			}
			return 0;
		}

		std::uint64_t find_unused(gadget_t id, info_t* out = nullptr)
		{
			for (std::uint32_t i = 0; i < m_count; ++i)
			{
				if (m_cache[i].id != id || m_cache[i].used)
					continue;
				m_cache[i].used = true;
				if (out)
					*out = m_cache[i];
				return m_cache[i].address;
			}
			return 0;
		}
	};

	c_scanner g_gadgets;
}
