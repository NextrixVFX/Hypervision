#pragma once

namespace crt
{
	[[nodiscard]] inline std::int32_t strcmp(const char* a, const char* b)
	{
		while (*a != '\0')
		{
			if (*a != *b)
				break;
			++a;
			++b;
		}
		return *a - *b;
	}

	[[nodiscard]] inline std::size_t strlen(const char* str)
	{
		const char* s = str;
		for (; *s; ++s)
			;
		return static_cast<std::size_t>(s - str);
	}

	inline unsigned long strtoul(const char* str, char** endptr, int base)
	{
		while (*str == ' ' || *str == '\t')
			++str;

		if (base == 16 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
			str += 2;

		unsigned long result = 0;
		while (*str)
		{
			int digit = -1;
			if (*str >= '0' && *str <= '9')
				digit = *str - '0';
			else if (*str >= 'a' && *str <= 'f')
				digit = *str - 'a' + 10;
			else if (*str >= 'A' && *str <= 'F')
				digit = *str - 'A' + 10;
			else
				break;

			if (digit >= base)
				break;

			result = result * static_cast<unsigned long>(base) + static_cast<unsigned long>(digit);
			++str;
		}

		if (endptr)
			*endptr = const_cast<char*>(str);
		return result;
	}

	inline void* memcpy(void* dest, const void* src, std::size_t len)
	{
		auto* d = static_cast<char*>(dest);
		const auto* s = static_cast<const char*>(src);
		while (len--)
			*d++ = *s++;
		return dest;
	}

	inline void* memset(void* dest, int value, std::size_t len)
	{
		auto* d = static_cast<unsigned char*>(dest);
		while (len--)
			*d++ = static_cast<unsigned char>(value);
		return dest;
	}
}
