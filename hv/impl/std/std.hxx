#pragma once
#include <intrin.h>
namespace std {
    using int8_t = signed char;
    using int16_t = short;
    using int32_t = int;
    using int64_t = long long;
    using uint8_t = unsigned char;
    using uint16_t = unsigned short;
    using uint32_t = unsigned int;
    using uint64_t = unsigned long long;

    using int_least8_t = signed char;
    using int_least16_t = short;
    using int_least32_t = int;
    using int_least64_t = long long;
    using uint_least8_t = unsigned char;
    using uint_least16_t = unsigned short;
    using uint_least32_t = unsigned int;
    using uint_least64_t = unsigned long long;

    using int_fast8_t = signed char;
    using int_fast16_t = int;
    using int_fast32_t = int;
    using int_fast64_t = long long;
    using uint_fast8_t = unsigned char;
    using uint_fast16_t = unsigned int;
    using uint_fast32_t = unsigned int;
    using uint_fast64_t = unsigned long long;

    using uintptr_t = unsigned long long;
    using addr_t = unsigned long long;
    using size_t = unsigned long long;
    using intmax_t = long long;
    using ptrdiff_t = long long;

    using double_t = double;
    using float_t = float;

    struct m128a_t {
        std::uint64_t m_low;
        std::int64_t m_high;
    };

    struct uint128_t {
        std::uint64_t m_low;
        std::uint64_t m_high;

        uint128_t() : m_low(0), m_high(0) {}
        uint128_t(std::uint64_t low, std::uint64_t high) :
            m_low(low), m_high(high) {
        }

        bool operator==(const uint128_t& other) const {
            return m_low == other.m_low && m_high == other.m_high;
        }

        bool operator!=(const uint128_t& other) const {
            return !(*this == other);
        }

        uint128_t& operator=(std::uint64_t value) {
            m_low = value;
            m_high = 0;
            return *this;
        }
    };
}


enum nt_status_t {
    success,
    unsuccessful = 0xc0000001,
    alerted = 0x101,
    timeout = 0x102,
    pending = 0x103,
    control_c_exit = 0xc000013a,
    buffer_too_small = 0xc0000023,
    info_length_mismatch = 0xc4l,
    insufficient_resources = 0xc9A,
    length_mismatch = 0xc4,
    invalid_parameter = 0xcd,
    access_denied = 0xc0000022,
    access_violation = 0xc5,
    cancelled = 0xc0000120,
    not_supported = 0xc00000bb,
    procedure_not_found = 0xC000007AL,
    invalid_device_state = 0xC0000184L
};

namespace std {
    void* memset(void* dest, int c, size_t count) {
        unsigned char* ptr;
        size_t			i;

        i = 0;
        ptr = (unsigned char*)dest;
        while (i < count) {
            ptr[i++] = c;
        }
        return (dest);
    }
}

enum nt_build_t {
    win11_23h2 = 0x589c,
    win11_22h2 = 0x585d,
    win11_21h2 = 0x55f0,
    win10_22h2 = 0x5a63,
    win10_21h1 = 0x4fc6,
    win10_20h2 = 0x4ec2,
    win10_20h1 = 0x4a61,
    win_server_2022 = 0x5900,
    win_server_2019 = 0x3c5a,
    win_server_2016 = 0x23f0,
    win8_1_update = 0x1db0,
    win8_1 = 0x1a2b,
    win7_sp1 = 0x1db1,
    win7_rtm = 0x1a28
};

enum pe_magic_t {
    dos_header = 0x5a4d,
    nt_headers = 0x4550,
    opt_header = 0x020b
};

struct unicode_string_t {
    std::uint16_t m_length;
    std::uint16_t m_maximum_length;
    wchar_t* m_buffer;
};

struct security_descriptor_t {
    std::uint8_t m_revision;
    std::uint8_t m_sbz1;
    std::uint16_t m_control;
    void* m_owner;
    void* m_group;
    void* m_sacl;
    void* m_dacl;
};

struct dos_header_t {
    std::int16_t m_magic;
    std::int16_t m_cblp;
    std::int16_t m_cp;
    std::int16_t m_crlc;
    std::int16_t m_cparhdr;
    std::int16_t m_minalloc;
    std::int16_t m_maxalloc;
    std::int16_t m_ss;
    std::int16_t m_sp;
    std::int16_t m_csum;
    std::int16_t m_ip;
    std::int16_t m_cs;
    std::int16_t m_lfarlc;
    std::int16_t m_ovno;
    std::int16_t m_res0[0x4];
    std::int16_t m_oemid;
    std::int16_t m_oeminfo;
    std::int16_t m_res1[0xa];
    std::int32_t m_lfanew;

    [[ nodiscard ]]
    constexpr bool is_valid() const {
        return m_magic == pe_magic_t::dos_header;
    }
};

struct data_directory_t {
    std::int32_t m_virtual_address;
    std::int32_t m_size;

    template< class type_t, typename addr_t >
    [[ nodiscard ]]
    type_t as_rva(
        addr_t rva
    ) {
        return reinterpret_cast<type_t>(rva + m_virtual_address);
    }
};

struct import_descriptor_t {
    union {
        std::uint32_t m_characteristics;
        std::uint32_t m_original_first_thunk;
    };
    std::uint32_t m_time_date_stamp;
    std::uint32_t m_forwarder_chain;
    std::uint32_t m_name;
    std::uint32_t m_first_thunk;
};

struct thunk_data_t {
    union {
        std::uint64_t m_forwarder_string;
        std::uint64_t m_function;
        std::uint64_t m_address_of_data;
        std::uint64_t m_ordinal;
    };
};

struct import_by_name_t {
    std::uint16_t m_hint;
    char m_name[1];
};

struct debug_directory_t {
    std::uint32_t m_characteristics;
    std::uint32_t m_time_date_stamp;
    std::uint16_t m_major_version;
    std::uint16_t m_minor_version;
    std::uint32_t m_type;
    std::uint32_t m_size_of_data;
    std::uint32_t m_address_of_raw_data;
    std::uint32_t m_pointer_to_raw_data;
};

struct nt_headers_t {
    std::int32_t m_signature;
    std::int16_t m_machine;
    std::int16_t m_number_of_sections;
    std::int32_t m_time_date_stamp;
    std::int32_t m_pointer_to_symbol_table;
    std::int32_t m_number_of_symbols;
    std::int16_t m_size_of_optional_header;
    std::int16_t m_characteristics;

    std::int16_t m_magic;
    std::int8_t m_major_linker_version;
    std::int8_t m_minor_linker_version;
    std::int32_t m_size_of_code;
    std::int32_t m_size_of_initialized_data;
    std::int32_t m_size_of_uninitialized_data;
    std::int32_t m_address_of_entry_point;
    std::int32_t m_base_of_code;
    std::uint64_t m_image_base;
    std::int32_t m_section_alignment;
    std::int32_t m_file_alignment;
    std::int16_t m_major_operating_system_version;
    std::int16_t m_minor_operating_system_version;
    std::int16_t m_major_image_version;
    std::int16_t m_minor_image_version;
    std::int16_t m_major_subsystem_version;
    std::int16_t m_minor_subsystem_version;
    std::int32_t m_win32_version_value;
    std::int32_t m_size_of_image;
    std::int32_t m_size_of_headers;
    std::int32_t m_check_sum;
    std::int16_t m_subsystem;
    std::int16_t m_dll_characteristics;
    std::uint64_t m_size_of_stack_reserve;
    std::uint64_t m_size_of_stack_commit;
    std::uint64_t m_size_of_heap_reserve;
    std::uint64_t m_size_of_heap_commit;
    std::int32_t m_loader_flags;
    std::int32_t m_number_of_rva_and_sizes;

    data_directory_t m_export_table;
    data_directory_t m_import_table;
    data_directory_t m_resource_table;
    data_directory_t m_exception_table;
    data_directory_t m_certificate_table;
    data_directory_t m_base_relocation_table;
    data_directory_t m_debug;
    data_directory_t m_architecture;
    data_directory_t m_global_ptr;
    data_directory_t m_tls_table;
    data_directory_t m_load_config_table;
    data_directory_t m_bound_import;
    data_directory_t m_iat;
    data_directory_t m_delay_import_descriptor;
    data_directory_t m_clr_runtime_header;
    data_directory_t m_reserved;

    [[ nodiscard ]]
    constexpr bool is_valid() const {
        return m_signature == pe_magic_t::nt_headers
            && m_magic == pe_magic_t::opt_header;
    }
};

struct export_directory_t {
    std::int32_t m_characteristics;
    std::int32_t m_time_date_stamp;
    std::int16_t m_major_version;
    std::int16_t m_minor_version;
    std::int32_t m_name;
    std::int32_t m_base;
    std::int32_t m_number_of_functions;
    std::int32_t m_number_of_names;
    std::int32_t m_address_of_functions;
    std::int32_t m_address_of_names;
    std::int32_t m_address_of_names_ordinals;
};

struct section_header_t {
    char m_name[0x8];
    union {
        std::int32_t m_physical_address;
        std::int32_t m_virtual_size;
    };
    std::int32_t m_virtual_address;
    std::int32_t m_size_of_raw_data;
    std::int32_t m_pointer_to_raw_data;
    std::int32_t m_pointer_to_relocations;
    std::int32_t m_pointer_to_line_numbers;
    std::int16_t m_number_of_relocations;
    std::int16_t m_number_of_line_numbers;
    std::int32_t m_characteristics;
};

struct list_entry_t {
    list_entry_t* m_flink;
    list_entry_t* m_blink;
};

struct single_list_entry_t {
    single_list_entry_t* m_next;
};


namespace std {
    char to_lower(char c) {
        if (c >= 'A' && c <= 'Z')
            return c + ('a' - 'A');
        return c;
    }

    std::size_t wcs_len(const wchar_t* str) {
        if (!str) return 0;
        std::size_t len = 0;
        while (str[len] != L'\0') len++;
        return len;
    }

    bool wchar_equal_ignore_case(wchar_t c1, wchar_t c2) {
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        return c1 == c2;
    }

    const wchar_t* wcsstr_lowercase(const wchar_t* str, const wchar_t* substr) {
        if (!str || !substr || *substr == L'\0')
            return str;

        for (; *str; ++str) {
            const wchar_t* h = str;
            const wchar_t* n = substr;

            while (*h && *n && wchar_equal_ignore_case(*h, *n)) {
                h++;
                n++;
            }

            if (*n == L'\0')
                return str;
        }

        return nullptr;
    }

    const char* strstr(const char* haystack, const char* needle) {
        if (!haystack || !needle)
            return nullptr;

        if (*needle == '\0')
            return haystack;

        for (; *haystack != '\0'; ++haystack) {
            const char* h = haystack;
            const char* n = needle;

            while (*h != '\0' && *n != '\0' && *h == *n) {
                ++h;
                ++n;
            }

            if (*n == '\0')
                return haystack;
        }

        return nullptr;
    }


    unsigned long strtoul(
        const char* str,
        char** endptr,
        int base
    ) {
        while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r')
            str++;

        bool negative = false;
        if (*str == '-') {
            negative = true;
            str++;
        }
        else if (*str == '+') {
            str++;
        }

        if (base == 0) {
            if (*str == '0') {
                str++;
                if (*str == 'x' || *str == 'X') {
                    base = 16;
                    str++;
                }
                else {
                    base = 8;
                }
            }
            else {
                base = 10;
            }
        }
        else if (base == 16) {
            if (*str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X')) {
                str += 2;
            }
        }

        unsigned long result = 0;
        bool valid_digit_found = false;

        while (*str) {
            int digit;

            if (*str >= '0' && *str <= '9') {
                digit = *str - '0';
            }
            else if (*str >= 'a' && *str <= 'z') {
                digit = *str - 'a' + 10;
            }
            else if (*str >= 'A' && *str <= 'Z') {
                digit = *str - 'A' + 10;
            }
            else {
                break;
            }

            if (digit >= base) {
                break;
            }

            valid_digit_found = true;

            if (result > (ULONG_MAX - digit) / base) {
                result = ULONG_MAX;
                break;
            }

            result = result * base + digit;
            str++;
        }

        if (endptr) {
            *endptr = const_cast<char*>(valid_digit_found ? str : str - valid_digit_found);
        }

        return negative ? static_cast<unsigned long>(-static_cast<long>(result)) : result;
    }

    const char* str_str(
        const char* haystack,
        const char* needle
    ) {
        if (!haystack || !needle)
            return nullptr;

        if (!*needle)
            return haystack;

        const char* p1 = haystack;
        while (*p1) {
            const char* p1_begin = p1;
            const char* p2 = needle;

            while (*p1 && *p2 && (*p1 == *p2)) {
                p1++;
                p2++;
            }

            if (!*p2)
                return p1_begin;

            p1 = p1_begin + 1;
        }

        return nullptr;
    }

    int tolower(int c) {
        if (c >= 'A' && c <= 'Z') {
            return c + ('a' - 'A');
        }
        return c;
    }

    char* strtolower(char* str) {
        for (char* p = str; *p != '\0'; ++p) {
            *p = static_cast<char>(tolower(*p));
        }
        return str;
    }

    void* memcpy(
        void* dest,
        const void* src,
        size_t len
    ) {
        char* d = (char*)dest;
        const char* s = (const char*)src;
        while (len--)
            *d++ = *s++;
        return d - reinterpret_cast<char>(dest);
    }

    int wcscmp(
        const wchar_t* s1,
        const wchar_t* s2
    ) {
        while (*s1 == *s2++)
            if (*s1++ == '\0')
                return (0);

        return (*(const unsigned int*)s1 - *(const unsigned int*)--s2);
    }

    std::int32_t strcmp(
        const char* string,
        const char* string_cmp
    ) {
        while (*string != '\0') {
            if (*string != *string_cmp)
                break;
            string++;
            string_cmp++;
        }
        return *string - *string_cmp;
    }

    std::size_t strlen(
        const char* str
    ) {
        const char* s;
        for (s = str; *s; ++s);
        return (s - str);
    }

    static const char null_string[] = "(null)";
    static const char hex_digits[] = "0123456789abcdef";
#define is_digit(c) ((c) >= '0' && (c) <= '9')

    static inline int format_uint(char* buf, unsigned int val) {
        if (val == 0) {
            *buf = '0';
            return 1;
        }

        unsigned int temp = val;
        int num_digits = 0;
        do {
            num_digits++;
            temp /= 10;
        } while (temp > 0);

        int idx = num_digits - 1;
        do {
            buf[idx--] = '0' + (val % 10);
            val /= 10;
        } while (val > 0);

        return num_digits;
    }

    static inline int format_int(char* buf, int val, int* is_negative) {
        unsigned int abs_val;

        if (val < 0) {
            *is_negative = 1;
            abs_val = (val == -2147483648) ? (unsigned int)(-(-2147483648 + 1)) + 1 : (unsigned int)-val;
        }
        else {
            *is_negative = 0;
            abs_val = (unsigned int)val;
        }

        return format_uint(buf, abs_val);
    }

    static inline int format_hex(char* buf, unsigned int val) {
        if (val == 0) {
            *buf = '0';
            return 1;
        }

        int num_digits = 0;
        unsigned int temp = val;

        while (temp) {
            num_digits++;
            temp >>= 4;
        }

        int idx = num_digits - 1;
        temp = val;
        do {
            buf[idx--] = hex_digits[temp & 0xF];
            temp >>= 4;
        } while (temp > 0);

        return num_digits;
    }

    bool strstr_lowercase(const char* haystack, const char* needle) {
        if (!haystack || !needle)
            return false;

        auto haystack_len = std::strlen(haystack);
        auto needle_len = std::strlen(needle);

        if (needle_len > haystack_len)
            return false;

        for (std::size_t i = 0; i <= haystack_len - needle_len; i++) {
            bool match = true;
            for (std::size_t j = 0; j < needle_len; j++) {
                if (to_lower(haystack[i + j]) != to_lower(needle[j])) {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }

    static inline int fast_strcpy(char* dst, const char* src, size_t max) {
        const char* s = src;
        int len = 0;
        size_t i = 0;

        if (dst != NULL && max > 0) {
            while (*s && i < max) {
                *dst++ = *s++;
                len++;
                i++;
            }
        }

        while (*s) {
            len++;
            s++;
        }

        return len;
    }
}
