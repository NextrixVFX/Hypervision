#pragma once

#pragma warning(disable : 4996)
#pragma warning(disable : 4201)
#pragma warning(disable : 4011)

extern "C" int _fltused = 0;

#include <ntifs.h>
#include <intrin.h>
#include <stdarg.h>
#include <ntddk.h>
#include <cstdint>
#include <ntddmou.h>

#include <impl/std/std.hxx>
#include <impl/ia32/ia32.hxx>
#include <impl/crt/crt.hxx>
#include <impl/amd/svm.hxx>
#include <impl/nt/resolver.hxx>
#include <impl/nt/exports.hxx>
#include <impl/nt/nt.hxx>
#include <impl/gadgets/gadgets.hxx>

#include <workspace/utility/common.hxx>
#include <workspace/utility/log.hxx>
#include <workspace/utility/cpu.hxx>
#include <workspace/core/npt/npt.hxx>
#include <workspace/core/mm/physical.hxx>
#include <workspace/core/mm/paging.hxx>
#include <workspace/core/mm/process.hxx>
#include <workspace/core/svm/vcpu.hxx>
#include <workspace/core/svm/hypercall.hxx>
#include <workspace/core/split/split.hxx>
#include <workspace/core/svm/vmexit.hxx>
#include <workspace/core/svm/hypervisor.hxx>
