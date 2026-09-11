#pragma once

#pragma warning(disable : 4996)
#pragma warning(disable : 4201)

#include <ntifs.h>
#include <intrin.h>
#include <stdarg.h>

#include <impl/std/std.hxx>
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
#include <workspace/core/svm/vcpu.hxx>
#include <workspace/core/split/split.hxx>
#include <workspace/core/svm/vmexit.hxx>
#include <workspace/core/svm/hypervisor.hxx>
