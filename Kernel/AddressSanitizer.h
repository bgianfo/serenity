/*
 * Copyright (c) 2021, Brian Gianforcaro <bgianf@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#if defined(__SANITIZE_ADDRESS__)

#    include <AK/Types.h>
#    include <Kernel/VirtualAddress.h>

namespace Kernel::AddressSanitizer {

/*
 * Kernel Address Sanitizer (KASAN) is a technology which detects
 * memory write/read errors by tracking the state of each byte of
 * memory in a special "shadow region". Checks which validate each
 * read and write by checking the state in the shadow region are
 * injected via compiler instrumentation.
 *
 * For this scheme to work KASAN needs to dedicate 1/8th of kernel
 * memory to its shadow memory (e.g. 500MB to cover the 4GB address
 * space on x86) and uses direct mapping with a scale and offset to
 * translate a memory address to its corresponding shadow address.
 *
 * The x86 virtual address space layout for KASAN looks like:
 *
 *     +----+ -> 0xFFFFFFFF
 *     |    |
 *     +----+ -> Constants::ShadowRegionEnd
 *     |    |
 *     +----+ -> Constants::ShadowRegionStart
 *     |    |
 *     +----+ -> 0xC1000000 (Kernel Image: End);
 *     +----+ -> 0xC0100000 (Kernel Image: Start);
 *     +----+ -> 0xC0000000 (Kernel Virtual Base)
 *     |    |
 *     |    |
 *     |    | => User mode address space.
 *     |    |
 *     |    |
 *     +----+ -> 0x00800000
 *     |    | =>
 *     +----+ -> 0x00000000
 */

namespace Constants {
// The shadow offset value is used to map an address to the
// corresponding shadow  address by the following formula:
//     shadow_address = (address >> 0x3) + ShadowOffset;
constexpr VirtualAddress ShadowOffset { FlatPtr(0x0) };

// The shadow scale shift value is just a constant which
// represents '3' in the formula described above.
constexpr VirtualAddress ShadowScaleShift { FlatPtr(0x3) };

// This represents the kernel address of the beginning of the shadow memory
// region address. It is the start of kernel virtual space.
constexpr VirtualAddress ShadowRegionStart { FlatPtr(0x0) };

// This represents the kernel address of the beginning of the shadow memory
// This value is the 0x100000000's shadow address: the mapping that would
// be after the end of the kernel memory at 0xffffffff.
// It is the end of kernel address sanitizer shadow area.
constexpr VirtualAddress ShadowRegionEnd { FlatPtr(0x0) };
};

void initialize();

void shadow_va_check_load(unsigned long address, size_t size, void* return_addr);

void shadow_va_check_store(unsigned long address, size_t size, void* return_addr);

}

#else

namespace Kernel::AddressSanitizer {
void initialize();
}

#endif
