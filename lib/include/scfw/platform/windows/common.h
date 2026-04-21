#pragma once

//
// Windows-specific module and symbol resolution.
//
// Provides two core operations:
//   - find_module()    - locate a loaded DLL by walking the PEB.
//   - lookup_symbol()  - find an exported function by parsing PE headers.
//
// These are the building blocks for the dispatch table init. They replace
// `GetModuleHandle` + `GetProcAddress` without calling any Windows APIs.
//

#include <phnt_windows.h>
#include <phnt.h>
#include <ntzwapi.h>

#include "../../runtime/fnv1a.h"

namespace sc {
namespace detail {
namespace windows {

//
// Symbol lookup by parsing the PE export directory.
//
// Manually parses the PE export directory to find exported symbols.
// This is equivalent to `GetProcAddress` but doesn't require a function call.
//
//-----------------------------------------------------------------------------
//  PE Export Directory Structure
//-----------------------------------------------------------------------------
//
//   DOS Header --> NT Headers --> Optional Header --> DataDirectory[0]
//                                                           |
//                                                           v
//                                             IMAGE_EXPORT_DIRECTORY
//                                              +- NumberOfNames
//                                              +- AddressOfNames ------+
//                                              +- AddressOfFunctions   |
//                                              +- AddressOfNameOrdinals|
//                                                                      |
//         +------------------------------------------------------------+
//         v
//    Names[]:        Ordinals[]:      Functions[]:
//    +----------+    +--------+       +------------+
//    |"FuncA"   |    |   2    |       | 0x1000 (0) |
//    |"FuncB"   |    |   0    |       | 0x2000 (1) |
//    |"FuncC"   |    |   1    |       | 0x3000 (2) |
//    +----------+    +--------+       +------------+
//
//    To find "FuncA": Names[0]="FuncA" -> Ordinals[0]=2 -> Functions[2]
//
//
// Forwarded Exports (optional, enable with `SCFW_ENABLE_FIND_MODULE_FORWARDER`):
//   Some exports don't contain code - they redirect to another DLL.
//   A forwarded export's RVA falls within the export directory bounds,
//   and points to a string like "NTDLL.RtlAllocateHeap" instead of code.
//   When enabled, we detect this and recursively resolve the target.
//

#ifdef SCFW_ENABLE_FIND_MODULE_FORWARDER
namespace usermode {
    void* find_module(const char* name);
} // namespace usermode

template <typename F>
F lookup_symbol(void* module, const char* name);
#endif

template <typename F, typename C>
__forceinline
F lookup_symbol_impl(void* module, C comparator) {
    PUCHAR ImageBase = (PUCHAR)module;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);

#ifdef SCFW_ENABLE_FIND_MODULE_FORWARDER
    DWORD ExportDirRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD ExportDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    PIMAGE_EXPORT_DIRECTORY Exports = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + ExportDirRVA);
#else
    PIMAGE_EXPORT_DIRECTORY Exports =
        (PIMAGE_EXPORT_DIRECTORY)(ImageBase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
#endif

    PULONG Names = (PULONG)(ImageBase + Exports->AddressOfNames);
    for (ULONG Index = Exports->NumberOfNames; Index--;) {
        LPCSTR Name = (LPCSTR)(ImageBase + Names[Index]);
        if (comparator(Name)) {
            PULONG Functions = (PULONG)(ImageBase + Exports->AddressOfFunctions);
            PUSHORT Ordinals = (PUSHORT)(ImageBase + Exports->AddressOfNameOrdinals);
            DWORD FunctionRVA = Functions[Ordinals[Index]];

#ifdef SCFW_ENABLE_FIND_MODULE_FORWARDER
            // Check if this is a forwarded export.
            // Forwarded exports have their RVA pointing within the export directory,
            // where a string like "NTDLL.NtdllDefWindowProc_A" is stored.
            if (FunctionRVA >= ExportDirRVA && FunctionRVA < ExportDirRVA + ExportDirSize) {
                LPCSTR ForwardStr = (LPCSTR)(ImageBase + FunctionRVA);
                // Find the dot separator between DLL name and function name.
                LPCSTR Dot = ForwardStr;
                while (*Dot && *Dot != '.') Dot++;
                if (!*Dot) return nullptr;

                // Build DLL name with .dll extension.
                // Forward strings use "NTDLL" not "ntdll.dll", so we append ".dll".
                char DllName[64];
                size_t DllNameLen = Dot - ForwardStr;
                if (DllNameLen + 5 > sizeof(DllName)) return nullptr;

                strcpy(DllName, ForwardStr);
                DllName[DllNameLen + 0] = '.';
                DllName[DllNameLen + 1] = 'd';
                DllName[DllNameLen + 2] = 'l';
                DllName[DllNameLen + 3] = 'l';
                DllName[DllNameLen + 4] = '\0';

                // Function name follows the dot.
                LPCSTR FuncName = Dot + 1;

                // Ordinal forwards start with '#' - not supported.
                if (*FuncName == '#') return nullptr;

                // Find the target module in the PEB.
                // #TODO: Using forwarder in kernel-mode is unsupported for now.
                void* TargetModule = usermode::find_module(DllName);
                if (!TargetModule) return nullptr;

                // Recursively resolve in the target module.
                return lookup_symbol<F>(TargetModule, FuncName);
            }
#endif

            return reinterpret_cast<F>((PVOID)(ImageBase + FunctionRVA));
        }
    }
    return nullptr;
}

template <typename F>
F lookup_symbol(void* module, const char* name) {
    return lookup_symbol_impl<F>(module, [name](const char* export_name) {
        return strcmp(export_name, name) == 0;
    });
}

template <typename F>
F lookup_symbol(void* module, uint32_t hash) {
    return lookup_symbol_impl<F>(module, [hash](const char* export_name) {
        return fnv1a_hash(export_name) == hash;
    });
}

namespace usermode {

//
// Module lookup by walking the PEB loader data structures.
//
// Walks the Process Environment Block (PEB) to find loaded modules.
// The PEB contains the Loader Data (LDR) which maintains a doubly-linked
// list of all modules loaded in the process.
//
//-----------------------------------------------------------------------------
// PEB Structure (simplified)
//-----------------------------------------------------------------------------
//   PEB
//    +--> Ldr (PEB_LDR_DATA)
//           +--> InLoadOrderModuleList <---------------------+
//                  |                                         |
//                  v                                         |
//          +-------------+    +-------------+    +-----------+-+
//          | ntdll.dll   |--->| kernel32.dll|--->| user32.dll  |---> ...
//          | DllBase     |    | DllBase     |    | DllBase     |
//          | BaseDllName |    | BaseDllName |    | BaseDllName |
//          +-------------+    +-------------+    +-------------+
//
//   `ntdll.dll` is always second (after exe), `kernel32.dll` third.
//   `find_module_ntdll()` and `find_module_kernel32()` exploit this.
//

template <typename F>
void* find_module_impl(F comparator) {
    PPEB Peb = NtCurrentPeb();
    PLIST_ENTRY Head = &Peb->Ldr->InLoadOrderModuleList;
    for (PLIST_ENTRY Entry = Head; Entry->Flink != Head; Entry = Entry->Flink) {
        PLDR_DATA_TABLE_ENTRY Ldr = (PLDR_DATA_TABLE_ENTRY)Entry->Flink;
        if (comparator(Ldr->BaseDllName.Buffer)) {
            return Ldr->DllBase;
        }
    }
    return nullptr;
}

__forceinline
void* find_module(const char* name) {
    return find_module_impl([name](const wchar_t* module) {
        return _wcsicmpa(module, name) == 0;
    });
}

__forceinline
void* find_module(const wchar_t* name) {
    return find_module_impl([name](const wchar_t* module) {
        return _wcsicmp(module, name) == 0;
    });
}

__forceinline
void* find_module(uint32_t hash) {
    return find_module_impl([hash](const wchar_t* module) {
        return fnv1a_hash(module) == hash;
    });
}

//
// Fast path: `ntdll.dll` is always the second entry in `InLoadOrderModuleList`
// (first is the exe itself). Skip straight to it instead of searching.
//

__forceinline
void* find_module_ntdll() {
    return ((PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink->Flink)->DllBase;
}

//
// Fast path: `kernel32.dll` is always the third entry in `InLoadOrderModuleList`
// (exe -> ntdll -> kernel32). Three Flink hops from the list head.
//

__forceinline
void* find_module_kernel32() {
    return ((PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink->Flink->Flink)->DllBase;
}

} // namespace usermode

namespace kernelmode {

extern "C" {

#undef NTKERNELAPI
#undef NTAPI

#define NTKERNELAPI
#define NTAPI __stdcall

typedef _Enum_is_bitflag_ enum _POOL_TYPE {
    NonPagedPool,
} POOL_TYPE;

NTKERNELAPI
PVOID
NTAPI
ExAllocatePool (
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExFreePool (
    _Pre_notnull_ __drv_freesMem(Mem) PVOID P
    );

NTKERNELAPI
PVOID
NTAPI
MmGetSystemRoutineAddress (
    _In_ PUNICODE_STRING SystemRoutineName
    );

}

template <typename F>
void* find_module_impl(void* kernel_base, F comparator) {
#ifdef SCFW_ENABLE_INIT_SYMBOLS_BY_STRING
#   define SCFW__SYMBOL(x) _(x)
#else
#   define SCFW__SYMBOL(x) fnv1a_hash(x)
#endif

    auto pExAllocatePool = lookup_symbol<decltype(&ExAllocatePool)>(
        kernel_base, SCFW__SYMBOL("ExAllocatePool"));
    auto pExFreePool = lookup_symbol<decltype(&ExFreePool)>(
        kernel_base, SCFW__SYMBOL("ExFreePool"));
    auto pZwQuerySystemInformation = lookup_symbol<decltype(&ZwQuerySystemInformation)>(
        kernel_base, SCFW__SYMBOL("ZwQuerySystemInformation"));

#undef SCFW__SYMBOL

    NTSTATUS Status;
    PVOID Result = nullptr;
    PVOID Buffer = nullptr;
    ULONG BufferLength = 0;
    ULONG RequiredLength = 0;

    do
    {
        if (RequiredLength) {
            if (Buffer) {
                pExFreePool(Buffer);
            }

            Buffer = pExAllocatePool(NonPagedPool, RequiredLength);
            BufferLength = RequiredLength;
        }

        Status = pZwQuerySystemInformation(SystemModuleInformation,
                                           Buffer,
                                           BufferLength,
                                           &RequiredLength);

    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)Buffer;
    for (ULONG Index = 0; Index < Modules->NumberOfModules; Index++) {
        PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &Modules->Modules[Index];

        PCHAR ModuleName = (PCHAR)ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName;
        if (comparator(ModuleName)) {
            Result = ModuleInfo->ImageBase;
            break;
        }
    }

    pExFreePool(Buffer);
    return Result;
}

__forceinline
void* find_module(void* kernel_base, const char* name) {
    return find_module_impl(kernel_base, [name](const char* module_name) {
        return _stricmp(module_name, name) == 0;
    });
}

__forceinline
void* find_module(void* kernel_base, uint32_t hash) {
    return find_module_impl(kernel_base, [hash](const char* module_name) {
        return fnv1a_hash(module_name) == hash;
    });
}

} // namespace kernelmode

} // namespace windows
} // namespace detail
} // namespace sc
