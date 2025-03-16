#![no_std]
extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use wdk_alloc::WdkAllocator;
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use wdk::{nt_success, println};
use wdk_sys::{STATUS_SUCCESS, NTSTATUS, PCUNICODE_STRING, DRIVER_OBJECT};

#[unsafe(export_name = "DriverEntry")] // WDF expects a symbol with the name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    
    

    STATUS_SUCCESS
}