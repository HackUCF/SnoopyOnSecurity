mod notifications;
mod yara;

use anyhow::{Result, anyhow};
use core::ffi::c_void;
use log::{LevelFilter, error, info, trace, warn};
use windows::Win32::{
    Foundation::*,
    Security::*,
    System::{Diagnostics::Debug::*, Memory::*, ProcessStatus::*, Threading::*},
};
use yara_x::{Scanner, Rules};

const NUM_PIDS: usize = 65535;

fn init_logging() {
    env_logger::Builder::from_default_env()
        .filter_module("redbaron", LevelFilter::Trace)
        .filter_level(LevelFilter::Off)
        .init()
}

fn get_current_pid() -> u32 {
    unsafe {
        return GetCurrentProcessId();
    }
}

fn enable_debug_privileges() -> Result<()> {
    unsafe {
        let redbaron_handle = GetCurrentProcess();
        let token_perms = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
        let mut h_token = HANDLE::default();

        match OpenProcessToken(redbaron_handle, token_perms, &mut h_token) {
            Ok(()) => {}
            Err(e) => return Err(anyhow!("OpenProcessToken failed with {}", e)),
        };

        let mut tp = TOKEN_PRIVILEGES::default();

        match LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut tp.Privileges[0].Luid) {
            Ok(()) => {}
            Err(e) => return Err(anyhow!("LookupPrivilegeValueW failed with {}", e)),
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        match AdjustTokenPrivileges(h_token, false, Some(&mut tp), 0, None, None) {
            Ok(()) => {}
            Err(e) => return Err(anyhow!("AdjustTokenPrivileges failed with {}", e)),
        }

        let _ = CloseHandle(h_token);

        return Ok(());
    }
}

fn get_pids() -> Result<Vec<u32>> {
    let mut pids: [u32; NUM_PIDS] = [0; NUM_PIDS];
    let mut bytes_written = 0u32;

    unsafe {
        match EnumProcesses(pids.as_mut_ptr(), NUM_PIDS as u32, &mut bytes_written) {
            Ok(()) => {}
            Err(e) => {
                return Err(anyhow!("EnumProcesses failed with error {}", e));
            }
        };
    };

    let num_written = bytes_written as usize / 4;

    if num_written >= NUM_PIDS {
        // should never be greater 🤓☝️
        return Err(anyhow!("HIT THE MAX NUMBER OF PIDS"));
    }

    let mut pid_vec = Vec::<u32>::with_capacity(num_written);
    pid_vec.extend_from_slice(&pids[..num_written]);
    return Ok(pid_vec);
}

fn get_process_handle(pid: u32) -> Result<HANDLE> {
    unsafe {
        match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => Ok(h),
            Err(e) => Err(anyhow!("OpenProcess failed on pid {:04} with {}", pid, e)),
        }
    }
}

// useless
#[derive(Default)]
struct ProcessInfo {
    name: String,
    path: String,
}

fn get_process_info(h: HANDLE) -> Result<ProcessInfo> {
    let mut pi = ProcessInfo::default();
    let mut buffer = [0u16; MAX_PATH as usize];

    unsafe {
        if GetModuleFileNameExW(Some(h), None, &mut buffer) == 0 {
            return Err(anyhow!("GetModuleFileNameExW failed"));
        }
    }

    // rust is so ugly
    pi.path = String::from_utf16_lossy(&buffer)
        .trim_end_matches('\0')
        .to_lowercase();
    pi.name = pi
        .path
        .split("\\")
        .last()
        .ok_or(anyhow!("failed to get file name from path"))?
        .trim_end_matches('\0')
        .trim()
        .to_lowercase();

    return Ok(pi);
}

type MemoryPage = Vec<u8>;
const MEM_INFO_SIZE: usize = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

fn scan_process_memory(h: HANDLE, pid: u32, rules: &Rules) -> Result<()> {
    let mut scanner: Scanner<'_> = Scanner::new(rules);

    let mut mem_info = MEMORY_BASIC_INFORMATION::default();
    let mut bytes_written: usize;
    let mut base_address: *const c_void = std::ptr::null();

    let pi = match get_process_info(h) {
        Ok(i) => {
            info!("pid: {:4} is {}", pid, i.name);
            i
        }
        Err(e) => {
            error!("failed getting proccess info {}", e);
            return Err(e);
        }
    };

    loop {
        unsafe {
            bytes_written = VirtualQueryEx(h, Some(base_address), &mut mem_info, MEM_INFO_SIZE);
        }

        if bytes_written == 0 {
            break;
        } else if bytes_written != MEM_INFO_SIZE {
            warn!(
                "VirtualQueryEx wrote a weird number of bytes. wanted {}, got {}",
                MEM_INFO_SIZE, bytes_written
            );
        }

        base_address = base_address.wrapping_add(mem_info.RegionSize);

        if mem_info.State != MEM_COMMIT {
            continue;
        }

        if mem_info.Protect & (PAGE_NOACCESS | PAGE_GUARD) != PAGE_PROTECTION_FLAGS(0) {
            continue;
        }

        let mut page: MemoryPage = std::vec::from_elem(0u8, mem_info.RegionSize as usize);

        let mut bytes_read = 0;
        unsafe {
            match ReadProcessMemory(
                h,
                mem_info.BaseAddress,
                page.as_mut_ptr() as *mut c_void,
                mem_info.RegionSize,
                Some(&mut bytes_read),
            ) {
                Ok(()) => {}
                Err(e) => {
                    error!("ReadProcessMemory failed with error {}", e);
                }
            }
        }

        if bytes_read != 0 && bytes_read != mem_info.RegionSize {
            warn!(
                "ReadProcessMemory read a weird number of bytes. wanted {}, got {}",
                mem_info.RegionSize, bytes_read
            )
        }

        let scan_results = match scanner.scan(&page) {
            Ok(sr) => sr,
            Err(e) => {
                error!("failed to scan {} with error {}", pi.name, e);
                continue;
            }
        };

        let mut file_scanned: bool = false;
        let mut file_matched: bool = false;

        for rule in scan_results.matching_rules() {

            if !file_scanned {
                
                match scan_file(&pi.path, &rules) {
                    Ok(b) => { 
                        file_matched = b 
                    }
                    Err(e) => {
                        warn!("error scanning file: {}", e)
                    }
                }

                file_scanned = true;
            }

            warn!("rule matched for {}: {}", pi.path, rule.identifier());

            match crate::notifications::notify(&pi.name, &pi.path, pid, file_matched, &rule) {
                Ok(_) => {}
                Err(e) => {
                    warn!("error notifying matched rule {}", e)
                }
            }
        }
    }

    return Ok(());
}

fn scan_file(path: &str, rules: &Rules) -> Result<bool> {
    let mut scanner: Scanner<'_> = Scanner::new(rules);

    let file_data = std::fs::read(path)?;
    
    let scan_results = scanner.scan(&file_data)?;
    
    for rule in scan_results.matching_rules() {
        warn!("file matched for {}: {}", path, rule.identifier());
        return Ok(true);
    }
    
    Ok(false)
}

fn main() -> Result<()> {
    init_logging();

    match enable_debug_privileges() {
        Ok(_) => trace!("enabled SeDebugPrivilege"),
        Err(e) => error!("failed to enable SeDebugPrivilege with error {}", e),
    }

    let rules = crate::yara::compile_rules();

    let redbaron_pid = get_current_pid();

    loop {
        let pids = match get_pids() {
            Ok(pids) => pids,
            Err(_) => continue,
        };

        for pid in pids {
            if pid == redbaron_pid || pid == 0 {
                continue;
            }

            let h = match get_process_handle(pid) {
                Ok(h) => h,
                Err(e) => {
                    error!("{}", e);
                    continue;
                }
            };

            match scan_process_memory(h, pid, &rules) {
                Ok(_) => {}
                Err(e) => {
                    error!("error scanning process memory for PID {}: {}", pid, e);
                    continue;
                }
            };

            unsafe {
                let _ = CloseHandle(h);
            }
        }
    }
}
