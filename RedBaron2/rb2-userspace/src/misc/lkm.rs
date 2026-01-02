use super::log::log_detection;
use log::debug;
use std::collections::HashSet;
use std::io;
use tokio::fs;
use tokio::io::AsyncReadExt;

async fn get_taint() -> io::Result<u64> {
    let taint_file = "/proc/sys/kernel/tainted";
    let s = fs::read_to_string(taint_file).await?;
    s.trim()
        .parse::<u64>()
        .map_err(|e| io::Error::other(format!("invalid u64 kernel taint {e}")))
}

pub async fn check_taint() -> io::Result<()> {
    let taint: u64 = get_taint().await?;

    if taint == 0 {
        debug!("Kernel not Tainted");
        return Ok(());
    }

    let mut out = String::new();

    // descriptions from: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/tools/debugging/kernel-chktaint
    let flags = [
        ('P', " * proprietary module was loaded"),
        ('F', " * module was force loaded"),
        ('S', " * kernel running on an out of specification system"),
        ('R', " * module was force unloaded"),
        ('M', " * processor reported a Machine Check Exception (MCE)"),
        ('B', " * bad page referenced or some unexpected page flags"),
        ('U', " * taint requested by userspace application"),
        ('D', " * kernel died recently"),
        ('A', " * an ACPI table was overridden by user"),
        ('W', " * kernel issued warning"),
        ('C', " * staging driver was loaded"),
        ('I', " * workaround for bug in platform firmware applied"),
        ('O', " * externally-built ('out-of-tree') module loaded "),
        ('E', " * unsigned module was loaded"),
        ('L', " * soft lockup occurred"),
        ('K', " * kernel has been live patched"),
        ('X', " * auxiliary taint, defined for and used by distros"),
        ('T', " * kernel built with the struct randomization plugin"),
        ('N', " * an in-kernel test (such as KUnit) has been run"),
        ('J', " * fwctl's mutating debug interface was used"),
    ];

    // bit 0 is special
    if (taint & 1) == 0 {
        out.push('G');
    } else {
        out.push('P');
        log_detection(&format!("LKM {}", flags[0].1)).await;
    }

    for (bit, (ch, msg)) in flags.iter().enumerate().skip(1) {
        if ((taint >> bit) & 1) == 1 {
            out.push(*ch);
            log_detection(&format!("LKM {}", msg)).await;
        } else {
            out.push(' ');
        }
    }
    log_detection(&format!(
        "THE KERNEL IS TAINTED: Full taint string: {}",
        out
    ))
    .await;
    Ok(())
}

/// https://danielroberson.com/post/defanging-lkms/
/// should detect simple rootkits like diamorphine
/// trivial to spoof this check
pub async fn check_sys_module() -> io::Result<()> {
    // lsmod
    let mut file = fs::File::open("/proc/modules").await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let loaded: HashSet<&str> = contents
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();

    // iterate /sys/module/*
    let mut dir = fs::read_dir("/sys/module").await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // check for refcnt file
        let refcnt = path.join("refcnt");
        if fs::metadata(&refcnt).await.is_ok() && !loaded.contains(name) {
            log_detection(&format!(
                "Potentially hidden rootkit found in /sys/module {}",
                name
            ))
            .await;
        }
    }

    Ok(())
}
