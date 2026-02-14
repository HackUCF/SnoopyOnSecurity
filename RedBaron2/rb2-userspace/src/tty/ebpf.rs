use crate::btf::{BtfKind, MiniBtf, extract_raw_btf_bytes};
use anyhow::{Context, anyhow};
use aya::maps::{MapData, RingBuf};
use aya::{
    Btf, Ebpf, EbpfLoader, Endianness,
    programs::{FEntry, KProbe},
    util::nr_cpus,
};
use std::path::Path;
use tokio::io::unix::AsyncFd;

const EBPF_EVENT_PROCESS_TTY_WRITE: u64 = 1 << 6;
const EBPF_VL_FIELD_TTY_OUT: u32 = 7;
const TASK_COMM_LEN: usize = 16;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EbpfEventHeader {
    ts: u64,
    ts_boot: u64,
    r#type: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EbpfTtyWinsize {
    rows: u16,
    cols: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EbpfTtyDev {
    minor: u16,
    major: u16,
    winsize: EbpfTtyWinsize,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EbpfVarlenFieldsStart {
    nfields: u32,
    size: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EbpfPidInfo {
    start_time_ns: u64,
    tid: u32,
    ppid: u32,
    sid: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EbpfProcessTtyWriteEventFixed {
    hdr: EbpfEventHeader,
    pids: EbpfPidInfo,
    tty_out_truncated: u64,
    ctty: EbpfTtyDev,
    tty: EbpfTtyDev,
    comm: [u8; TASK_COMM_LEN],
    vl_fields: EbpfVarlenFieldsStart,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EbpfVarlenFieldHdr {
    field_type: u32,
    size: u32,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ParsedTtyWrite {
    pub ts: u64,
    pub ts_boot: u64,
    pub tty_out_truncated: u64,
    pub start_time_ns: u64,
    pub tid: u32,
    pub ppid: u32,
    pub sid: u32,
    pub ctty_major: u16,
    pub ctty_minor: u16,
    pub tty_major: u16,
    pub tty_minor: u16,
    pub rows: u16,
    pub cols: u16,
    pub comm: String,
    pub tty_out: Vec<u8>,
}

#[inline(always)]
unsafe fn ru16(p: *const u16) -> u16 {
    unsafe { core::ptr::read_unaligned(p) }
}

#[inline(always)]
unsafe fn ru32(p: *const u32) -> u32 {
    unsafe { core::ptr::read_unaligned(p) }
}

#[inline(always)]
unsafe fn ru64(p: *const u64) -> u64 {
    unsafe { core::ptr::read_unaligned(p) }
}

#[inline]
fn read_unaligned<T: Copy>(bytes: &[u8], offset: usize) -> Option<T> {
    let sz = core::mem::size_of::<T>();
    let ptr = bytes.get(offset..offset + sz)?.as_ptr() as *const T;
    Some(unsafe { core::ptr::read_unaligned(ptr) })
}

fn comm_to_string(comm: &[u8; TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

pub fn parse_tty_write_event(bytes: &[u8]) -> anyhow::Result<ParsedTtyWrite> {
    let fixed = read_unaligned::<EbpfProcessTtyWriteEventFixed>(bytes, 0).context("short read")?;

    let ev_type = unsafe { ru64(core::ptr::addr_of!(fixed.hdr.r#type)) };
    if ev_type != EBPF_EVENT_PROCESS_TTY_WRITE {
        return Err(anyhow!("unexpected event type {}", ev_type));
    }

    let mut off = core::mem::size_of::<EbpfProcessTtyWriteEventFixed>();
    let mut tty_out: &[u8] = &bytes[0..0];

    for _ in 0..unsafe { ru32(core::ptr::addr_of!(fixed.vl_fields.nfields)) } {
        let fh = read_unaligned::<EbpfVarlenFieldHdr>(bytes, off)
            .ok_or_else(|| anyhow!("short read: varlen field header"))?;
        off += core::mem::size_of::<EbpfVarlenFieldHdr>();

        let size = fh.size as usize;
        let data = bytes.get(off..off + size).context("varlen overrun")?;
        off += size;

        if fh.field_type == EBPF_VL_FIELD_TTY_OUT {
            tty_out = data;
        }
    }

    Ok(ParsedTtyWrite {
        ts: unsafe { ru64(core::ptr::addr_of!(fixed.hdr.ts)) },
        ts_boot: unsafe { ru64(core::ptr::addr_of!(fixed.hdr.ts_boot)) },
        tty_out_truncated: unsafe { ru64(core::ptr::addr_of!(fixed.tty_out_truncated)) },
        start_time_ns: unsafe { ru64(core::ptr::addr_of!(fixed.pids.start_time_ns)) },
        tid: unsafe { ru32(core::ptr::addr_of!(fixed.pids.tid)) },
        ppid: unsafe { ru32(core::ptr::addr_of!(fixed.pids.ppid)) },
        sid: unsafe { ru32(core::ptr::addr_of!(fixed.pids.sid)) },
        ctty_major: unsafe { ru16(core::ptr::addr_of!(fixed.ctty.major)) },
        ctty_minor: unsafe { ru16(core::ptr::addr_of!(fixed.ctty.minor)) },
        tty_major: unsafe { ru16(core::ptr::addr_of!(fixed.tty.major)) },
        tty_minor: unsafe { ru16(core::ptr::addr_of!(fixed.tty.minor)) },
        rows: unsafe { ru16(core::ptr::addr_of!(fixed.tty.winsize.rows)) },
        cols: unsafe { ru16(core::ptr::addr_of!(fixed.tty.winsize.cols)) },
        comm: comm_to_string(&fixed.comm),
        tty_out: tty_out.to_vec(),
    })
}

pub async fn load_and_attach_ebpf<P: AsRef<Path>>(btf_file_path: P) -> anyhow::Result<Ebpf> {
    let btf = Btf::parse_file(btf_file_path.as_ref(), Endianness::default())?;
    let consumer_pid = std::process::id() as i32;
    let nproc = nr_cpus().map_err(|(ctx, e)| anyhow!("{ctx}: {e}"))? as u32;

    let offsets = get_offset_bytes(btf_file_path.as_ref())
        .await
        .unwrap_or_default();

    let mut ebpf = EbpfLoader::new()
        .btf(Some(&btf))
        .set_global("consumer_pid", &consumer_pid, true)
        .set_global("IOV_OFFSET", &offsets.iov_offset, true)
        .set_global("DRIVER_TYPE_OFFSET", &offsets.driver_type_offset, true)
        .set_global(
            "DRIVER_SUBTYPE_OFFSET",
            &offsets.driver_subtype_offset,
            true,
        )
        .set_max_entries("event_buffer_map", nproc)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/tty_view.bpf.o"
        )))?;

    attach_tty_write(&mut ebpf, &btf)?;

    Ok(ebpf)
}

fn attach_tty_write(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    let mut try_fentry = || -> anyhow::Result<()> {
        let p: &mut FEntry = ebpf.program_mut("fentry__tty_write").unwrap().try_into()?;
        p.load("tty_write", btf)?;
        p.attach()?;
        Ok(())
    };

    if try_fentry().is_ok() {
        return Ok(());
    }

    let p: &mut KProbe = ebpf.program_mut("kprobe__tty_write").unwrap().try_into()?;
    p.load()?;
    p.attach("tty_write", 0)?;
    Ok(())
}

pub fn take_ringbuf_asyncfd(mut ebpf: Ebpf) -> anyhow::Result<(AsyncFd<RingBuf<MapData>>, Ebpf)> {
    let map = ebpf
        .take_map("ringbuf")
        .context("ringbuf map not found (Ebpf::take_map)")?;

    let ring: RingBuf<MapData> =
        RingBuf::try_from(map).context("failed to convert map to RingBuf")?;
    let afd = AsyncFd::new(ring).context("failed to wrap RingBuf in AsyncFd")?;

    Ok((afd, ebpf))
}

#[derive(Default)]
struct BtfOffsetBytes {
    iov_offset: u32,
    driver_type_offset: u32,
    driver_subtype_offset: u32,
}

/// fake CO_RE when needed for odd reasons
async fn get_offset_bytes(btf_path: &Path) -> anyhow::Result<BtfOffsetBytes> {
    let blob = tokio::fs::read(btf_path)
        .await
        .with_context(|| format!("failed to read {:?}", btf_path))?;

    let raw_btf = extract_raw_btf_bytes(&blob)?;
    let btf = MiniBtf::parse(raw_btf.as_ref())?;

    let iov_iter_id = btf
        .id_by_name_and_kind("iov_iter", BtfKind::Struct)
        .context("type `struct iov_iter` not found in BTF")?;

    let iov_off_bits = btf
        .find_member_offset_bits(iov_iter_id, "iov")?
        .unwrap_or_default();

    let iov_off_bytes = iov_off_bits / 8;

    let tty_driver_id = btf
        .id_by_name_and_kind("tty_driver", BtfKind::Struct)
        .context("type `struct tty_driver` not found in BTF")?;

    let driver_type_off = btf
        .find_member_offset_bits(tty_driver_id, "type")?
        .unwrap_or_default()
        / 8;

    let driver_subtype_off = btf
        .find_member_offset_bits(tty_driver_id, "subtype")?
        .unwrap_or_default()
        / 8;

    Ok(BtfOffsetBytes {
        iov_offset: iov_off_bytes,
        driver_type_offset: driver_type_off,
        driver_subtype_offset: driver_subtype_off,
    })
}
