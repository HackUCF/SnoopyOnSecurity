pub mod fetch_btf;

use anyhow::{Context as _, Result, bail};
use aya::Endianness;
use object::{Object, ObjectSection};
use std::borrow::Cow;

const BTF_MAGIC: u16 = 0xeb9f;
const MAX_RESOLVE_DEPTH: usize = 32;

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BtfKind {
    Unknown = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

/// If `blob` is an ELF (e.g., .o), pull `.BTF`. Otherwise treat it as raw BTF (e.g., /sys/kernel/btf/vmlinux).
pub fn extract_raw_btf_bytes<'a>(blob: &'a [u8]) -> Result<Cow<'a, [u8]>> {
    if blob.starts_with(b"\x7fELF") {
        let obj = object::read::File::parse(blob).context("failed to parse ELF")?;
        let sec = obj
            .section_by_name(".BTF")
            .context("ELF has no .BTF section")?;
        let data = sec.data().context("failed to read .BTF section data")?;
        Ok(Cow::Borrowed(data))
    } else {
        Ok(Cow::Borrowed(blob))
    }
}

#[derive(Clone, Debug)]
pub struct MiniBtf {
    #[allow(unused)]
    endianness: Endianness,
    strings: Vec<u8>,
    // type_id == index (with dummy at 0)
    types: Vec<TypeInfo>,
}

#[derive(Clone, Debug)]
struct TypeInfo {
    name_off: u32,
    kind: BtfKind,
    #[allow(unused)]
    kind_flag: bool,
    #[allow(unused)]
    vlen: u16,
    // For TYPEDEF/CONST/VOLATILE/RESTRICT/TYPE_TAG: underlying type id.
    // For others: size or kind-specific meaning.
    size_or_type: u32,
    members: Option<Vec<Member>>, // only for struct/union
}

#[derive(Clone, Debug)]
struct Member {
    name_off: u32,
    ty: u32,
    offset_bits: u32,
}

impl MiniBtf {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 24 {
            bail!("raw BTF too small for header");
        }

        let endianness = detect_btf_endianness(raw)?;
        let hdr_len = read_u32(endianness, &raw[4..8]) as usize;
        let type_off = read_u32(endianness, &raw[8..12]) as usize;
        let type_len = read_u32(endianness, &raw[12..16]) as usize;
        let str_off = read_u32(endianness, &raw[16..20]) as usize;
        let str_len = read_u32(endianness, &raw[20..24]) as usize;

        let type_start = hdr_len
            .checked_add(type_off)
            .context("overflow type_start")?;
        let type_end = type_start
            .checked_add(type_len)
            .context("overflow type_end")?;
        let str_start = hdr_len.checked_add(str_off).context("overflow str_start")?;
        let str_end = str_start.checked_add(str_len).context("overflow str_end")?;

        if type_end > raw.len()
            || str_end > raw.len()
            || type_start > type_end
            || str_start > str_end
        {
            bail!("invalid BTF bounds (corrupt header?)");
        }

        let type_sec = &raw[type_start..type_end];
        let strings = raw[str_start..str_end].to_vec();

        let mut types = Vec::<TypeInfo>::new();
        // dummy type id 0
        types.push(TypeInfo {
            name_off: 0,
            kind: BtfKind::Unknown,
            kind_flag: false,
            vlen: 0,
            size_or_type: 0,
            members: None,
        });

        let mut off = 0usize;
        while off < type_sec.len() {
            if type_sec.len() - off < 12 {
                bail!("truncated type record");
            }

            let name_off = read_u32(endianness, &type_sec[off..off + 4]);
            let info = read_u32(endianness, &type_sec[off + 4..off + 8]);
            let size_or_type = read_u32(endianness, &type_sec[off + 8..off + 12]);

            let kind_u8 = ((info >> 24) & 0x1f) as u8;
            let kind: BtfKind = kind_u8_to_enum(kind_u8)?;
            let kind_flag = (info >> 31) != 0;
            let vlen = (info & 0xffff) as u16;

            let extra_len =
                type_extra_len(kind, vlen).with_context(|| format!("unsupported kind {kind:?}"))?;
            let rec_len = 12usize + extra_len;

            if off + rec_len > type_sec.len() {
                bail!("type record overruns type section");
            }

            let members = if kind == BtfKind::Struct || kind == BtfKind::Union {
                let mut ms = Vec::with_capacity(vlen as usize);
                let mut m_off = off + 12;
                for _ in 0..vlen {
                    let m_name_off = read_u32(endianness, &type_sec[m_off..m_off + 4]);
                    let m_ty = read_u32(endianness, &type_sec[m_off + 4..m_off + 8]);
                    let raw_off = read_u32(endianness, &type_sec[m_off + 8..m_off + 12]);

                    // If kflag is set, lower 24 bits = bit offset, upper 8 bits = bitfield size.
                    let offset_bits = if kind_flag {
                        raw_off & 0x00ff_ffff
                    } else {
                        raw_off
                    };

                    ms.push(Member {
                        name_off: m_name_off,
                        ty: m_ty,
                        offset_bits,
                    });
                    m_off += 12;
                }
                Some(ms)
            } else {
                None
            };

            types.push(TypeInfo {
                name_off,
                kind,
                kind_flag,
                vlen,
                size_or_type,
                members,
            });

            off += rec_len;
        }

        Ok(Self {
            endianness,
            strings,
            types,
        })
    }

    fn string_at(&self, off: u32) -> Result<&str> {
        let off = off as usize;
        if off >= self.strings.len() {
            bail!("invalid string offset {off}");
        }
        let tail = &self.strings[off..];
        let nul = tail
            .iter()
            .position(|&b| b == 0)
            .context("unterminated btf string")?;
        Ok(std::str::from_utf8(&tail[..nul])?)
    }

    fn type_by_id(&self, id: u32) -> Result<&TypeInfo> {
        self.types
            .get(id as usize)
            .with_context(|| format!("unknown BTF type id {id}"))
    }

    fn resolve_type(&self, root: u32) -> Result<u32> {
        let mut id = root;
        for _ in 0..MAX_RESOLVE_DEPTH {
            let t = self.type_by_id(id)?;
            match t.kind {
                BtfKind::Typedef
                | BtfKind::Volatile
                | BtfKind::Const
                | BtfKind::Restrict
                | BtfKind::TypeTag => {
                    id = t.size_or_type;
                }
                _ => return Ok(id),
            }
        }
        Ok(id)
    }

    pub fn id_by_name_and_kind(&self, name: &str, kind: BtfKind) -> Option<u32> {
        for (i, t) in self.types.iter().enumerate().skip(1) {
            if t.kind != kind {
                continue;
            }
            if self.string_at(t.name_off).ok()? == name {
                return Some(i as u32);
            }
        }
        None
    }

    pub fn find_member_offset_bits(&self, root_type_id: u32, target: &str) -> Result<Option<u32>> {
        let root = self.resolve_type(root_type_id)?;
        find_member_offset_bits_rec(self, root, target, 0, 0)
    }
}

fn find_member_offset_bits_rec(
    btf: &MiniBtf,
    type_id: u32,
    target: &str,
    base_offset_bits: u32,
    depth: usize,
) -> Result<Option<u32>> {
    if depth >= MAX_RESOLVE_DEPTH {
        return Ok(None);
    }

    let ty = btf.type_by_id(type_id)?;
    if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
        return Ok(None);
    }

    let Some(members) = &ty.members else {
        return Ok(None);
    };

    for m in members {
        let m_ty = btf.resolve_type(m.ty)?;
        let abs_off = base_offset_bits + m.offset_bits;

        // Named members
        if m.name_off != 0 && btf.string_at(m.name_off)? == target {
            return Ok(Some(abs_off));
        }

        // Anonymous struct/union nesting
        let sub = btf.type_by_id(m_ty)?;
        if (sub.kind == BtfKind::Struct || sub.kind == BtfKind::Union)
            && let Some(found) = find_member_offset_bits_rec(btf, m_ty, target, abs_off, depth + 1)?
        {
            return Ok(Some(found));
        }
    }

    Ok(None)
}

fn detect_btf_endianness(raw: &[u8]) -> Result<Endianness> {
    let le = u16::from_le_bytes([raw[0], raw[1]]);
    if le == BTF_MAGIC {
        return Ok(Endianness::Little);
    }
    let be = u16::from_be_bytes([raw[0], raw[1]]);
    if be == BTF_MAGIC {
        return Ok(Endianness::Big);
    }
    bail!("not a BTF blob (bad magic)")
}

fn read_u32(e: Endianness, b: &[u8]) -> u32 {
    let a: [u8; 4] = b.try_into().unwrap();
    match e {
        Endianness::Little => u32::from_le_bytes(a),
        Endianness::Big => u32::from_be_bytes(a),
    }
}

fn kind_u8_to_enum(k: u8) -> Result<BtfKind> {
    Ok(match k {
        0 => BtfKind::Unknown,
        1 => BtfKind::Int,
        2 => BtfKind::Ptr,
        3 => BtfKind::Array,
        4 => BtfKind::Struct,
        5 => BtfKind::Union,
        6 => BtfKind::Enum,
        7 => BtfKind::Fwd,
        8 => BtfKind::Typedef,
        9 => BtfKind::Volatile,
        10 => BtfKind::Const,
        11 => BtfKind::Restrict,
        12 => BtfKind::Func,
        13 => BtfKind::FuncProto,
        14 => BtfKind::Var,
        15 => BtfKind::DataSec,
        16 => BtfKind::Float,
        17 => BtfKind::DeclTag,
        18 => BtfKind::TypeTag,
        19 => BtfKind::Enum64,
        _ => bail!("unsupported BTF kind value {k}"),
    })
}

fn type_extra_len(kind: BtfKind, vlen: u16) -> Result<usize> {
    let v = vlen as usize;
    Ok(match kind {
        BtfKind::Int => 4, // btf_int
        BtfKind::Ptr => 0,
        BtfKind::Array => 12,                       // btf_array
        BtfKind::Struct | BtfKind::Union => v * 12, // btf_member[vlen]
        BtfKind::Enum => v * 8,                     // btf_enum[vlen]
        BtfKind::Fwd => 0,
        BtfKind::Typedef => 0,
        BtfKind::Volatile => 0,
        BtfKind::Const => 0,
        BtfKind::Restrict => 0,
        BtfKind::Func => 0,
        BtfKind::FuncProto => v * 8, // btf_param[vlen]
        BtfKind::Var => 4,           // btf_var
        BtfKind::DataSec => v * 12,  // btf_var_secinfo[vlen]
        BtfKind::Float => 0,
        BtfKind::DeclTag => 4, // component_idx (btf_type is in size_or_type)
        BtfKind::TypeTag => 0,
        BtfKind::Enum64 => v * 12, // btf_enum64[vlen]
        BtfKind::Unknown => bail!("unknown kind"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn btf_header_le(type_len: u32, str_len: u32) -> Vec<u8> {
        // btf_header, little endian, hdr_len=24, type_off=0
        let mut v = Vec::new();
        v.extend_from_slice(&0xeb9fu16.to_le_bytes()); // magic
        v.push(1); // version
        v.push(0); // flags
        v.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        v.extend_from_slice(&0u32.to_le_bytes()); // type_off
        v.extend_from_slice(&type_len.to_le_bytes());
        v.extend_from_slice(&type_len.to_le_bytes()); // str_off
        v.extend_from_slice(&str_len.to_le_bytes());
        v
    }

    fn push_string_table(strings: &[&str]) -> (Vec<u8>, Vec<u32>) {
        let mut buf = vec![0];
        let mut offs = Vec::new();
        for s in strings {
            let off = buf.len() as u32;
            offs.push(off);
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        (buf, offs)
    }

    fn type_info_le(kind: BtfKind, vlen: u16, name_off: u32, size_or_type: u32) -> Vec<u8> {
        let info = ((kind as u32) << 24) | vlen as u32; // kflag=0
        let mut v = Vec::new();
        v.extend_from_slice(&name_off.to_le_bytes());
        v.extend_from_slice(&info.to_le_bytes());
        v.extend_from_slice(&size_or_type.to_le_bytes());
        v
    }

    #[test]
    fn test_parse_header_and_min_struct_member() {
        // struct foo { int bar; };
        let (strings, offs) = push_string_table(&["foo", "bar", "int"]);
        let foo = offs[0];
        let bar = offs[1];
        let int = offs[2];

        let mut types = Vec::new();

        types.extend(type_info_le(BtfKind::Int, 0, int, 4));
        types.extend_from_slice(&0u32.to_le_bytes()); // btf_int encoding

        // type 2: struct foo, 1 member, size=4
        types.extend(type_info_le(BtfKind::Struct, 1, foo, 4));
        // member record: name_off, type, offset_bits
        types.extend_from_slice(&bar.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes()); // int type id
        types.extend_from_slice(&0u32.to_le_bytes()); // offset bits

        let mut blob = btf_header_le(types.len() as u32, strings.len() as u32);
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strings);

        let btf = MiniBtf::parse(&blob).expect("parse failed");
        let foo_id = btf
            .id_by_name_and_kind("foo", BtfKind::Struct)
            .expect("foo not found");

        let off_bits = btf
            .find_member_offset_bits(foo_id, "bar")
            .expect("walk failed")
            .expect("bar not found");

        assert_eq!(off_bits, 0);
    }

    #[test]
    fn test_parse_anonymous_union_nesting() {
        let (strings, offs) = push_string_table(&["s", "iov", "other", "int"]);
        let s = offs[0];
        let iov = offs[1];
        let other = offs[2];
        let int = offs[3];

        let mut types = Vec::new();

        // int
        types.extend(type_info_le(BtfKind::Int, 0, int, 4));
        types.extend_from_slice(&0u32.to_le_bytes());

        // union (anonymous name_off=0), size=4, 2 members at offset 0
        types.extend(type_info_le(BtfKind::Union, 2, 0, 4));
        types.extend_from_slice(&iov.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&other.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());

        // struct s, contains the anonymous union as an anonymous member
        types.extend(type_info_le(BtfKind::Struct, 1, s, 4));
        types.extend_from_slice(&0u32.to_le_bytes()); // anonymous member name
        types.extend_from_slice(&2u32.to_le_bytes()); // union type id
        types.extend_from_slice(&0u32.to_le_bytes()); // offset bits

        let mut blob = btf_header_le(types.len() as u32, strings.len() as u32);
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strings);

        let btf = MiniBtf::parse(&blob).expect("parse failed");
        let sid = btf
            .id_by_name_and_kind("s", BtfKind::Struct)
            .expect("s not found");

        let off_bits = btf
            .find_member_offset_bits(sid, "iov")
            .expect("walk failed")
            .expect("iov not found");

        assert_eq!(off_bits, 0);
    }

    #[test]
    fn test_resolve_typedef_chain() {
        // typedef int T;
        // struct iov_iter { T iov; };
        let (strings, offs) = push_string_table(&["iov_iter", "iov", "int", "T"]);
        let iov_iter = offs[0];
        let iov = offs[1];
        let int = offs[2];
        let tname = offs[3];

        let mut types = Vec::new();

        // int
        types.extend(type_info_le(BtfKind::Int, 0, int, 4));
        types.extend_from_slice(&0u32.to_le_bytes());

        // typedef T -> int
        types.extend(type_info_le(BtfKind::Typedef, 0, tname, 1));

        // struct iov_iter { T iov; }
        types.extend(type_info_le(BtfKind::Struct, 1, iov_iter, 4));
        types.extend_from_slice(&iov.to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes()); // typedef type id
        types.extend_from_slice(&0u32.to_le_bytes()); // offset

        let mut blob = btf_header_le(types.len() as u32, strings.len() as u32);
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strings);

        let btf = MiniBtf::parse(&blob).expect("parse failed");
        let iid = btf
            .id_by_name_and_kind("iov_iter", BtfKind::Struct)
            .expect("iov_iter not found");

        let off_bits = btf
            .find_member_offset_bits(iid, "iov")
            .expect("walk failed")
            .expect("iov not found");

        assert_eq!(off_bits, 0);
    }
}
