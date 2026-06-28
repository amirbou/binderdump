// flat_binder_object type tags, sizes, and offset-array iteration.
// tag constants from <linux/android/binder.h> B_PACK_CHARS / B_TYPE_LARGE.

pub const fn b_pack_chars(c1: u8, c2: u8, c3: u8, c4: u8) -> u32 {
    ((c1 as u32) << 24) | ((c2 as u32) << 16) | ((c3 as u32) << 8) | (c4 as u32)
}

const B_TYPE_LARGE: u8 = 0x85;

pub const BINDER: u32 = b_pack_chars(b's', b'b', b'*', B_TYPE_LARGE);
pub const WEAK_BINDER: u32 = b_pack_chars(b'w', b'b', b'*', B_TYPE_LARGE);
pub const HANDLE: u32 = b_pack_chars(b's', b'h', b'*', B_TYPE_LARGE);
pub const WEAK_HANDLE: u32 = b_pack_chars(b'w', b'h', b'*', B_TYPE_LARGE);
pub const FD: u32 = b_pack_chars(b'f', b'd', b'*', B_TYPE_LARGE);
pub const PTR: u32 = b_pack_chars(b'p', b't', b'*', B_TYPE_LARGE);
pub const FDA: u32 = b_pack_chars(b'f', b'd', b'a', B_TYPE_LARGE);

// 64-bit binder_size_t offset entry
pub const ENTRY_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Binder,
    Handle,
    Fd,
    Ptr,
    Fda,
    Unknown,
}

pub fn classify(type_tag: u32) -> Kind {
    match type_tag {
        BINDER | WEAK_BINDER => Kind::Binder,
        HANDLE | WEAK_HANDLE => Kind::Handle,
        FD => Kind::Fd,
        PTR => Kind::Ptr,
        FDA => Kind::Fda,
        _ => Kind::Unknown,
    }
}

impl Kind {
    pub fn flat_size(self) -> Option<usize> {
        match self {
            Kind::Binder | Kind::Handle | Kind::Fd => Some(24),
            Kind::Ptr => Some(40),
            Kind::Fda => Some(32),
            Kind::Unknown => None,
        }
    }
}

// yields each 8-byte LE entry in `offsets` as a usize byte position.
pub fn offset_entries(offsets: &[u8]) -> impl Iterator<Item = usize> + '_ {
    offsets
        .chunks_exact(ENTRY_SIZE)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_all_tags() {
        assert_eq!(classify(BINDER), Kind::Binder);
        assert_eq!(classify(WEAK_BINDER), Kind::Binder); // weak folds to Binder
        assert_eq!(classify(HANDLE), Kind::Handle);
        assert_eq!(classify(WEAK_HANDLE), Kind::Handle); // weak folds to Handle
        assert_eq!(classify(FD), Kind::Fd);
        assert_eq!(classify(PTR), Kind::Ptr);
        assert_eq!(classify(FDA), Kind::Fda);
        assert_eq!(classify(0), Kind::Unknown);
        assert_eq!(classify(0xdeadbeef), Kind::Unknown);
    }

    #[test]
    fn flat_size_per_kind() {
        assert_eq!(Kind::Binder.flat_size(), Some(24));
        assert_eq!(Kind::Handle.flat_size(), Some(24));
        assert_eq!(Kind::Fd.flat_size(), Some(24));
        assert_eq!(Kind::Ptr.flat_size(), Some(40));
        assert_eq!(Kind::Fda.flat_size(), Some(32));
        assert_eq!(Kind::Unknown.flat_size(), None);
    }

    #[test]
    fn offset_entries_parses_le_u64s() {
        let mut offsets = Vec::new();
        offsets.extend_from_slice(&0u64.to_le_bytes());
        offsets.extend_from_slice(&24u64.to_le_bytes());
        offsets.extend_from_slice(&48u64.to_le_bytes());
        let entries: Vec<usize> = offset_entries(&offsets).collect();
        assert_eq!(entries, vec![0, 24, 48]);
    }

    #[test]
    fn offset_entries_ignores_trailing_partial_chunk() {
        let mut offsets = 0u64.to_le_bytes().to_vec();
        offsets.push(0xff); // 7 leftover bytes -> ignored
        offsets.extend_from_slice(&[0; 6]);
        let entries: Vec<usize> = offset_entries(&offsets).collect();
        assert_eq!(entries, vec![0]);
    }
}
