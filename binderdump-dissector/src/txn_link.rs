use binderdump_epan_sys::epan;
use std::ffi::c_void;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FrameLink {
    pub bc_frame: u32,
    pub br_frame: u32,
}

pub struct TxnLinkTable {
    map: *mut epan::wmem_map_t,
    scope: *mut epan::wmem_allocator_t,
}

impl TxnLinkTable {
    pub fn new() -> Self {
        unsafe {
            let scope = epan::wmem_file_scope();
            let map =
                epan::wmem_map_new(scope, Some(epan::g_direct_hash), Some(epan::g_direct_equal));
            Self { map, scope }
        }
    }

    pub fn current_scope(&self) -> *mut epan::wmem_allocator_t {
        self.scope
    }

    fn key(debug_id: i32) -> *const c_void {
        debug_id as isize as *const c_void
    }

    fn entry(&self, debug_id: i32) -> Option<*mut FrameLink> {
        unsafe {
            let raw = epan::wmem_map_lookup(self.map, Self::key(debug_id));
            if raw.is_null() {
                None
            } else {
                Some(raw as *mut FrameLink)
            }
        }
    }

    fn entry_or_alloc(&self, debug_id: i32) -> *mut FrameLink {
        if let Some(p) = self.entry(debug_id) {
            return p;
        }
        unsafe {
            let raw = epan::wmem_alloc(self.scope, std::mem::size_of::<FrameLink>());
            let p = raw as *mut FrameLink;
            (*p).bc_frame = 0;
            (*p).br_frame = 0;
            epan::wmem_map_insert(self.map, Self::key(debug_id), raw);
            p
        }
    }

    pub fn record_bc(&self, debug_id: i32, frame: u32) {
        if debug_id == 0 || frame == 0 {
            return;
        }
        unsafe {
            let p = self.entry_or_alloc(debug_id);
            (*p).bc_frame = frame;
        }
    }

    pub fn record_br(&self, debug_id: i32, frame: u32) {
        if debug_id == 0 || frame == 0 {
            return;
        }
        unsafe {
            let p = self.entry_or_alloc(debug_id);
            (*p).br_frame = frame;
        }
    }

    pub fn lookup(&self, debug_id: i32) -> Option<FrameLink> {
        if debug_id == 0 {
            return None;
        }
        unsafe { self.entry(debug_id).map(|p| *p) }
    }
}

unsafe impl Send for TxnLinkTable {}
unsafe impl Sync for TxnLinkTable {}
