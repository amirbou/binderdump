#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/binder_gen.rs"));

use plain::Plain;

unsafe impl Plain for binder_write_read {}
unsafe impl Plain for binder_transaction_data {}

impl std::fmt::Debug for binder_transaction_data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("binder_transaction_data")
            .field(
                "target",
                &format_args!(
                    "handle {:x} - ptr {:x}",
                    unsafe { &self.target.handle },
                    unsafe { &self.target.ptr }
                ),
            )
            .field("cookie", &self.cookie)
            .field(
                "code",
                &format_args!("{}", transaction::Code::new(self.code)),
            )
            .field("flags", &self.flags)
            .field("sender_pid", &self.sender_pid)
            .field("sender_euid", &self.sender_euid)
            .field("data_size", &self.data_size)
            .field("offsets_size", &self.offsets_size)
            .field(
                "data",
                &format_args!("{:x} - {:x?}", unsafe { &self.data.ptr.buffer }, unsafe {
                    &self.data.buf
                }),
            )
            .finish()
    }
}

pub mod transaction {
    #[allow(non_snake_case)]
    const fn B_PACK_CHARS(c1: char, c2: char, c3: char, c4: char) -> u32 {
        ((c1 as u32) << 24) | ((c2 as u32) << 16) | ((c3 as u32) << 8) | (c4 as u32)
    }

    pub const PING_TRANSACTION: u32 = B_PACK_CHARS('_', 'P', 'N', 'G');
    pub const START_RECORDING_TRANSACTION: u32 = B_PACK_CHARS('_', 'S', 'R', 'D');
    pub const STOP_RECORDING_TRANSACTION: u32 = B_PACK_CHARS('_', 'E', 'R', 'D');
    pub const DUMP_TRANSACTION: u32 = B_PACK_CHARS('_', 'D', 'M', 'P');
    pub const SHELL_COMMAND_TRANSACTION: u32 = B_PACK_CHARS('_', 'C', 'M', 'D');
    pub const INTERFACE_TRANSACTION: u32 = B_PACK_CHARS('_', 'N', 'T', 'F');
    pub const SYSPROPS_TRANSACTION: u32 = B_PACK_CHARS('_', 'S', 'P', 'R');
    pub const EXTENSION_TRANSACTION: u32 = B_PACK_CHARS('_', 'E', 'X', 'T');
    pub const DEBUG_PID_TRANSACTION: u32 = B_PACK_CHARS('_', 'P', 'I', 'D');
    pub const SET_RPC_CLIENT_TRANSACTION: u32 = B_PACK_CHARS('_', 'R', 'P', 'C');

    // See android.os.IBinder.TWEET_TRANSACTION
    // Most importantly, messages can be anything not exceeding 130 UTF-8
    // characters, and callees should exclaim "jolly good message old boy!"
    pub const TWEET_TRANSACTION: u32 = B_PACK_CHARS('_', 'T', 'W', 'T');

    // See android.os.IBinder.LIKE_TRANSACTION
    // Improve binder self-esteem.
    pub const LIKE_TRANSACTION: u32 = B_PACK_CHARS('_', 'L', 'I', 'K');

    pub struct Code {
        code: u32,
    }

    impl Code {
        pub fn new(code: u32) -> Self {
            Self { code }
        }
    }

    impl std::fmt::Display for Code {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.code {
                PING_TRANSACTION => write!(f, "'_PNG'"),
                START_RECORDING_TRANSACTION => write!(f, "'_SRD'"),
                STOP_RECORDING_TRANSACTION => write!(f, "'_ERD'"),
                DUMP_TRANSACTION => write!(f, "'_DMP'"),
                SHELL_COMMAND_TRANSACTION => write!(f, "'_CMD'"),
                INTERFACE_TRANSACTION => write!(f, "'_NTF'"),
                SYSPROPS_TRANSACTION => write!(f, "'_SPR'"),
                EXTENSION_TRANSACTION => write!(f, "'_EXT'"),
                DEBUG_PID_TRANSACTION => write!(f, "'_PID'"),
                SET_RPC_CLIENT_TRANSACTION => write!(f, "'_RPC'"),
                TWEET_TRANSACTION => write!(f, "'_TWT'"),
                LIKE_TRANSACTION => write!(f, "'_LIK'"),
                _ => write!(f, "{}", self.code),
            }
        }
    }
}
