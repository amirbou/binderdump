use binderdump_epan_sys::epan;
use binderdump_structs;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::binder_types::binder_command;
use binderdump_structs::binder_types::binder_return;
use binderdump_structs::binder_types::bwr_trait::Bwr;
use binderdump_structs::event_layer::EventProtocol;
use binderdump_trait::ConstOffsets;
use binderdump_trait::EpanProtocolEnum;
use std::ffi::c_int;
use std::ptr::null_mut;

use crate::dissect_offsets;
use crate::epan_plugin::ProtocolBuilder;
use crate::header_fields_manager::HeaderFieldsManager;

macro_rules! bc_prefix {
    ($s:literal) => {
        concat!("binderdump.ioctl_data.bwr.commands.", $s)
    };
}

macro_rules! br_prefix {
    ($s:literal) => {
        concat!("binderdump.ioctl_data.bwr.returns.", $s)
    };
}

macro_rules! dissect_arm {
    ($ty:ty, $abbrev:literal, $offset:expr, $bissect:expr, $tree:expr, $macro:ident) => {
        dissect_offsets::dissect_offsets(
            $bissect.event,
            <$ty>::get_offsets($offset).unwrap(),
            $bissect.manager,
            $macro!($abbrev).into(),
            $bissect.tvb,
            $bissect.pinfo,
            $tree,
        )
    };
}

macro_rules! br_dissect_arm {
    ($ty:ty, $abbrev:literal, $offset:expr, $bissect:expr, $tree:expr) => {
        dissect_arm!($ty, $abbrev, $offset, $bissect, $tree, br_prefix)
    };
}

macro_rules! bc_dissect_arm {
    ($ty:ty, $abbrev:literal, $offset:expr, $bissect:expr, $tree:expr) => {
        dissect_arm!($ty, $abbrev, $offset, $bissect, $tree, bc_prefix)
    };
}

struct BwrDissect<'a> {
    pub event: &'a EventProtocol,
    pub manager: &'a HeaderFieldsManager<EventProtocol>,
    pub tvb: *mut epan::tvbuff,
    pub pinfo: *mut epan::packet_info,
}

fn dissect_br_data(
    event: &EventProtocol,
    handle: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    data: &[u8],
    offset: FieldOffset,
    tvb: *mut epan::tvbuff,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let returns_tree = unsafe {
        epan::proto_tree_add_subtree(
            tree,
            tvb,
            offset.offset.try_into()?,
            offset.size.try_into()?,
            handle,
            null_mut(),
            c"Returns".as_ptr(),
        )
    };

    let mut pos = 0;
    let br_dissect = BwrDissect {
        event,
        manager,
        tvb,
        pinfo,
    };

    while pos < data.len() {
        let result = binder_return::BinderReturn::from_bytes(&data[pos..])?;
        unsafe {
            let br_tree = epan::proto_tree_add_subtree(
                returns_tree,
                tvb,
                (offset.offset + pos).try_into()?,
                result.size().try_into()?,
                handle,
                null_mut(),
                result.get_header().to_cstr().as_ptr(),
            );

            epan::proto_tree_add_item(
                br_tree,
                manager.get_handle(br_prefix!("br")).unwrap(),
                tvb,
                (offset.offset + pos).try_into()?,
                std::mem::size_of::<binder_return::binder_return>().try_into()?,
                epan::ENC_LITTLE_ENDIAN,
            );

            let offset = offset.offset + pos + std::mem::size_of::<binder_return::binder_return>();
            match result {
                binder_return::BinderReturn::Error(_) => br_dissect_arm!(
                    binder_return::ErrorReturn,
                    "error",
                    offset,
                    br_dissect,
                    br_tree
                )?,

                binder_return::BinderReturn::TransactionSecCtx(_) => br_dissect_arm!(
                    binder_return::TransactionSecCtx,
                    "transaction_secctx",
                    offset,
                    br_dissect,
                    br_tree
                )?,
                binder_return::BinderReturn::Transaction(_)
                | binder_return::BinderReturn::Reply(_) => br_dissect_arm!(
                    binderdump_structs::binder_types::transaction::Transaction,
                    "transaction",
                    offset,
                    br_dissect,
                    br_tree
                )?,
                binder_return::BinderReturn::IncRefs(_)
                | binder_return::BinderReturn::Acquire(_)
                | binder_return::BinderReturn::Release(_)
                | binder_return::BinderReturn::DecRefs(_) => {
                    br_dissect_arm!(binder_return::RefReturn, "ref", offset, br_dissect, br_tree)?
                }
                binder_return::BinderReturn::DeadBinder(_) => br_dissect_arm!(
                    binder_return::DeadBinder,
                    "dead_binder",
                    offset,
                    br_dissect,
                    br_tree
                )?,
                binder_return::BinderReturn::ClearDeathNotificationDone(_) => br_dissect_arm!(
                    binder_return::ClearDeathNotificationDone,
                    "clear_death_done",
                    offset,
                    br_dissect,
                    br_tree
                )?,
                binder_return::BinderReturn::FrozenBinder(_) => br_dissect_arm!(
                    binder_return::FrozenStateInfo,
                    "frozen_state_info",
                    offset,
                    br_dissect,
                    br_tree
                )?,
                binder_return::BinderReturn::ClearFreezeNotificationDone(_) => br_dissect_arm!(
                    binder_return::FreezeNotificationDone,
                    "clear_freeze_done",
                    offset,
                    br_dissect,
                    br_tree
                )?,

                _ => (),
            }
        }

        pos += result.size();
    }
    if pos != data.len() {
        return Err(anyhow::anyhow!(
            "Only {} out of {} bytes comsumed from bwr read command",
            pos,
            data.len()
        ));
    }

    Ok(())
}

fn dissect_bc_data(
    event: &EventProtocol,
    handle: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    data: &[u8],
    offset: FieldOffset,
    tvb: *mut epan::tvbuff,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    let commands_tree = unsafe {
        epan::proto_tree_add_subtree(
            tree,
            tvb,
            offset.offset.try_into()?,
            offset.size.try_into()?,
            handle,
            null_mut(),
            c"Commands".as_ptr(),
        )
    };

    let mut pos = 0;
    let bc_dissect = BwrDissect {
        event,
        manager,
        tvb,
        pinfo,
    };

    while pos < data.len() {
        let result = binder_command::BinderCommand::from_bytes(&data[pos..])?;
        unsafe {
            let bc_tree = epan::proto_tree_add_subtree(
                commands_tree,
                tvb,
                (offset.offset + pos).try_into()?,
                result.size().try_into()?,
                handle,
                null_mut(),
                result.get_header().to_cstr().as_ptr(),
            );

            epan::proto_tree_add_item(
                bc_tree,
                manager.get_handle(bc_prefix!("bc")).unwrap(),
                tvb,
                (offset.offset + pos).try_into()?,
                std::mem::size_of::<binder_command::binder_command>().try_into()?,
                epan::ENC_LITTLE_ENDIAN,
            );

            let offset =
                offset.offset + pos + std::mem::size_of::<binder_command::binder_command>();
            match result {
                binder_command::BinderCommand::IncRefs(_)
                | binder_command::BinderCommand::Acquire(_)
                | binder_command::BinderCommand::Release(_)
                | binder_command::BinderCommand::DecRefs(_) => bc_dissect_arm!(
                    binder_command::RefCommand,
                    "ref",
                    offset,
                    bc_dissect,
                    bc_tree
                )?,
                binder_command::BinderCommand::IncRefsDone(_)
                | binder_command::BinderCommand::AcquireDone(_) => bc_dissect_arm!(
                    binder_command::RefDoneCommand,
                    "ref_done",
                    offset,
                    bc_dissect,
                    bc_tree
                )?,
                binder_command::BinderCommand::FreeBuffer(_) => bc_dissect_arm!(
                    binder_command::FreeBufferCommand,
                    "free",
                    offset,
                    bc_dissect,
                    bc_tree
                )?,
                binder_command::BinderCommand::TransactionSg(_)
                | binder_command::BinderCommand::ReplySg(_) => bc_dissect_arm!(
                    binderdump_structs::binder_types::transaction::TransactionSg,
                    "transaction_sg",
                    offset,
                    bc_dissect,
                    bc_tree
                )?,
                binder_command::BinderCommand::Transaction(_)
                | binder_command::BinderCommand::Reply(_) => bc_dissect_arm!(
                    binderdump_structs::binder_types::transaction::Transaction,
                    "transaction",
                    offset,
                    bc_dissect,
                    bc_tree
                )?,
                binder_command::BinderCommand::RequestDeathNotification(_)
                | binder_command::BinderCommand::ClearDeathNotification(_) => bc_dissect_arm!(
                    binder_command::DeathCommand,
                    "death",
                    offset,
                    bc_dissect,
                    bc_tree
                )?,
                binder_command::BinderCommand::DeadBinderDone(_) => bc_dissect_arm!(
                    binder_command::DeathDoneCommand,
                    "dead_done",
                    offset,
                    bc_dissect,
                    bc_tree
                )?,
                _ => (),
            }
        }

        pos += result.size();
    }
    if pos != data.len() {
        return Err(anyhow::anyhow!(
            "Only {} out of {} bytes comsumed from bwr write command",
            pos,
            data.len()
        ));
    }

    Ok(())
}

pub fn dissect_bwr_data(
    _hf: c_int,
    ett: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    event: &EventProtocol,
    offset: FieldOffset,
    tvb: *mut epan::tvbuff,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    let bwr = event.ioctl_data.as_ref().unwrap().bwr.as_ref().unwrap();

    match bwr.is_write() {
        true => dissect_bc_data(event, ett, manager, &bwr.data, offset, tvb, pinfo, tree),
        false => dissect_br_data(event, ett, manager, &bwr.data, offset, tvb, pinfo, tree),
    }
}

pub fn collect_command_names(is_write: bool, data: &[u8]) -> Vec<&'static str> {
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if is_write {
            match binder_command::BinderCommand::from_bytes(&data[pos..]) {
                Ok(cmd) => {
                    names.push(cmd.get_header().to_str());
                    pos += cmd.size();
                }
                Err(_) => break,
            }
        } else {
            match binder_return::BinderReturn::from_bytes(&data[pos..]) {
                Ok(ret) => {
                    names.push(ret.get_header().to_str());
                    pos += ret.size();
                }
                Err(_) => break,
            }
        }
    }
    names
}

// stable src/dst endpoint derivation for the convenience filter fields
// (binderdump.src.* / binderdump.dst.*). pure (no epan ffi) so it is
// unit-testable on its own.
pub struct Endpoints {
    // always known: every frame has a local pid (the txn sender or, for
    // non-transaction frames, the capturing process).
    pub src_pid: i32,
    pub src_tid: Option<i32>,
    pub src_cmdline: Option<String>,
    pub dst_pid: Option<i32>,
    pub dst_tid: Option<i32>,
    pub dst_cmdline: Option<String>,
}

pub fn cmdline_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

// resolve stable endpoints for one frame. caller_lookup maps a transaction
// debug_id to the sender's (tid, cmdline) recorded from its send frame; used
// on the receive side where the wire only carries the sender pid.
pub fn resolve_endpoints(
    event: &EventProtocol,
    caller_lookup: impl Fn(i32) -> Option<(i32, String)>,
) -> Endpoints {
    // default: local process is the source, no destination.
    let mut ep = Endpoints {
        src_pid: event.pid,
        src_tid: Some(event.tid),
        src_cmdline: Some(cmdline_to_string(&event.cmdline)),
        dst_pid: None,
        dst_tid: None,
        dst_cmdline: None,
    };

    let Some(ioctl) = event.ioctl_data.as_ref() else {
        return ep;
    };
    let Some(bwr) = ioctl.bwr.as_ref() else {
        return ep;
    };
    let Some(txn) = bwr.transaction.as_ref() else {
        return ep;
    };

    // replies keep the local-src / no-dst default; richer reply linkage lives
    // under the binderdump_reply.* post-dissector fields.
    if txn.reply != 0 {
        return ep;
    }

    // the transaction rides the WRITE buffer on the sender (BC_TRANSACTION) and
    // the READ buffer on the receiver (BR_TRANSACTION). on each side the LOCAL
    // process is one endpoint and the wire carries the other; resolving this way
    // makes src/dst identical on both frames of a txn:
    //   send (write): local = caller (default src); wire to_proc/target = callee.
    //   recv (read):  local = callee; wire sender_pid = caller. the kernel only
    //                 stamps sender_pid on this side, and to_proc here is NOT the
    //                 target (it mirrors the sender), so the callee must come
    //                 from the local event, not the wire.
    if bwr.is_write() {
        // 0 / empty is the unset sentinel; one-way (async) txns carry to_thread
        // == 0 and the target proc/cmdline may be unresolved.
        ep.dst_pid = (txn.to_proc != 0).then_some(txn.to_proc);
        ep.dst_tid = (txn.to_thread != 0).then_some(txn.to_thread);
        let dst_cmd = cmdline_to_string(&txn.target_cmdline);
        ep.dst_cmdline = (!dst_cmd.is_empty()).then_some(dst_cmd);
    } else {
        ep.src_pid = txn.sender_pid;
        match caller_lookup(txn.debug_id) {
            Some((tid, cmd)) => {
                ep.src_tid = Some(tid);
                ep.src_cmdline = Some(cmd);
            }
            None => {
                ep.src_tid = None;
                ep.src_cmdline = None;
            }
        }
        ep.dst_pid = Some(event.pid);
        ep.dst_tid = Some(event.tid);
        ep.dst_cmdline = Some(cmdline_to_string(&event.cmdline));
    }
    ep
}

pub trait AddBinderTypes {
    fn add_bc_types(self) -> Self;
    fn add_br_types(self) -> Self;
}

impl AddBinderTypes for ProtocolBuilder {
    fn add_bc_types(self) -> Self {
        self.add_extra_enum::<binder_command::binder_command>("BC", bc_prefix!("bc"))
            .add_extra_type::<binder_command::DeathCommand>(
                "Death Notification Request",
                bc_prefix!("death"),
            )
            .add_extra_type::<binder_command::RefCommand>("Ref", bc_prefix!("ref"))
            .add_extra_type::<binder_command::DeathDoneCommand>(
                "Dead Binder Done",
                bc_prefix!("dead_done"),
            )
            .add_extra_type::<binder_command::RefDoneCommand>("Ref Done", bc_prefix!("ref_done"))
            .add_extra_type::<binder_command::FreeBufferCommand>("Free Buffer", bc_prefix!("free"))
            .add_extra_type::<binderdump_structs::binder_types::transaction::Transaction>(
                "Transaction",
                bc_prefix!("transaction"),
            )
            .add_extra_type::<binderdump_structs::binder_types::transaction::TransactionSg>(
                "TransactionSg",
                bc_prefix!("transaction_sg"),
            )
    }

    fn add_br_types(self) -> Self {
        self.add_extra_enum::<binder_return::binder_return>("Return", br_prefix!("br"))
            .add_extra_type::<binder_return::RefReturn>("Ref", br_prefix!("ref"))
            .add_extra_type::<binder_return::ErrorReturn>("Error", br_prefix!("error"))
            .add_extra_type::<binder_return::DeadBinder>("Dead Binder", br_prefix!("dead_binder"))
            .add_extra_type::<binder_return::ClearDeathNotificationDone>(
                "Clear Death Notification Done",
                br_prefix!("clear_death_done"),
            )
            .add_extra_type::<binder_return::FrozenStateInfo>(
                "Frozen State Info",
                br_prefix!("frozen_state_info"),
            )
            .add_extra_type::<binder_return::FreezeNotificationDone>(
                "Clear Freeze Notification Done",
                br_prefix!("clear_freeze_done"),
            )
            .add_extra_type::<binder_return::TransactionSecCtx>(
                "TransactionSecCtx",
                br_prefix!("transaction_secctx"),
            )
            .add_extra_type::<binderdump_structs::binder_types::transaction::Transaction>(
                "Transaction",
                br_prefix!("transaction"),
            )
            .add_extra_type::<binderdump_structs::binder_types::transaction::TransactionSg>(
                "TransactionSg",
                br_prefix!("transaction_sg"),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_command_names_empty() {
        let names = collect_command_names(true, &[]);
        assert!(names.is_empty());
    }

    #[test]
    fn collect_command_names_bc_free_buffer() {
        // BC_FREE_BUFFER opcode + 8-byte buffer pointer payload.
        let bc_free =
            binderdump_structs::binder_types::binder_command::binder_command::BC_FREE_BUFFER as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&bc_free.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        let names = collect_command_names(true, &data);
        assert_eq!(names, vec!["BC_FREE_BUFFER"]);
    }

    use binderdump_structs::binder_types::{binder_ioctl, BinderInterface};
    use binderdump_structs::bwr_layer::{
        BinderWriteReadProtocol, BinderWriteReadType, TransactionProtocol,
    };
    use binderdump_structs::event_layer::{EventType, IoctlProtocol};

    fn comm(s: &str) -> [u8; 16] {
        let mut b = [0u8; 16];
        let bytes = s.as_bytes();
        b[..bytes.len()].copy_from_slice(bytes);
        b
    }

    fn event_with_txn(
        local_pid: i32,
        local_tid: i32,
        local_cmd: &str,
        bwr_type: BinderWriteReadType,
        txn: Option<TransactionProtocol>,
    ) -> EventProtocol {
        let bwr = BinderWriteReadProtocol {
            bwr_type,
            transaction: txn,
            ..Default::default()
        };
        let ioctl = IoctlProtocol::new(7, binder_ioctl::default(), 0, 0, 0, 0, 0, false, Some(bwr));
        EventProtocol::new(
            0,
            local_pid,
            local_tid,
            comm(local_cmd),
            EventType::FinishedIoctl,
            BinderInterface::default(),
            0,
            local_cmd.as_bytes().to_vec(),
            Some(ioctl),
        )
    }

    fn txn(
        reply: i32,
        debug_id: i32,
        sender_pid: i32,
        to_proc: i32,
        to_thread: i32,
        target: &str,
    ) -> TransactionProtocol {
        TransactionProtocol {
            reply,
            debug_id,
            sender_pid,
            to_proc,
            to_thread,
            target_cmdline: target.as_bytes().to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn send_frame_uses_local_as_src_target_as_dst() {
        let e = event_with_txn(
            100,
            1001,
            "app",
            BinderWriteReadType::Write,
            Some(txn(0, 42, 0, 200, 2002, "system_server")),
        );
        let ep = resolve_endpoints(&e, |_| None);
        assert_eq!(ep.src_pid, 100); // send frame: wire sender_pid is 0, so src_pid must be the local event.pid
        assert_eq!(ep.src_tid, Some(1001));
        assert_eq!(ep.src_cmdline.as_deref(), Some("app"));
        assert_eq!(ep.dst_pid, Some(200));
        assert_eq!(ep.dst_tid, Some(2002));
        assert_eq!(ep.dst_cmdline.as_deref(), Some("system_server"));
    }

    #[test]
    fn recv_frame_resolves_src_from_lookup() {
        // recv (read) frame: local IS the callee. wire to_proc/target are NOT the
        // target here (they mirror the sender), so dst must come from the local
        // event; src comes from sender_pid + the caller-info lookup.
        let e = event_with_txn(
            200,
            2002,
            "system_server",
            BinderWriteReadType::Read,
            Some(txn(0, 42, 100, 100, 100, "NOT_THE_TARGET")),
        );
        let ep = resolve_endpoints(&e, |id| {
            assert_eq!(id, 42);
            Some((1001, "app".into()))
        });
        assert_eq!(ep.src_pid, 100);
        assert_eq!(ep.src_tid, Some(1001));
        assert_eq!(ep.src_cmdline.as_deref(), Some("app"));
        assert_eq!(ep.dst_pid, Some(200));
        assert_eq!(ep.dst_tid, Some(2002));
        assert_eq!(ep.dst_cmdline.as_deref(), Some("system_server"));
    }

    #[test]
    fn recv_frame_without_lookup_keeps_pid_only() {
        let e = event_with_txn(
            200,
            2002,
            "system_server",
            BinderWriteReadType::Read,
            Some(txn(0, 42, 100, 100, 100, "NOT_THE_TARGET")),
        );
        let ep = resolve_endpoints(&e, |_| None);
        assert_eq!(ep.src_pid, 100);
        assert_eq!(ep.src_tid, None);
        assert_eq!(ep.src_cmdline, None);
        assert_eq!(ep.dst_pid, Some(200));
        assert_eq!(ep.dst_cmdline.as_deref(), Some("system_server"));
    }

    #[test]
    fn reply_frame_is_local_src_no_dst() {
        let e = event_with_txn(
            200,
            2002,
            "system_server",
            BinderWriteReadType::Write,
            Some(txn(1, 42, 100, 0, 0, "")),
        );
        let ep = resolve_endpoints(&e, |_| None);
        assert_eq!(ep.src_pid, 200);
        assert_eq!(ep.src_tid, Some(2002));
        assert_eq!(ep.src_cmdline.as_deref(), Some("system_server"));
        assert_eq!(ep.dst_pid, None);
        assert_eq!(ep.dst_cmdline, None);
    }

    #[test]
    fn non_transaction_frame_is_local_src_no_dst() {
        let bwr = BinderWriteReadProtocol {
            bwr_type: BinderWriteReadType::Write,
            transaction: None,
            ..Default::default()
        };
        let ioctl = IoctlProtocol::new(7, binder_ioctl::default(), 0, 0, 0, 0, 0, false, Some(bwr));
        let e = EventProtocol::new(
            0,
            300,
            3003,
            comm("daemon"),
            EventType::FinishedIoctl,
            BinderInterface::default(),
            0,
            b"daemon".to_vec(),
            Some(ioctl),
        );
        let ep = resolve_endpoints(&e, |_| None);
        assert_eq!(ep.src_pid, 300);
        assert_eq!(ep.src_tid, Some(3003));
        assert_eq!(ep.src_cmdline.as_deref(), Some("daemon"));
        assert_eq!(ep.dst_pid, None);
    }

    #[test]
    fn async_send_frame_has_no_dst_tid() {
        // one-way transaction: kernel leaves to_thread == 0 (no blocked thread).
        let e = event_with_txn(
            100,
            1001,
            "app",
            BinderWriteReadType::Write,
            Some(txn(0, 42, 100, 200, 0, "system_server")),
        );
        let ep = resolve_endpoints(&e, |_| None);
        assert_eq!(ep.dst_pid, Some(200));
        assert_eq!(ep.dst_tid, None);
        assert_eq!(ep.dst_cmdline.as_deref(), Some("system_server"));
    }

    #[test]
    fn endpoints_stable_across_send_and_recv() {
        // the same transaction's send and recv frames must report identical src
        // AND dst, so one filter catches both. send: local=caller(100), wire
        // to_proc=callee(200), sender_pid=0.
        let send = event_with_txn(
            100,
            1001,
            "app",
            BinderWriteReadType::Write,
            Some(txn(0, 42, 0, 200, 2002, "system_server")),
        );
        let send_ep = resolve_endpoints(&send, |_| None);
        // recv: local=callee(200), wire sender_pid=caller(100); to_proc mirrors
        // the sender (not the target), so dst must come from the local event.
        let recv = event_with_txn(
            200,
            2002,
            "system_server",
            BinderWriteReadType::Read,
            Some(txn(0, 42, 100, 100, 100, "NOT_THE_TARGET")),
        );
        let recv_ep = resolve_endpoints(&recv, |_| Some((1001, "app".into())));
        assert_eq!(send_ep.src_pid, 100);
        assert_eq!(recv_ep.src_pid, 100);
        assert_eq!(send_ep.dst_pid, Some(200));
        assert_eq!(recv_ep.dst_pid, Some(200));
        assert_eq!(send_ep.src_cmdline, recv_ep.src_cmdline);
        assert_eq!(send_ep.dst_cmdline, recv_ep.dst_cmdline);
    }
}
