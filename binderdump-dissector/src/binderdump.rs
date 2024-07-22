use binderdump_epan_sys::epan;
use binderdump_structs;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::binder_types::binder_command;
use binderdump_structs::binder_types::binder_return;
use binderdump_structs::binder_types::bwr_trait::Bwr;
use binderdump_structs::event_layer::EventProtocol;
use binderdump_trait::ConstOffsets;
use binderdump_trait::EpanProtocolEnum;
use std::ffi::{c_int, CString};
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
    let mut returns_str = String::new();
    let br_dissect = BwrDissect {
        event,
        manager,
        tvb,
        pinfo,
    };

    while pos < data.len() {
        let result = binder_return::BinderReturn::from_bytes(&data[pos..])?;
        returns_str.push_str(result.get_header().to_str());
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

                _ => (),
            }
        }

        pos += result.size();
        if pos < data.len() {
            returns_str.push_str(", ");
        }
    }
    if pos != data.len() {
        return Err(anyhow::anyhow!(
            "Only {} out of {} bytes comsumed from bwr read command",
            pos,
            data.len()
        ));
    }

    let returns_cstr = CString::new(returns_str)?;
    unsafe {
        epan::col_add_str(
            (*pinfo).cinfo,
            epan::COL_INFO as c_int,
            returns_cstr.as_ptr(),
        )
    };
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
    let mut commands_str = String::new();

    let bc_dissect = BwrDissect {
        event,
        manager,
        tvb,
        pinfo,
    };

    while pos < data.len() {
        let result = binder_command::BinderCommand::from_bytes(&data[pos..])?;
        commands_str.push_str(result.get_header().to_str());
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
        if pos < data.len() {
            commands_str.push_str(", ");
        }
    }
    if pos != data.len() {
        return Err(anyhow::anyhow!(
            "Only {} out of {} bytes comsumed from bwr write command",
            pos,
            data.len()
        ));
    }

    let commands_cstr = CString::new(commands_str)?;
    unsafe {
        epan::col_add_str(
            (*pinfo).cinfo,
            epan::COL_INFO as c_int,
            commands_cstr.as_ptr(),
        )
    };
    Ok(())
}

pub fn dissect_bwr_data(
    handle: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    event: &EventProtocol,
    offset: FieldOffset,
    tvb: *mut epan::tvbuff,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    let bwr = event.ioctl_data.as_ref().unwrap().bwr.as_ref().unwrap();

    match bwr.is_write() {
        true => dissect_bc_data(event, handle, manager, &bwr.data, offset, tvb, pinfo, tree),
        false => dissect_br_data(event, handle, manager, &bwr.data, offset, tvb, pinfo, tree),
    }
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
