use crate::header_fields_manager::HeaderFieldsManager;
use anyhow::{Context, Result};
use binderdump_epan_sys::epan;
use binderdump_structs::binder_serde::StructOffset;
use binderdump_trait::EpanProtocol;
// fn dissect_offsets_prefix(offsets: StructOffset, manager: &HeaderFieldsManager, prefix: String) {}

pub fn dissect_offsets_inner<T: EpanProtocol>(
    base: &T,
    offsets: StructOffset,
    manager: &HeaderFieldsManager<T>,
    prefix: String,
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> Result<()> {
    let ett = manager
        .get_handle(&prefix)
        .context(format!("ett handle of {} not found", prefix))?;

    // proto_tree_add_subtree copies the string, so its ok
    let name = std::ffi::CString::new(offsets.name)?;
    let tree = unsafe {
        epan::proto_tree_add_subtree(
            tree,
            tvb,
            offsets.offset.try_into()?,
            offsets.size.try_into()?,
            ett,
            std::ptr::null_mut(),
            name.as_ptr(),
        )
    };

    for field in offsets.fields {
        let field_path = format!("{}.{}", prefix, field.field_name);
        if let Some(struct_offset) = field.inner_struct {
            dissect_offsets_inner(base, struct_offset, manager, field_path, tvb, pinfo, tree)?;
        } else {
            let handle = manager
                .get_handle(&field_path)
                .context(format!("Failed to find handle for field: {}", field_path))?;

            if let Some(handler) = manager.get_custom_handle(&field_path) {
                handler.call(handle, manager, base, field, tvb, pinfo, tree)?;
            } else {
                unsafe {
                    epan::proto_tree_add_item(
                        tree,
                        handle,
                        tvb,
                        field.offset.try_into()?,
                        field.size.try_into()?,
                        epan::ENC_LITTLE_ENDIAN,
                    );
                }
            }
        }
    }

    Ok(())
}

pub fn dissect_offsets<T: EpanProtocol>(
    base: &T,
    offsets: StructOffset,
    manager: &HeaderFieldsManager<T>,
    prefix: String,
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    tree_item: *mut epan::proto_item,
) -> Result<()> {
    let ett = manager
        .get_handle(&prefix)
        .context(format!("ett handle of {} not found", prefix))?;

    let tree = unsafe { epan::proto_item_add_subtree(tree_item, ett) };

    dissect_offsets_inner(base, offsets, manager, prefix, tvb, pinfo, tree)
}
