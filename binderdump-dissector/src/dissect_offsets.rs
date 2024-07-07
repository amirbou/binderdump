use crate::epan_plugin::HeaderFieldsManager;
use anyhow::{Context, Result};
use binderdump_epan_sys::epan;
use binderdump_structs::binder_serde::StructOffset;
// fn dissect_offsets_prefix(offsets: StructOffset, manager: &HeaderFieldsManager, prefix: String) {}

pub fn dissect_offsets_inner(
    offsets: StructOffset,
    manager: &HeaderFieldsManager,
    prefix: String,
    tvb: *mut epan::tvbuff_t,
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
            dissect_offsets_inner(struct_offset, manager, field_path, tvb, tree)?;
        } else {
            let handle = manager
                .get_handle(&field_path)
                .context(format!("Failed to find handle for field: {}", field_path))?;

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

    Ok(())
}

pub fn dissect_offsets(
    offsets: StructOffset,
    manager: &HeaderFieldsManager,
    prefix: String,
    tvb: *mut epan::tvbuff_t,
    tree_item: *mut epan::proto_item,
) -> Result<()> {
    let ett = manager
        .get_handle(&prefix)
        .context(format!("ett handle of {} not found", prefix))?;

    let tree = unsafe { epan::proto_item_add_subtree(tree_item, ett) };

    dissect_offsets_inner(offsets, manager, prefix, tvb, tree)
}
