## Task 3 Report

**Status:** DONE

**Commit:** eaf7c51d (parent 505c658a — correct ancestry confirmed)

**Build:** `cargo build -p binderdump-dissector` — Finished dev profile, 0 errors. Dead-code warnings on `emit`, `build_status`, `Severity`, `Status`, `StatusInput` (all expected until Task 4 wires them).

---

### Changes

**`binderdump-dissector/src/decode_status.rs`**
- Added `use` imports: `HeaderFieldsManager`, `epan`, `EventProtocol` (path corrected to `binderdump_structs::event_layer::EventProtocol` — the brief used a wrong `binder_types::event_layer` subpath not used anywhere else in the crate), `c_int`, `CString`.
- Added `static mut EI_DECODE_INCOMPLETE` and `EI_DECODE_NA` (both `epan::expert_field { ei: -1, hf: -1 }`).
- Added `pub fn register(proto_id: c_int)` — registers both EIs against the main binderdump proto via `expert_register_protocol` + `expert_register_field_array`.
- Added `pub fn emit(...)` — looks up `binderdump.decode_status` handle, adds a string item via `proto_tree_add_string`, marks it generated via `binderdump_proto_item_set_generated`, then calls `expert_add_info` with the appropriate EI.

**`binderdump-dissector/src/epan_plugin.rs`**
- Added `.add_extra_field(FieldInfo { name: "Decode status", abbrev: "binderdump.decode_status", ftype: FtEnum::String, display: FieldDisplay::StrAsciis, strings: None })` after the "Method source" block.
- Added `crate::decode_status::register(proto_id);` after `crate::reply_postdissector::register();` in `register_protoinfo`.

---

### Symbol decisions

- **`PI_UNDECODED`**: present in the bindings (`u32 = 83886080`). Used for both EIs since it's the most semantically accurate group for "we have data but couldn't decode it". No need to fall back to `PI_PROTOCOL`.
- **`PI_WARN`** / **`PI_NOTE`**: both present. Used as specified.
- **`binderdump_proto_item_set_generated`**: confirmed in `epan_utils.rs` (lines 45, 56, 67, 82) applied to `*mut proto_item` items returned by `proto_tree_add_string` — applied the same way in `emit`.
- **Import path bug in brief**: the brief's `use binderdump_structs::binder_types::event_layer::EventProtocol` is wrong; the correct path used throughout the dissector is `binderdump_structs::event_layer::EventProtocol`. Fixed.

---

## Task 3 — Review fixup (decode_status review findings)

**Status:** DONE

**Changes in `binderdump-dissector/src/decode_status.rs`:**

1. **Duplicate expert-info name (important):** Both `ei_register_info` entries had `name: c"binderdump.decode_status"`. Changed to distinct names:
   - `EI_DECODE_INCOMPLETE` → `c"binderdump.decode_status.incomplete"`
   - `EI_DECODE_NA` → `c"binderdump.decode_status.not_applicable"`

2. **`-1` hf fallback UB (minor):** `manager.get_handle(...).unwrap_or(-1)` replaced with `.ok_or_else(|| anyhow::anyhow!("decode_status hf not registered"))?` — propagates a real error instead of passing -1 to the Wireshark FFI.

3. **Stale file header comment (minor):** Top-of-file comment claiming "Pure — no Wireshark types here" replaced with an accurate two-liner: `build_status` is pure/unit-testable; `register`/`emit` hold the epan FFI side.

**Build:** `cargo build -p binderdump-dissector` — Finished dev profile [unoptimized + debuginfo], 0 errors. Dead-code warnings on `emit`, `build_status`, `Severity`, `Status`, `StatusInput`, `stream_index_for_anchor` — all pre-existing, expected until Task 4 wires them in.
