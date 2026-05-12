---
name: wireshark-dissectors
description: >
  Canonical Wireshark dissector patterns from upstream `doc/README.*` (dissector,
  request_response_tracking, wmem, heuristic, conversation). Covers two-phase
  registration, the dissect-callback contract, ett subtrees, wmem memory scopes,
  conversation_t state, request/response correlation (FT_FRAMENUM cross-refs +
  PINFO_FD_VISITED two-pass model), generated items, and the common gotchas that
  silently break dissectors. TRIGGER when: writing or reviewing any `dissect_*`
  callback; designing request/response (or reply) correlation; allocating per-flow
  or per-file state; touching `hf_register_info` / `proto_register_subtree_array`;
  diagnosing a dissector that loads but produces wrong values or claims wrong
  byte ranges. PAIRS WITH `wireshark-epan` (project-specific Rust FFI quirks);
  this skill is upstream-canonical and language-neutral.
---

Upstream-canonical Wireshark dissector patterns. Apply these BEFORE inventing project-local mechanisms.

## Two-phase registration

Every dissector splits into two startup callbacks:

1. `proto_register_<name>` — registers protocol id, header fields (`hf_register_info[]`), subtree (`ett`) ids. Runs once before any packet.
2. `proto_reg_handoff_<name>` — attaches the dissector to a parent table (`wtap_encap`, `tcp.port`, `udp.port`, etc.).

In plugins: wire both through `proto_plugin { register_protoinfo, register_handoff }` and `proto_register_plugin`. Plugin .so symbols are dlsym'd by name — see `wireshark-epan` skill for exact ABI.

## `hf_register_info` shape

```c
{ &hf_my_field,
  { "Display name",                  // tree label
    "abbrev.dotted.path",            // filter syntax
    FT_UINT32, BASE_HEX,             // ftenum + display
    NULL, 0x0,                       // strings table, bitmask
    "Tooltip (or NULL)", HFILL }}
```

- `abbrev` must be unique across loaded protocols. Convention: `<proto>.<struct>.<field>`.
- `FT_*` drives parse width: `FT_BYTES`, `FT_STRING` (counted), `FT_STRINGZ` (NUL-terminated), `FT_UINT*`/`FT_INT*`, `FT_NONE` (label-only), `FT_BOOLEAN`, `FT_RELATIVE_TIME`, `FT_FRAMENUM`.
- `BASE_*` is display: `BASE_DEC`, `BASE_HEX`, `BASE_DEC_HEX`. Bytes use `SEP_SPACE` etc. Strings use `STR_ASCII`/`STR_UNICODE`.
- `HFILL` is a sentinel macro that fills internal state. Forgetting it compiles but mis-initializes runtime.

## ett subtrees

Each collapsible subtree under your protocol needs an `int ett_*` id, registered via `proto_register_subtree_array`. Without registration, `proto_item_add_subtree` silently expands inline.

```c
static int ett_foo;
static int *ett[] = { &ett_foo };
proto_register_subtree_array(ett, array_length(ett));
```

## The dissect callback contract

```c
static int dissect_my(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    int offset = 0;
    proto_item *ti = proto_tree_add_item(tree, proto_my, tvb, 0, -1, ENC_NA);
    proto_tree *sub = proto_item_add_subtree(ti, ett_my);

    proto_tree_add_item(sub, hf_field, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return tvb_captured_length(tvb);
}
```

- **Return bytes consumed.** Return `0` only if you added NOTHING to the tree (= "not my packet, try next").
- `ENC_LITTLE_ENDIAN` / `ENC_BIG_ENDIAN` for integers; `ENC_NA` for bytes/none.
- `tvb_get_*` reads raw without tree; pair with explicit `proto_tree_add_uint`/`add_string` to display.
- Never read past `tvb_reported_length`. `tvb_get_*` throws a Wireshark exception on overrun — fine in C, but FFI bridges must catch it (or pre-bound offsets at the serde layer).

## wmem memory scopes

Three pools you almost always want, from `epan/wmem_scopes.h`:

| Pool | Scope | Use for |
|---|---|---|
| `pinfo->pool` | This packet only | Temporary strings, small allocs for current frame |
| `wmem_file_scope()` | Until file is closed / reloaded | **Per-flow state, request/response tables, conversation data** |
| `wmem_epan_scope()` | Process lifetime | Plugin-global tables that should outlive file reloads |

`wmem_alloc(pool, n)` / `wmem_new(pool, T)` / `wmem_map_new(pool, hash, eq)` etc. NEVER `malloc`/`free` inside a dissector — exceptions can leak heap.

Picking the wrong scope is the #1 cause of weird "works on first open, breaks on filter/reload" bugs.

## conversation_t — per-flow state

```c
#include <epan/conversation.h>

conversation_t *conv = find_or_create_conversation(pinfo);
my_conv_info_t *info = (my_conv_info_t *)conversation_get_proto_data(conv, proto_my);
if (!info) {
    info = wmem_new(wmem_file_scope(), my_conv_info_t);
    info->pdus = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    conversation_add_proto_data(conv, proto_my, info);
}
```

A conversation key is derived from `pinfo` (src/dst addrs + ports + protocol). For protocols without true network endpoints (binder, USB, in-memory IPC), invent stable keys: PID, sequence id, etc., and attach state in a custom pool keyed by them. The same per-file-scope + `wmem_map_t` pattern still applies.

## Request/response correlation (canonical pattern)

From `doc/README.request_response_tracking`. The single most important pattern for any protocol with paired messages.

```c
typedef struct _my_transaction_t {
    uint32_t req_frame;       // frame number of request (for FT_FRAMENUM)
    uint32_t rep_frame;       // frame number of response
    nstime_t req_time;        // for response time calculation
    /* + any per-transaction state you want to carry from req to rep */
} my_transaction_t;

typedef struct _my_conv_info_t {
    wmem_map_t *pdus;         // keyed on transaction id
} my_conv_info_t;
```

```c
/* Inside dissect_*: */
if (!PINFO_FD_VISITED(pinfo)) {
    /* First pass over this frame: mutate state */
    if (is_request) {
        trans = wmem_new(wmem_file_scope(), my_transaction_t);
        trans->req_frame = pinfo->num;
        trans->rep_frame = 0;
        trans->req_time = pinfo->fd->abs_ts;
        wmem_map_insert(info->pdus, GUINT_TO_POINTER(txn_id), trans);
    } else {
        trans = wmem_map_lookup(info->pdus, GUINT_TO_POINTER(txn_id));
        if (trans) trans->rep_frame = pinfo->num;
    }
} else {
    /* Filter eval / re-display: state already built, just look up */
    trans = wmem_map_lookup(info->pdus, GUINT_TO_POINTER(txn_id));
}
```

```c
/* Display the cross-reference: */
if (is_request && trans->rep_frame) {
    proto_item *it = proto_tree_add_uint(tree, hf_response_in,
                                         tvb, 0, 0, trans->rep_frame);
    proto_item_set_generated(it);
}
if (!is_request && trans->req_frame) {
    proto_item *it = proto_tree_add_uint(tree, hf_response_to,
                                         tvb, 0, 0, trans->req_frame);
    proto_item_set_generated(it);

    nstime_t ns;
    nstime_delta(&ns, &pinfo->fd->abs_ts, &trans->req_time);
    it = proto_tree_add_time(tree, hf_response_time, tvb, 0, 0, &ns);
    proto_item_set_generated(it);
}
```

```c
/* hf_register_info entries: */
{ &hf_response_in,
  { "Response In", "myproto.response_in",
    FT_FRAMENUM, BASE_NONE,
    FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
    "The response is in this frame", HFILL }},
{ &hf_response_to,
  { "Request In", "myproto.response_to",
    FT_FRAMENUM, BASE_NONE,
    FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
    "This is a response to the request in this frame", HFILL }},
{ &hf_response_time,
  { "Response Time", "myproto.response_time",
    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
    "Time between request and reply", HFILL }},
```

Key invariants:
- **State pool is `wmem_file_scope()`**, so the map survives the multiple passes Wireshark does over one capture and is dropped on file close.
- **`PINFO_FD_VISITED(pinfo)` gates writes.** Wireshark dissects each frame ≥ twice: once on initial load (build state), again on every filter eval / Apply (read state). Mutating state on every pass duplicates entries and silently corrupts cross-references on Apply.
- **`FT_FRAMENUM` + `FRAMENUM_TYPE(...)`** makes the rendered value a clickable jump in the GUI.
- **`proto_item_set_generated(it)`** marks the item as synthesized — it doesn't claim tvb bytes. Without this, the item shows offset/length data that pretends to be on the wire.
- **`FT_RELATIVE_TIME`** + `nstime_delta` renders an inter-frame duration.

### Adapting this pattern when there are no traditional conversations

For protocols where `find_or_create_conversation(pinfo)` doesn't fit (binder transactions are a good example — endpoints are PIDs, not addresses), drop the `conversation_t` wrapper but keep:

- a single `wmem_map_t *transactions` allocated once via `wmem_epan_scope()` (or `wmem_file_scope()` if you want it cleared per reload — usually the right choice)
- the same `PINFO_FD_VISITED` gating
- the same `FT_FRAMENUM` field definitions

The map can hang off a static `OnceLock`/`OnceCell` if your dissector is plugin-scoped. Be deliberate about scope: a stale state across file reloads produces wrong cross-references on the second pcap; use `wmem_file_scope()` and rebuild from a `register_init_routine` hook if you want re-init guarantees.

## Generated items

Anything the dissector adds that does NOT correspond to bytes in `tvb` must be marked:

```c
proto_item_set_generated(it);
```

This affects display (italicized in the GUI) and tells filter machinery the item is synthetic. Use for: response-in/response-to cross-refs, response time, derived enums, anything you computed from prior state.

## Two-pass dissection model — internalize it

Wireshark dissects each frame multiple times in one session:

1. **First pass:** sequential read of the capture. `pinfo->fd->visited == false`. This is where you populate per-flow/per-transaction state.
2. **Subsequent passes:** filter-apply, GUI redraw, Find-next, tap callbacks. `pinfo->fd->visited == true`. State is already built; you must NOT mutate it (would double-count). You only READ from it for display.

`PINFO_FD_VISITED(pinfo)` is the gate. Forgetting it is the #2 most common dissector bug (after wrong wmem scope).

## Heuristic dissectors (brief)

For protocols that share a transport with others (e.g. UDP/53 used by both DNS and a custom proto), register a **heuristic dissector** that inspects the payload and returns true only if it recognizes the format. See `doc/README.heuristic`. Heuristics must be cheap and conservative — a false positive masks the real protocol.

## Plugin ABI

See the project-specific `wireshark-epan` skill for the exact symbol set, version-pinning, and Rust FFI quirks. Cross-versioned plugin compatibility is **not** a thing — match the running Wireshark's MAJOR.MINOR exactly.

## Sanity-check workflow

After any non-trivial dissector change:

1. `tshark -G protocols | grep <abbrev>` — registration ran.
2. `tshark -G fields | grep <abbrev>.<your_field>` — hf array registered.
3. `tshark -r capture.pcapng -V | head -40` — dissection tree appears under the right protocol.
4. `tshark -r capture.pcapng -Y '<abbrev>.<field>'` — filter syntax works.
5. `tshark -r capture.pcapng -Y '<abbrev>.response_in'` — request frames carry cross-refs (if you added them).
6. Reload the file in the GUI and apply a display filter twice — confirms `PINFO_FD_VISITED` gating doesn't double-add state.

## Common gotchas

- **Wrong wmem scope.** Per-packet state in epan-scope leaks; per-file state in pinfo-scope crashes on Apply.
- **Mutating state without `PINFO_FD_VISITED` check.** Each Apply duplicates entries; cross-refs become wrong on N-th apply.
- **Forgetting `proto_item_set_generated`** for synthesized items. Bytes appear to be "on the wire" when they're not.
- **`FT_*` and `BASE_*` mismatched.** `FT_UINT32` with `BASE_DEC` shows decimals; `FT_BYTES` with `BASE_HEX` ignores `BASE_HEX`.
- **`HFILL` missing.** Compiles, but the entry's hidden tail fields aren't initialized — sporadic crashes on filter eval.
- **`ett` array unregistered.** Subtrees collapse inline, no fold/unfold arrow.
- **Returning wrong byte count.** Return `tvb_captured_length(tvb)` if you consumed everything; return `0` only when you added nothing.
- **Calling `proto_tree_add_*` with `tree == NULL`.** Allowed if you don't need a tree, but check first or you'll hit silent NULL derefs on filter eval (Wireshark passes NULL when only filter values are needed, not tree display).
- **Allocating with `malloc`/`g_malloc` inside a dissector.** Use `wmem_*` — `tvb_get_*` raises C++-style exceptions and your raw allocs leak on the exception path.

## Skeleton

Upstream's `doc/packet-PROTOABBREV.c` is the canonical starting template. New dissectors copy it and substitute. Read it once before writing one from scratch. Key bits:

- `void proto_register_PROTOABBREV(void);` and `void proto_reg_handoff_PROTOABBREV(void);` prototypes at top.
- Statics: `static int proto_PROTOABBREV;`, `static int hf_<field>;`, `static int ett_<subtree>;`, `static expert_field ei_<error>;`, `static dissector_handle_t <proto>_handle;`.
- `dissect_<proto>` signature: `static int dissect_PROTOABBREV(tvbuff_t *, packet_info *, proto_tree *, void *)`.
- The two registration functions wire it all up; `proto_reg_handoff_*` is the place to attach the handle to dissector tables.

## Column writers (Protocol / Info columns)

Column updates land in the GUI's column row. Use them sparingly — `col_*` calls have non-trivial cost when called from a hot path.

| Function | Use |
|---|---|
| `col_set_str(cinfo, COL_PROTOCOL, "MYPROTO")` | Set column to a STATIC string (no copy). Fastest. |
| `col_add_str(cinfo, COL_INFO, dynamic_str)` | Set to a dynamic string (copies into wmem). |
| `col_add_fstr(cinfo, COL_INFO, "%s req, %u bytes", a, b)` | printf-style. Don't use with just `"%s"` — use `col_add_str` instead. |
| `col_clear(cinfo, COL_INFO)` | Clear (typical: call once at start of dissect to overwrite prior layer). |
| `col_append_str(cinfo, COL_INFO, ", more")` | Append, allowing prior layers' content to remain. |
| `col_append_sep_str(cinfo, COL_INFO, ", ", "tail")` | Append with separator only if column non-empty. |
| `col_set_fence(cinfo, COL_INFO)` | Lock current contents — no later layer can clear. |
| `col_set_str(cinfo, COL_PROTOCOL, ...)` should come BEFORE building the tree; columns get committed regardless of tree. |

Pattern: at the top of `dissect_*`, set COL_PROTOCOL, optionally `col_clear(COL_INFO)`. After parsing critical fields, call `col_append_*` to summarize ("foo: 42, bar: baz").

## value_string — enum-to-string decoding

```c
static const value_string my_codes[] = {
    { 0, "Unknown" },
    { 1, "Hello" },
    { 2, "Goodbye" },
    { 0, NULL }      // terminator
};
```

Then in `hf_register_info`, pass `VALS(my_codes)` as the strings table:

```c
{ &hf_my_code,
  { "Code", "myproto.code",
    FT_UINT8, BASE_DEC,
    VALS(my_codes), 0x0,
    NULL, HFILL }},
```

Wireshark renders the value as `Hello (1)` etc. For lookups in dissector logic:

- `val_to_str(scope, val, table, "Unknown (0x%x)")` — string with fallback formatter
- `val_to_str_const(val, table, "Unknown")` — string with literal fallback
- `try_val_to_str(val, table)` — returns NULL on miss
- `val_to_str_ext` / `val_to_str_ext_const` — extended `value_string_ext` for huge tables (binary search instead of linear)

For ranges of values, use `range_string` and `RVALS(...)`. For bitfield-style multi-value (decode each bit), use `proto_tree_add_bitmask` with an array of `hf_register_info` entries, each tagged with the bit mask.

## Expert info — surfacing protocol errors

Use when the dissected bytes are syntactically valid but semantically suspect: unexpected value, length mismatch, deprecated, malformed-but-recoverable.

```c
static expert_field ei_my_short_pdu;

static ei_register_info ei[] = {
    { &ei_my_short_pdu,
      { "myproto.short_pdu", PI_MALFORMED, PI_ERROR,
        "PDU shorter than declared length", EXPFILL }},
};

// In proto_register_*:
expert_module_t *em = expert_register_protocol(proto_my);
expert_register_field_array(em, ei, array_length(ei));

// In dissect_*:
if (length < MY_MIN_LEN) {
    proto_item *ti = proto_tree_add_uint(tree, hf_my_len, tvb, off, 2, length);
    expert_add_info(pinfo, ti, &ei_my_short_pdu);
}
```

`PI_GROUP` is the category: `PI_MALFORMED`, `PI_PROTOCOL`, `PI_SEQUENCE`, `PI_DEPRECATED`, `PI_REQUEST_CODE`, etc. `PI_SEVERITY`: `PI_COMMENT`, `PI_CHAT`, `PI_NOTE`, `PI_WARN`, `PI_ERROR`. The pair surfaces in the GUI's Expert Info dialog and colorizes the packet list row.

## Preferences (per-protocol user knobs)

```c
module_t *m = prefs_register_protocol(proto_my, apply_cb);   // apply_cb invoked when user changes prefs

prefs_register_bool_preference(m, "show_hex", "Show as hex",
    "Display payload as hex instead of UTF-8", &pref_show_hex);

prefs_register_uint_preference(m, "tls_port", "TLS Port",
    "Port for TLS-wrapped traffic", 10, &pref_tls_port);

prefs_register_range_preference(m, "tcp_ports", "TCP Ports",
    "List of TCP ports", &pref_tcp_ports, 65535);

prefs_register_string_preference(m, "user_name", "User name",
    "Free-form text", &pref_user_name);

prefs_register_filename_preference(m, "log_file", "Log file",
    "Where to write debug info", &pref_log_file, FALSE /* mustExist */);

prefs_register_directory_preference(m, "data_dir", "Data directory",
    "Lookup tables", &pref_data_dir);

prefs_register_enum_preference(m, "decode_mode", "Decode mode",
    "Which sub-protocol to assume", &pref_decode_mode, my_enum_vals, FALSE);
```

`apply_cb` typically rewires dissector handles on dissector tables when a port pref changes (see `proto_reg_handoff_*` pattern in the upstream template).

## Heuristic dissection

When a protocol shares a transport (e.g. TCP port 1234 used by multiple custom protos), register a **heuristic dissector** that inspects bytes and votes:

```c
// In proto_reg_handoff_*:
heur_dissector_add("tcp", dissect_my_heur, "MyProto over TCP",
                   "myproto_tcp", proto_my, HEURISTIC_ENABLE);
```

```c
static bool dissect_my_heur(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data) {
    // Cheap checks first. Bail with `false` early if the payload doesn't look like us.
    if (tvb_captured_length(tvb) < MY_MIN_LEN) return false;
    if (tvb_get_uint8(tvb, 0) != 0x42) return false;
    if (tvb_get_uint8(tvb, 1) > 0x33) return false;

    // Looks like us. Pin the conversation to our regular dissector so we
    // don't pay the heuristic cost every subsequent packet on this flow.
    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, my_handle);

    // Dispatch to the real dissector (or inline parsing).
    dissect_my(tvb, pinfo, tree, data);
    return true;
}
```

**Heuristic rules:**
- Be cheap and conservative. A false positive masks the real protocol forever (until manual Decode-As).
- Reject on minimum length first.
- Check magic numbers, value ranges, sane combinations — multiple constraints, not just one.
- Once recognized, pin via `conversation_set_dissector` so future packets skip the heuristic entirely.

## Dissector tables and sub-dissection

Three ways to invoke a sub-dissector:

```c
// 1. Direct call (handle obtained earlier):
call_dissector_with_data(child_handle, tvb, pinfo, tree, data);

// 2. Lookup by integer key (e.g. ethertype, TCP port):
dissector_handle_t h = dissector_get_uint_handle(child_table, key);
if (h) call_dissector(h, tvb, pinfo, tree);

// 3. Lookup by string key (e.g. media type):
h = dissector_get_string_handle(child_table, "application/myformat");
```

Registering YOUR dissector under a parent table:

```c
// In proto_reg_handoff_*:
my_handle = create_dissector_handle(dissect_my, proto_my);
dissector_add_uint("tcp.port", 1234, my_handle);
dissector_add_uint_range("tcp.port", port_range, my_handle);   // dynamic port list
dissector_add_string("media_type", "application/myformat", my_handle);
```

Create your own table that other dissectors can plug into:

```c
// In proto_register_*:
my_table = register_dissector_table("myproto.subtype",
                                    "MyProto subtype",
                                    proto_my,
                                    FT_UINT8, BASE_HEX);
```

## TCP reassembly via `tcp_dissect_pdus`

When your protocol runs over TCP and PDUs span multiple segments (or multiple PDUs share one segment), DON'T parse offsets manually — use `tcp_dissect_pdus`:

```c
static int dissect_my_tcp(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree,
                     desegment,                  // bool from prefs
                     MY_HEADER_LEN,              // fixed-size prefix that contains length
                     get_my_pdu_length,          // callback: read prefix → return total PDU length
                     dissect_my_pdu,             // callback: invoked once per complete PDU
                     data);
    return tvb_reported_length(tvb);
}
```

`get_my_pdu_length(pinfo, tvb, offset, data)` returns the full PDU length given the prefix bytes. `dissect_my_pdu` is invoked with a tvb pre-trimmed to exactly one PDU. Wireshark handles segment boundaries, partial PDUs, and out-of-order delivery.

For UDP-equivalent, `udp_dissect_pdus` exists with a similar shape (one PDU per UDP datagram, no reassembly).

## Tap system (event notification)

A tap lets external code subscribe to dissected packets without modifying dissectors. Typical use: stats, exporters, custom CLI tools (`tshark -z`).

```c
// In proto_register_*:
my_tap = register_tap("myproto");

// In dissect_*, after parsing:
tap_queue_packet(my_tap, pinfo, my_struct_ptr);
```

Tap listeners register via `register_tap_listener("myproto", ...)` and get the `pinfo` + the struct pointer per packet. `stats_tree` is a higher-level API for simple counter trees (`README.stats_tree`).

## Optimizations

`tree` can be `NULL` when Wireshark is only evaluating filters, not building a display tree. Guard expensive tree work:

```c
if (tree) {
    // Detailed tree-building goes here.
}
// Always do the work needed for filter eval (col_set, tap_queue, parse for return value).
```

But: **don't** guard `proto_tree_add_item` itself — Wireshark's macros handle `NULL` tree and return faked items, which is faster than a manual check. The `if (tree)` guard is for genuinely expensive computations (long strings, multi-pass scans) that only serve display.

`ptvcursor` is a helper for sequential parsing of fixed-layout PDUs — call `ptvcursor_add` repeatedly, the cursor advances internally. Less verbose than tracking `offset` manually for big record-style protocols.

## Conversations API (extended)

Beyond `find_or_create_conversation(pinfo)`, useful entry points:

- `conversation_new(setup_frame, addr1, addr2, ctype, port1, port2, options)` — explicit construction (when you know all four endpoints + port-or-id pair).
- `find_conversation(frame, addr1, addr2, ctype, port1, port2, options)` — explicit lookup without auto-create.
- `find_conversation_pinfo(pinfo, options)` — search by `pinfo` only.
- `conversation_set_dissector(conv, handle)` — bind a dissector to this conversation so future packets skip table lookup.

For non-network protocols (binder, USB, shared memory): the conversation framework still applies — invent a stable identifier (PID pair, endpoint id, etc.), wrap it in an `address`, and pass through. Or skip `conversation_t` entirely and key your state on whatever id is natural; the per-file `wmem_map_t` pattern works either way.

## Decode As

When the dissector can be applied to multiple parents (e.g. arbitrary TCP ports, arbitrary RTP payload types), register Decode-As support so users can manually assign your dissector at runtime:

```c
register_decode_as(&my_decode_as);   // structure pointing at table, list-of-defaults, etc.
```

This adds your dissector to the GUI's Analyze → Decode As menu. See `epan/decode_as.h`.

## Initialization / cleanup hooks

```c
register_init_routine(my_init);       // called per file open — clear caches, rebuild state
register_cleanup_routine(my_cleanup); // called on prefs change or unload — free anything not in wmem
```

These are the file-scope hooks. `my_init` is the canonical place to clear plugin-global state that's NOT in `wmem_file_scope` (which gets cleared automatically when the file closes).

## ptvcursor (sequential parser helper)

```c
ptvcursor_t *c = ptvcursor_new(pool, tree, tvb, 0);
ptvcursor_add(c, hf_a, 4, ENC_BIG_ENDIAN);     // advance 4 bytes
ptvcursor_add(c, hf_b, 2, ENC_LITTLE_ENDIAN);
ptvcursor_push_subtree(c, hf_sub, ett_sub);    // descend into a subtree
ptvcursor_add(c, hf_sub_field, 8, ENC_NA);
ptvcursor_pop_subtree(c);
ptvcursor_free(c);
```

Cleaner than manual offset arithmetic for densely-packed binary records. Don't bother for protocols with conditional layouts; the manual style is clearer there.

## Display-filter type system reference

Internal field types (`ftenum`, from `epan/ftypes/ftypes.h`):

```
FT_NONE, FT_PROTOCOL, FT_BOOLEAN, FT_CHAR,
FT_UINT8, FT_UINT16, FT_UINT24, FT_UINT32, FT_UINT40..64,
FT_INT8..INT64,
FT_FLOAT, FT_DOUBLE,
FT_ABSOLUTE_TIME, FT_RELATIVE_TIME,
FT_STRING, FT_STRINGZ, FT_UINT_STRING, FT_STRINGZPAD,
FT_BYTES, FT_UINT_BYTES, FT_AX25, FT_VINES, FT_ETHER,
FT_IPv4, FT_IPv6, FT_IPXNET, FT_FCWWN,
FT_GUID, FT_OID, FT_REL_OID, FT_SYSTEM_ID,
FT_EUI64,
FT_FRAMENUM,            // clickable jump to another frame
FT_PCRE,
FT_IEEE_11073_SFLOAT, FT_IEEE_11073_FLOAT
```

Display formats (`field_display_e`):

```
BASE_NONE, BASE_DEC, BASE_HEX, BASE_OCT, BASE_DEC_HEX, BASE_HEX_DEC,
BASE_CUSTOM,
SEP_DOT, SEP_DASH, SEP_COLON, SEP_SPACE,
STR_ASCII, STR_UNICODE,
BASE_EXT_STRING,        // value_string_ext lookup
BASE_RANGE_STRING,      // range_string lookup
BASE_UNIT_STRING,       // append a unit suffix
```

`BASE_*` and `STR_*` are mutually exclusive depending on `FT_*`. Pair them sensibly: `FT_BYTES + SEP_SPACE`, `FT_STRING + STR_ASCII`, `FT_UINT* + BASE_DEC/HEX`. Mismatches sometimes compile and silently misrender.

## Dev environment + testing

- Wireshark builds out-of-tree against pkg-config-supplied `wireshark` + `glib-2.0`. The plugin .so links against `libwireshark`; the ABI is pinned per `<MAJOR>.<MINOR>`.
- Upstream test suite: `test/` directory with pytest-based dissector smoke tests. Pattern: `tshark -r tests/captures/foo.pcap -Y 'myproto.field == X' | grep ...`. Reuse for any new dissector.
- For Rust-FFI dissectors (this repo's style), tests go through `tshark` on a committed fixture pcapng — see `binderdump-dissector/tests/dissect.rs`. The fixture is regenerated via a device script; never edit pcapng bytes by hand.

## More gotchas

- **`col_*` after `col_set_fence`** is a silent no-op — useful for outer layers, but a head-scratcher when you forget you set a fence.
- **`expert_add_info_format(...)`** with a stale `proto_item*` (from a prior packet's tree) crashes. Always pair with the item created on THIS dissect pass.
- **`conversation_new`** options `NO_ADDR_B | NO_PORT_B` etc. matter — wildcard fields must match exactly, otherwise `find_conversation` won't find what you stored.
- **Per-protocol stats counters** in a static int are NOT thread-safe across multiple worker dissection threads (Wireshark 4.x onwards uses them). Use `g_atomic_int_add` or move state into `wmem_file_scope`.
- **`tcp_dissect_pdus` length callback returning 0 or a too-small value** loops forever — return at least `length_so_far + 1`.
- **`heur_dissector_add` to a non-existent parent table** silently fails on plugin load. Verify the parent dissector exists (use `find_dissector` / `find_dissector_table`).
- **`prefs_register_*_preference`** with a name colliding with an existing pref silently overwrites. Namespace your prefs with the protocol abbrev.

## Reference documents (Wireshark master)

- `doc/README.dissector` — canonical introduction, section 2 covers advanced topics
- `doc/README.request_response_tracking` — the exact pattern shown above
- `doc/README.wmem` — every memory rule, every scope
- `doc/README.heuristic` — when and how to write heuristic dissectors
- `doc/README.tapping` — tap system + stats_tree
- `doc/README.stats_tree` — simple counter-tree GUI / tshark `-z`
- `doc/README.display_filter` — `ftenum`, field-value engine, filter parser
- `doc/README.developer` — broader contribution guide
- `doc/packet-PROTOABBREV.c` — copy-and-substitute skeleton
- `epan/conversation.h`, `epan/wmem_scopes.h`, `epan/proto.h`, `epan/expert.h`, `epan/prefs.h` — primary headers
- Developer's Guide (HTML): https://www.wireshark.org/docs/wsdg_html_chunked/ — chapter "Adding a new dissector"
