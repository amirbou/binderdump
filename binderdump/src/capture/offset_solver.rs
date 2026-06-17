// Derives binder reply-correlation offsets from calibration samples shipped by
// offsets.bpf.c. Pure logic so it can be unit-tested on the host without a
// device. Part of the binder offset-finder tool.

use anyhow::{bail, Result};
use std::collections::HashMap;

// window sizes; must match offsets.bpf.c
pub const STRUCT_WIN: usize = 256;
pub const DEREF_WIN: usize = 128;
const MIN_REPLY_CONFIRMATIONS: usize = 3;

#[derive(Debug, Clone)]
pub struct Deref {
    pub src_off: u32,
    pub window: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub txn_ptr: u64,
    pub reply: bool,
    // debug_id value read from the structured binder_transaction tracepoint for
    // this same event. Lets us locate the debug_id field by an exact value match
    // in the struct window. 0 means the structured tp never supplied it.
    pub debug_id: u32,
    pub struct_window: Vec<u8>,
    pub derefs: Vec<Deref>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedOffsets {
    pub to_thread: u32,
    pub transaction_stack: u32,
    pub debug_id: u32,
}

impl DerivedOffsets {
    pub fn to_reply_offsets_arg(&self) -> String {
        format!(
            "to_thread={},transaction_stack={},debug_id={}",
            self.to_thread, self.transaction_stack, self.debug_id
        )
    }
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        // length checked by the get(..) above; the slice is exactly 4 bytes
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        // length checked by the get(..) above; the slice is exactly 8 bytes
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

// Find the offset of `debug_id` by searching for the exact value the structured
// tracepoint reported for each event. The winning offset is the 4-aligned slot
// whose u32 equals every sample's known debug_id. Samples whose debug_id is 0
// (structured tp didn't supply one) are ignored.
fn find_debug_id_offset(samples: &[Sample]) -> Result<u32> {
    let known: Vec<&Sample> = samples.iter().filter(|s| s.debug_id != 0).collect();
    if known.len() < MIN_REPLY_CONFIRMATIONS {
        bail!(
            "insufficient debug_id samples ({}, need {}); is the structured \
             binder_transaction tracepoint available?",
            known.len(),
            MIN_REPLY_CONFIRMATIONS
        );
    }
    let mut winner: Option<u32> = None;
    for off in (0..64usize).step_by(4) {
        let matches_all = known
            .iter()
            .all(|s| read_u32(&s.struct_window, off) == Some(s.debug_id));
        if !matches_all {
            continue;
        }
        if winner.is_some() {
            bail!("ambiguous debug_id offset (multiple candidates)");
        }
        winner = Some(off as u32);
    }
    winner.ok_or_else(|| anyhow::anyhow!("could not determine debug_id offset"))
}

pub fn solve(samples: &[Sample]) -> Result<DerivedOffsets> {
    if samples.is_empty() {
        bail!("no calibration samples");
    }
    let debug_id_off = find_debug_id_offset(samples)?;

    let known: HashMap<u64, u32> = samples
        .iter()
        .filter(|s| s.debug_id != 0)
        .map(|s| (s.txn_ptr, s.debug_id))
        .collect();

    // votes[(txn_to_thread_off, thread_txn_stack_off)] = confirming replies.
    //   txn_to_thread_off:   offset of the to_thread pointer inside binder_transaction
    //   thread_txn_stack_off: offset of transaction_stack inside binder_thread
    let mut votes: HashMap<(u32, u32), usize> = HashMap::new();
    let mut replies = 0usize;
    for r in samples.iter().filter(|s| s.reply) {
        let reply_debug_id = r.debug_id;
        if reply_debug_id == 0 {
            continue;
        }
        replies += 1;
        for d in &r.derefs {
            for q in (0..d.window.len().saturating_sub(7)).step_by(8) {
                let Some(val) = read_u64(&d.window, q) else {
                    continue;
                };
                if val == r.txn_ptr {
                    continue;
                }
                // a slot pointing at a known earlier transaction (debug_id <
                // this reply's) is the transaction_stack -> in_reply_to chain.
                let Some(&debug_id) = known.get(&val) else {
                    continue;
                };
                if debug_id < reply_debug_id {
                    *votes.entry((d.src_off, q as u32)).or_insert(0) += 1;
                }
            }
        }
    }
    if replies < MIN_REPLY_CONFIRMATIONS {
        bail!(
            "insufficient reply traffic ({} replies, need {}); retry with more activity",
            replies,
            MIN_REPLY_CONFIRMATIONS
        );
    }

    let max_votes = votes.values().copied().max().unwrap_or(0);
    if max_votes < MIN_REPLY_CONFIRMATIONS {
        bail!(
            "could not anchor to_thread/transaction_stack (max {} confirmations)",
            max_votes
        );
    }
    let winners: Vec<(u32, u32)> = votes
        .iter()
        .filter(|(_, &v)| v == max_votes)
        .map(|(&k, _)| k)
        .collect();
    if winners.len() != 1 {
        bail!(
            "ambiguous to_thread/transaction_stack candidates: {:?}",
            winners
        );
    }
    let (to_thread, transaction_stack) = winners[0];

    Ok(DerivedOffsets {
        to_thread,
        transaction_stack,
        debug_id: debug_id_off,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(pairs: &[(usize, &[u8])], len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        for (off, bytes) in pairs {
            v[*off..*off + bytes.len()].copy_from_slice(bytes);
        }
        v
    }

    // Build a request sample: debug_id at off 0, a to_thread pointer at off 56,
    // and a deref window (the binder_thread) with transaction_stack at off 64.
    fn make_samples() -> Vec<Sample> {
        let mut samples = Vec::new();
        // 4 requests with debug_ids 1..=4, each with a distinct txn_ptr.
        let req_ptrs = [
            0xffff_0000_0000_1000u64,
            0xffff_0000_0000_2000,
            0xffff_0000_0000_3000,
            0xffff_0000_0000_4000,
        ];
        for (i, &tp) in req_ptrs.iter().enumerate() {
            let did = (i as u32) + 1;
            samples.push(Sample {
                txn_ptr: tp,
                reply: false,
                debug_id: did,
                struct_window: win(&[(0, &did.to_le_bytes())], STRUCT_WIN),
                derefs: vec![],
            });
        }
        // 3 replies (debug_ids 5..=7), each to_thread -> a binder_thread whose
        // transaction_stack (off 64) points at an earlier request.
        for (i, req) in req_ptrs.iter().take(3).enumerate() {
            let did = (i as u32) + 5;
            let thread_ptr = 0xffff_0000_0009_0000u64 + (i as u64) * 0x100;
            let mut thread_win = win(&[(64, &req.to_le_bytes())], DEREF_WIN);
            // a decoy kernel pointer at off 16 that points nowhere known
            thread_win[16..24].copy_from_slice(&0xffff_0000_00aa_0000u64.to_le_bytes());
            samples.push(Sample {
                txn_ptr: 0xffff_0000_000b_0000 + (i as u64) * 0x100,
                reply: true,
                debug_id: did,
                struct_window: win(
                    &[(0, &did.to_le_bytes()), (56, &thread_ptr.to_le_bytes())],
                    STRUCT_WIN,
                ),
                derefs: vec![Deref {
                    src_off: 56,
                    window: thread_win,
                }],
            });
        }
        samples
    }

    #[test]
    fn solves_planted_offsets() {
        let d = solve(&make_samples()).unwrap();
        assert_eq!(d.debug_id, 0);
        assert_eq!(d.to_thread, 56);
        assert_eq!(d.transaction_stack, 64);
        assert_eq!(
            d.to_reply_offsets_arg(),
            "to_thread=56,transaction_stack=64,debug_id=0"
        );
    }

    #[test]
    fn errors_on_insufficient_replies() {
        let mut s = make_samples();
        s.retain(|x| !x.reply); // drop all replies
        let err = solve(&s).unwrap_err().to_string();
        assert!(err.contains("insufficient reply traffic"), "got: {err}");
    }

    #[test]
    fn ignores_decoy_pointers_and_self_reference() {
        // Add a reply whose deref window also contains its own txn_ptr (must be
        // ignored) and an unknown pointer (must be ignored).
        let mut s = make_samples();
        if let Some(reply) = s.iter_mut().find(|x| x.reply) {
            let self_ptr = reply.txn_ptr;
            reply.derefs[0].window[80..88].copy_from_slice(&self_ptr.to_le_bytes());
            reply.derefs[0].window[96..104]
                .copy_from_slice(&0xffff_dead_dead_0000u64.to_le_bytes());
        }
        let d = solve(&s).unwrap();
        assert_eq!((d.to_thread, d.transaction_stack, d.debug_id), (56, 64, 0));
    }

    #[test]
    fn debug_id_located_by_value_at_nonzero_offset() {
        // Plant the known debug_id at offset 12 (not 0); the value match must
        // still find it, and a same-width decoy that doesn't equal debug_id at
        // offset 0 must not be mistaken for it.
        let mk = |did: u32| Sample {
            txn_ptr: 0xffff_0000_0000_0000 + did as u64,
            reply: false,
            debug_id: did,
            struct_window: win(
                &[(0, &0xdead_beefu32.to_le_bytes()), (12, &did.to_le_bytes())],
                STRUCT_WIN,
            ),
            derefs: vec![],
        };
        let samples = vec![mk(7), mk(8), mk(9)];
        assert_eq!(find_debug_id_offset(&samples).unwrap(), 12);
    }

    #[test]
    fn errors_on_insufficient_debug_id_samples() {
        // No sample carries a debug_id (structured tp unavailable).
        let mut s = make_samples();
        for sample in &mut s {
            sample.debug_id = 0;
        }
        let err = solve(&s).unwrap_err().to_string();
        assert!(err.contains("insufficient debug_id samples"), "got: {err}");
    }

    #[test]
    fn errors_on_ambiguous_debug_id() {
        // Mirror each sample's debug_id into offset 8 as well, so two offsets
        // (0 and 8) both match the known value.
        let mut s = make_samples();
        for sample in &mut s {
            let did = sample.debug_id.to_le_bytes();
            sample.struct_window[8..12].copy_from_slice(&did);
        }
        let err = solve(&s).unwrap_err().to_string();
        assert!(err.contains("ambiguous debug_id"), "got: {err}");
    }
}
