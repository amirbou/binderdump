#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    Bc,
    Br,
}

// the distinct event kinds that can appear in the Info column. a BWR ioctl
// carries the rich transaction/command info; everything else is a one-liner.
pub enum ColEvent<'a> {
    DeadProcess,
    DeadThread,
    // a non-BWR ioctl. we only capture the command and its return value, not
    // the payload behind the arg pointer, so that's all we can show.
    Ioctl { name: &'a str, result: i32 },
    Bwr(BwrInputs<'a>),
}

pub struct BwrInputs<'a> {
    pub is_reply: bool,
    pub iface: Option<&'a str>,
    pub method: Option<&'a str>,
    pub code: u32,
    pub raw_commands: &'a [&'a str],
    pub has_transaction: bool,
    pub is_oneway: bool,
    /// Interface-agnostic built-in transaction (PING/DUMP/INTERFACE/...). These
    /// resolve a name but inherit whatever interface the target binder fd had
    /// (None, "", or the "<query>" placeholder), so the name is shown alone.
    pub is_special: bool,
}

pub fn format(event: &ColEvent) -> String {
    match event {
        ColEvent::DeadProcess => "process died".to_string(),
        ColEvent::DeadThread => "thread died".to_string(),
        ColEvent::Ioctl { name, result } if *result < 0 => {
            format!("{} (failed: {})", name, result)
        }
        ColEvent::Ioctl { name, .. } => name.to_string(),
        ColEvent::Bwr(bwr) => format_bwr(bwr),
    }
}

fn format_bwr(inputs: &BwrInputs) -> String {
    if !inputs.has_transaction {
        return inputs.raw_commands.join(", ");
    }
    if inputs.is_reply {
        return "\u{2190} reply".to_string();
    }
    let arrow = match (inputs.is_special, inputs.method, inputs.iface) {
        // Interface-agnostic special transactions: show the name alone,
        // whatever interface (if any) the target binder fd carried.
        (true, Some(method), _) => format!("\u{2192} {}", method),
        (_, Some(method), Some(iface)) => format!("\u{2192} {}.{}()", iface, method),
        (_, Some(method), None) => format!("\u{2192} {}", method),
        (_, None, Some(iface)) => format!("\u{2192} {}::{}", iface, inputs.code),
        (_, None, None) => format!("\u{2192} <unknown interface>::{}", inputs.code),
    };
    if inputs.is_oneway {
        format!("{} (oneway)", arrow)
    } else {
        arrow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base<'a>(raw: &'a [&'a str]) -> BwrInputs<'a> {
        BwrInputs {
            is_reply: false,
            iface: None,
            method: None,
            code: 0,
            raw_commands: raw,
            has_transaction: false,
            is_oneway: false,
            is_special: false,
        }
    }

    #[test]
    fn non_txn_single_command() {
        let raw = ["BC_FREE_BUFFER"];
        assert_eq!(format(&ColEvent::Bwr(base(&raw))), "BC_FREE_BUFFER");
    }

    #[test]
    fn non_txn_multiple_commands() {
        let raw = ["BC_INCREFS", "BC_ACQUIRE"];
        assert_eq!(format(&ColEvent::Bwr(base(&raw))), "BC_INCREFS, BC_ACQUIRE");
    }

    #[test]
    fn non_txn_empty_commands() {
        let raw: [&str; 0] = [];
        assert_eq!(format(&ColEvent::Bwr(base(&raw))), "");
    }

    #[test]
    fn dead_process_marker() {
        assert_eq!(format(&ColEvent::DeadProcess), "process died");
    }

    #[test]
    fn dead_thread_marker() {
        assert_eq!(format(&ColEvent::DeadThread), "thread died");
    }

    #[test]
    fn ioctl_success_shows_bare_name() {
        let event = ColEvent::Ioctl {
            name: "BINDER_VERSION",
            result: 0,
        };
        assert_eq!(format(&event), "BINDER_VERSION");
    }

    #[test]
    fn ioctl_error_appends_result() {
        let event = ColEvent::Ioctl {
            name: "BINDER_SET_MAX_THREADS",
            result: -22,
        };
        assert_eq!(format(&event), "BINDER_SET_MAX_THREADS (failed: -22)");
    }

    fn txn<'a>(
        is_reply: bool,
        iface: Option<&'a str>,
        method: Option<&'a str>,
        code: u32,
    ) -> BwrInputs<'a> {
        BwrInputs {
            is_reply,
            iface,
            method,
            code,
            raw_commands: &[],
            has_transaction: true,
            is_oneway: false,
            is_special: false,
        }
    }

    #[test]
    fn txn_resolved_iface_and_method() {
        let inputs = txn(false, Some("IServiceManager"), Some("checkService"), 33);
        assert_eq!(
            format(&ColEvent::Bwr(inputs)),
            "\u{2192} IServiceManager.checkService()"
        );
    }

    #[test]
    fn txn_unresolved_method_falls_back_to_code() {
        let inputs = txn(false, Some("IServiceManager"), None, 33);
        assert_eq!(
            format(&ColEvent::Bwr(inputs)),
            "\u{2192} IServiceManager::33"
        );
    }

    #[test]
    fn txn_unknown_iface_falls_back_to_unknown_label() {
        let inputs = txn(false, None, None, 33);
        assert_eq!(
            format(&ColEvent::Bwr(inputs)),
            "\u{2192} <unknown interface>::33"
        );
    }

    #[test]
    fn txn_special_transaction_shows_name_regardless_of_iface() {
        // Special transactions inherit whatever interface the target binder fd
        // carried — None (PING), "" (DUMP), or "<query>" (INTERFACE). All must
        // render as the bare name, never "<iface>.NAME()" or the raw code.
        for iface in [None, Some(""), Some("<query>")] {
            let mut inputs = txn(false, iface, Some("DUMP_TRANSACTION"), 0x5f44_4d50);
            inputs.is_special = true;
            assert_eq!(
                format(&ColEvent::Bwr(inputs)),
                "\u{2192} DUMP_TRANSACTION",
                "iface = {iface:?}"
            );
        }
    }

    #[test]
    fn txn_reply_is_bare() {
        let inputs = txn(true, Some("IServiceManager"), Some("checkService"), 0);
        assert_eq!(format(&ColEvent::Bwr(inputs)), "\u{2190} reply");
    }

    #[test]
    fn txn_resolved_oneway_appends_marker() {
        let mut inputs = txn(false, Some("IFace"), Some("notify"), 5);
        inputs.is_oneway = true;
        assert_eq!(
            format(&ColEvent::Bwr(inputs)),
            "\u{2192} IFace.notify() (oneway)"
        );
    }

    #[test]
    fn txn_reply_ignores_oneway() {
        let mut inputs = txn(true, None, None, 0);
        inputs.is_oneway = true;
        assert_eq!(format(&ColEvent::Bwr(inputs)), "\u{2190} reply");
    }
}
