#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    Bc,
    Br,
}

pub struct ColInputs<'a> {
    pub is_reply: bool,
    pub iface: Option<&'a str>,
    pub method: Option<&'a str>,
    pub code: u32,
    pub raw_commands: &'a [&'a str],
    pub has_transaction: bool,
}

pub fn format(inputs: &ColInputs) -> String {
    if !inputs.has_transaction {
        return inputs.raw_commands.join(", ");
    }
    if inputs.is_reply {
        return "\u{2190} reply".to_string();
    }
    match (inputs.iface, inputs.method) {
        (Some(iface), Some(method)) => format!("\u{2192} {}.{}()", iface, method),
        (Some(iface), None) => format!("\u{2192} {}::{}", iface, inputs.code),
        (None, _) => format!("\u{2192} <unknown interface>::{}", inputs.code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base<'a>(raw: &'a [&'a str]) -> ColInputs<'a> {
        ColInputs {
            is_reply: false,
            iface: None,
            method: None,
            code: 0,
            raw_commands: raw,
            has_transaction: false,
        }
    }

    #[test]
    fn non_txn_single_command() {
        let raw = ["BC_FREE_BUFFER"];
        assert_eq!(format(&base(&raw)), "BC_FREE_BUFFER");
    }

    #[test]
    fn non_txn_multiple_commands() {
        let raw = ["BC_INCREFS", "BC_ACQUIRE"];
        assert_eq!(format(&base(&raw)), "BC_INCREFS, BC_ACQUIRE");
    }

    #[test]
    fn non_txn_empty_commands() {
        let raw: [&str; 0] = [];
        assert_eq!(format(&base(&raw)), "");
    }

    fn txn<'a>(
        is_reply: bool,
        iface: Option<&'a str>,
        method: Option<&'a str>,
        code: u32,
    ) -> ColInputs<'a> {
        ColInputs {
            is_reply,
            iface,
            method,
            code,
            raw_commands: &[],
            has_transaction: true,
        }
    }

    #[test]
    fn txn_resolved_iface_and_method() {
        let inputs = txn(false, Some("IServiceManager"), Some("checkService"), 33);
        assert_eq!(format(&inputs), "\u{2192} IServiceManager.checkService()");
    }

    #[test]
    fn txn_unresolved_method_falls_back_to_code() {
        let inputs = txn(false, Some("IServiceManager"), None, 33);
        assert_eq!(format(&inputs), "\u{2192} IServiceManager::33");
    }

    #[test]
    fn txn_unknown_iface_falls_back_to_unknown_label() {
        let inputs = txn(false, None, None, 33);
        assert_eq!(format(&inputs), "\u{2192} <unknown interface>::33");
    }

    #[test]
    fn txn_reply_is_bare() {
        let inputs = txn(true, Some("IServiceManager"), Some("checkService"), 0);
        assert_eq!(format(&inputs), "\u{2190} reply");
    }
}
