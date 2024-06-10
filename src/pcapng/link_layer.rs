// Copied from wireshark/wsutil/exported_pdu_tlvs.h
const EXP_PDU_TAG_END_OF_OPT: u16 = 0;
const EXP_PDU_TAG_DISSECTOR_NAME: u16 = 12;

const DISSECTOR_NAME: &'static [u8; 18] = b"android_binderdump";
// len should be 32 bits aligned, value will be padded with 0s
const ALIGNMENT: usize = 4;
const DISSECTOR_ALIGNED_LEN: usize = (DISSECTOR_NAME.len() + ALIGNMENT - 1) & (!(ALIGNMENT - 1));

pub fn get_pdu_header() -> [u8; 24] {
    let mut value: [u8; 24] = [0; 24];
    value[0..2].clone_from_slice(&EXP_PDU_TAG_DISSECTOR_NAME.to_be_bytes());
    value[2..4].clone_from_slice(&(DISSECTOR_ALIGNED_LEN as u16).to_be_bytes());
    value[4..4 + DISSECTOR_NAME.len()].clone_from_slice(DISSECTOR_NAME);
    // XXX last 4 bytes are 0 so we skip them
    value
}
