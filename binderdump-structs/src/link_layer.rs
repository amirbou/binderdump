// Copied from wireshark/wsutil/exported_pdu_tlvs.h
const EXP_PDU_TAG_END_OF_OPT: u16 = 0;
const EXP_PDU_TAG_DISSECTOR_NAME: u16 = 12;

const EXP_PDU_TAG_END_OF_OPT_VALUE: u16 = 0;

const DISSECTOR_NAME: &'static [u8; 10] = b"binderdump";
// len should be 32 bits aligned, value will be padded with 0s
const ALIGNMENT: usize = 4;
const DISSECTOR_ALIGNED_LEN: usize = (DISSECTOR_NAME.len() + ALIGNMENT - 1) & (!(ALIGNMENT - 1));

pub fn get_pdu_header() -> [u8; 20] {
    let mut value: [u8; 20] = [0; 20];
    value[0..2].clone_from_slice(&EXP_PDU_TAG_DISSECTOR_NAME.to_be_bytes());
    value[2..4].clone_from_slice(&(DISSECTOR_ALIGNED_LEN as u16).to_be_bytes());
    value[4..4 + DISSECTOR_NAME.len()].clone_from_slice(DISSECTOR_NAME);
    value[4 + DISSECTOR_ALIGNED_LEN..4 + DISSECTOR_ALIGNED_LEN + 2]
        .clone_from_slice(&EXP_PDU_TAG_END_OF_OPT.to_be_bytes());
    value[4 + DISSECTOR_ALIGNED_LEN + 2..]
        .clone_from_slice(&EXP_PDU_TAG_END_OF_OPT_VALUE.to_be_bytes());
    value
}
