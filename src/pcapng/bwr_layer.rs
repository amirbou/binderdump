use binrw::binrw;

#[binrw]
pub struct BinderWriteProtocol {
    write_size: u64,
    write_consumed: u64,
    write_buffer: u64,
    read_size: u64,
    read_consumed: u64,
    read_buffer: u64,
    #[br(count = write_size)]
    buffer: Vec<u8>,
}

#[binrw]
pub struct BinderReadProtocol {
    write_size: u64,
    write_consumed: u64,
    write_buffer: u64,
    read_size: u64,
    read_consumed: u64,
    read_buffer: u64,
    #[br(count = read_consumed)]
    buffer: Vec<u8>,
}
