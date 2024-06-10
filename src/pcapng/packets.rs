use crate::binder;
use crate::capture;
use crate::capture::events::BinderEvent;
use crate::capture::process_cache;
use crate::capture::process_cache::ProcessCache;
use crate::capture::ringbuf::EventChannel;
use anyhow::Result;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{
    blocks::{
        section_header::{SectionHeaderBlock, SectionHeaderOption},
        PcapNgBlock,
    },
    PcapNgWriter,
};
use pcap_file::DataLink;
use std::io::Write;

use super::capture_info::CaptureInfo;

pub struct PacketGenerator<W: Write> {
    channel: EventChannel,
    pcap_writer: PcapNgWriter<W>,
    process_cache: process_cache::ProcessCache,
    incomplete_packets: (),
}

impl<W: Write> PacketGenerator<W> {
    pub fn new(channel: EventChannel, writer: W) -> Result<Self> {
        let capture_info = CaptureInfo::new()?;
        let options = vec![
            SectionHeaderOption::OS(capture_info.get_os().to_string().into()),
            SectionHeaderOption::Hardware(capture_info.get_model().to_string().into()),
            SectionHeaderOption::UserApplication(capture_info.get_capture_app().to_string().into()),
            SectionHeaderOption::Comment(capture_info.get_fingerprint().to_string().into()),
            SectionHeaderOption::Comment(capture_info.get_kernel_version().to_string().into()),
        ];

        let mut header = SectionHeaderBlock::default();
        header.options = options;

        let mut pcap_writer = PcapNgWriter::with_section_header(writer, header)?;

        for interface in ["/dev/binder", "/dev/hwbinder", "/dev/vndbinder"] {
            let interface_block = interface_description::InterfaceDescriptionBlock {
                linktype: DataLink::WIRESHARK_UPPER_PDU,
                snaplen: 0,
                options: vec![InterfaceDescriptionOption::IfName(interface.into())],
            };

            pcap_writer.write_pcapng_block(interface_block)?;
        }

        // let pcap_writer = PcapNgWriter::with
        Ok(Self {
            channel,
            pcap_writer,
            process_cache: ProcessCache::new(),
            incomplete_packets: (),
        })
    }

    fn handle_event(&mut self, event: BinderEvent) -> Result<Option<EnhancedPacketBlock>> {
        // let process_info = self.process_cache.get_proc(event.pid, event.tid, None)?;
        match event.data {
            capture::events::BinderEventData::BinderInvalidate => todo!(),
            capture::events::BinderEventData::BinderIoctl(_) => todo!(),
            capture::events::BinderEventData::BinderWriteRead(_) => todo!(),
            capture::events::BinderEventData::BinderIoctlDone(_) => todo!(),
            capture::events::BinderEventData::BinderTransaction(_) => todo!(),
            capture::events::BinderEventData::BinderTransactionReceived(_) => todo!(),
            capture::events::BinderEventData::BinderInvalidateProcess => todo!(),
        }
        todo!()
    }
}
