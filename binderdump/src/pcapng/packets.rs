use super::capture_info::CaptureInfo;
use super::event_layer::{EventProtocol, EventType, IoctlProtocol};
use super::events_aggregator::EventsAggregator;
use super::link_layer;
use crate::binder::binder_command::BinderCommand;
use crate::binder::binder_return::BinderReturn;
use crate::capture::events::BinderEventWriteRead;
use crate::capture::events::{BinderEvent, BinderEventData};
use crate::capture::process_cache;
use crate::capture::process_cache::ProcessCache;
use crate::capture::ringbuf::EventChannel;
use anyhow::{Context, Result};
use binrw::BinWrite;
use log::error;
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
use std::io::{Cursor, Write};
use std::time::Duration;
use yansi::Paint;

pub struct PacketGenerator<W: Write> {
    pcap_writer: PcapNgWriter<W>,
    process_cache: process_cache::ProcessCache,
    events_aggregator: Option<EventsAggregator>,
    timeshift: Duration,
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
                options: vec![
                    InterfaceDescriptionOption::IfName(interface.into()),
                    // seems like the pcap-file library implicitly uses nanoseconds when writing Duration to a packet block,
                    // so we tell wireshark about it
                    // this seems to be fixed pcap-file 3.0.0-rc1
                    InterfaceDescriptionOption::IfTsResol(0x9),
                ],
            };

            pcap_writer.write_pcapng_block(interface_block)?;
        }

        Ok(Self {
            pcap_writer,
            process_cache: ProcessCache::new(),
            events_aggregator: Some(EventsAggregator::new(channel)),
            timeshift: capture_info.get_timeshift().clone(),
        })
    }

    fn print_events(events: &Vec<BinderEvent>) -> Result<()> {
        for event in events {
            println!("{:?}", event);
            if let BinderEventData::BinderWriteRead(bwr) = &event.data {
                match bwr {
                    BinderEventWriteRead::BinderEventRead(_) => {
                        let brs: Vec<BinderReturn> = bwr.try_into()?;
                        for br in brs {
                            println!("{:x?}", br.blue())
                        }
                    }
                    BinderEventWriteRead::BinderEventWrite(_) => {
                        let bcs: Vec<BinderCommand> = bwr.try_into()?;
                        for bc in bcs {
                            println!("{:x?}", bc.green());
                        }
                    }
                }
            }
        }
        println!("");
        Ok(())
    }

    fn handle_invalidate_process(&mut self, event: &BinderEvent) -> Result<EventProtocol> {
        let info = self.process_cache.invalidate_proc(event.pid, event.tid);
        let mut builder = EventProtocol::builder(event.timestamp, event.pid, event.tid)
            .event_type(EventType::DeadProcess);
        if let Some(info) = info {
            builder = builder
                .cmdline(info.get_cmdline().into())
                .comm(info.get_comm().into());
        };
        builder.build()
    }

    pub fn handle_events(&mut self, events: Vec<BinderEvent>) -> Result<EventProtocol> {
        let last_event = events.last().context("empty events vector")?;
        let timestamp = last_event.timestamp;
        let pid = last_event.pid;
        let tid = last_event.tid;

        if last_event.is_invalidate_process() {
            return self.handle_invalidate_process(last_event);
        }

        let mut builder = EventProtocol::builder(timestamp, pid, tid);
        let mut ioctl_builder = IoctlProtocol::builder();
        let mut comm: Option<String> = None;

        for event in events {
            match event.data {
                BinderEventData::BinderInvalidate => break,
                BinderEventData::BinderIoctl(ioctl) => {
                    ioctl_builder = ioctl_builder.with_ioctl_event(&ioctl);
                    comm = Some(
                        ioctl
                            .comm
                            .clone()
                            .into_string()
                            .context("failed to convert comm to String")?,
                    );
                    builder = builder.event_type(EventType::SplitIoctl).comm(
                        ioctl
                            .comm
                            .into_string()
                            .context("failed to convert comm to String")?,
                    );
                }
                BinderEventData::BinderWriteRead(_) => (),
                BinderEventData::BinderIoctlDone(result) => {
                    ioctl_builder = ioctl_builder.result(result);
                    builder = builder.event_type(EventType::FinishedIoctl);
                }
                BinderEventData::BinderTransaction(_) => (),
                BinderEventData::BinderTransactionReceived(_) => (),
                BinderEventData::BinderInvalidateProcess => unreachable!(),
            }
        }

        let info = self.process_cache.get_proc(pid, tid, comm.as_deref())?;

        if let Some(comm) = comm {
            builder = builder.comm(comm);
        };

        let ioctl = ioctl_builder.build();
        if let Some(binder_type) = info.get_binder_type(ioctl.fd()) {
            builder = builder.binder_type(binder_type);
        }
        builder
            .cmdline(info.get_cmdline().into())
            .ioctl_data(ioctl)
            .build()
    }

    fn write_packet(&mut self, proto: EventProtocol, link: &[u8]) -> Result<()> {
        let mut cursor = Cursor::new(Vec::new());
        cursor.write(link)?;
        proto.write_le(&mut cursor)?;
        let data = cursor.into_inner();

        let packet = EnhancedPacketBlock {
            interface_id: proto.binder_type() as u32,
            timestamp: Duration::from_nanos(proto.timestamp()) + self.timeshift,
            original_len: data.len() as u32,
            data: data.into(),
            options: vec![],
        };
        self.pcap_writer.write_block(&packet.into_block())?;
        Ok(())
    }

    pub fn capture(&mut self) -> Result<()> {
        let link_layer = link_layer::get_pdu_header();
        let events_aggregator = self.events_aggregator.take();
        let events_aggregator = match events_aggregator {
            Some(events_aggregator) => events_aggregator,
            None => {
                return Err(anyhow::anyhow!(
                    "Tried to use PacketGenerator more than once"
                ));
            }
        };
        for events in events_aggregator {
            let proto = match self.handle_events(events) {
                Ok(proto) => proto,
                Err(err) => {
                    error!("Failed to handle events: {}", err);
                    continue;
                }
            };
            self.write_packet(proto, &link_layer)?;
        }
        Ok(())
    }
}
