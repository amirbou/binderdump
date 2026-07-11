use std::{
    collections::HashMap,
    sync::mpsc::RecvTimeoutError,
    time::{Duration, Instant},
};

use log::{error, warn};

use crate::capture::{
    events::{BinderEvent, BinderEventData},
    ringbuf::EventChannel,
};

pub struct EventsAggregator {
    channel: EventChannel,
    ongoing_events: HashMap<i32, OngoingEvent>,
    current_ioctl_id: u64,
    // finish the iteration if `timeout` passed without a new event (useful for testing to ensure we don't block indefinitly)
    timeout: Option<Duration>,
    // finish the iteration once this absolute instant is reached
    deadline: Option<Instant>,
}

struct OngoingEvent {
    events: Vec<BinderEvent>,
    should_split: bool,
}

impl OngoingEvent {
    fn new() -> Self {
        Self {
            events: vec![],
            should_split: false,
        }
    }

    fn new_split(event: BinderEvent) -> Self {
        Self {
            events: vec![event],
            should_split: false,
        }
    }

    fn push(&mut self, event: BinderEvent) {
        self.events.push(event)
    }

    fn insert(&mut self, event: BinderEvent) {
        self.events.insert(0, event)
    }
}

impl EventsAggregator {
    pub fn new(channel: EventChannel) -> Self {
        Self {
            channel,
            ongoing_events: HashMap::new(),
            current_ioctl_id: 0,
            timeout: None,
            deadline: None,
        }
    }

    // Stop iteration once `deadline` is reached (absolute Instant).
    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }

    fn get_event(&mut self) -> Result<BinderEvent, RecvTimeoutError> {
        let channel = self.channel.get_channel();
        let remaining = match self.deadline {
            None => None,
            Some(d) => match d.checked_duration_since(Instant::now()) {
                Some(r) if !r.is_zero() => Some(r),
                _ => return Err(RecvTimeoutError::Timeout),
            },
        };
        match (self.timeout, remaining) {
            (None, None) => channel.recv().map_err(|err| err.into()),
            (Some(t), None) => channel.recv_timeout(t),
            (None, Some(r)) => channel.recv_timeout(r),
            (Some(t), Some(r)) => channel.recv_timeout(t.min(r)),
        }
    }

    fn split_events(&mut self, tid: i32) -> Option<Vec<BinderEvent>> {
        // place a copy of the original BinderIoctl event
        let events = self.ongoing_events.remove(&tid);
        if let Some(evts) = &events {
            if !evts.events.is_empty() {
                let first_event = (*evts.events.first().unwrap()).clone();
                if let BinderEventData::BinderIoctl(_) = first_event.data {
                    let new_events = OngoingEvent::new_split(first_event);
                    self.ongoing_events.insert(tid, new_events);
                } else {
                    warn!("first event is not ioctl: {:?}", first_event);
                }
            } else {
                warn!("empty events?");
            }
        } else {
            warn!("split_events None");
        }
        events.map(|evts| evts.events)
    }

    fn handle_new_event(
        &mut self,
        mut event: BinderEvent,
    ) -> anyhow::Result<Option<Vec<BinderEvent>>> {
        let tid = event.tid;
        let events = self
            .ongoing_events
            .entry(tid)
            .or_insert_with(|| OngoingEvent::new());
        match &mut event.data {
            BinderEventData::BinderInvalidate
            | BinderEventData::BinderIoctlDone(_)
            | BinderEventData::BinderInvalidateProcess => {
                events.push(event);
                // We got everything we need to parse this ioctl / error occured
                return Ok(self.ongoing_events.remove(&tid).map(|evts| evts.events));
            }
            BinderEventData::BinderWriteRead(bwr) => {
                match bwr {
                    crate::capture::events::BinderEventWriteRead::BinderEventRead(br) => {
                        if br.get_bwr().read_size > 0 {
                            events.push(event);
                        }
                        return Ok(None);
                    }
                    crate::capture::events::BinderEventWriteRead::BinderEventWrite(bw) => {
                        // This BWR is either only write or only read, so wait for IoctlDone OR this BWR contains a transaction, so we should wait for BinderTransaction event
                        let should_split = bw.get_bwr().read_size > 0;
                        if (bw.get_bwr().write_size == 0 || bw.get_bwr().read_size == 0)
                            || bwr.is_blocking()?
                        {
                            events.should_split = should_split;
                            events.push(event);
                            return Ok(None);
                        }
                    }
                }
                events.push(event);
                return Ok(self.split_events(tid));
            }
            BinderEventData::BinderTransaction(_) => {
                // We got a transaction. if the previous BWR command contains a read_size > 0,
                // we should split the events now, otherwise we should wait for IoctlDone
                events.push(event);
                if events.should_split {
                    return Ok(self.split_events(tid));
                }
            }
            BinderEventData::BinderIoctl(ref mut ioctl) => {
                ioctl.ioctl_id = self.current_ioctl_id;
                self.current_ioctl_id += 1;
                if ioctl.read_only {
                    events.insert(event);
                } else {
                    events.push(event);
                }
            }
            _ => events.push(event),
        }

        Ok(None)
    }
}

impl Iterator for EventsAggregator {
    type Item = Vec<BinderEvent>;

    // Each iteration will produce a vector of events according to the following rules:
    // If a non-blocking ioctl was performed - a vector of all the events between (and including) BinderIoctl and BinderIoctlDone
    // If a blocking ioctl was performed (BINDER_WRITE_READ) - if only read was requested, the same as before. If write (and possibly read),
    // events between (and including) BinderIoctl and BinderWriteRead(BinderEventWriteRead::BinderEventWrite(...)), will be returned first,
    // and a copy of the first ioctl event, along with all the remaining events until BinderIoctlDone will be produced as a seperate vector.
    //
    // If a BinderInvalidate or BinderInvalidateProcess events are received, they are sent immediatly.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let event = self.get_event();
            let event = match event {
                Ok(event) => event,
                Err(RecvTimeoutError::Timeout) if self.deadline.is_some() => return None,
                Err(err) => {
                    error!("Events channel error: {}", err);
                    return None;
                }
            };
            match self.handle_new_event(event) {
                Ok(events) => match events {
                    Some(events) => return Some(events),
                    None => continue,
                },
                Err(err) => error!("error handling new event: {:#?}", err),
            }
        }
    }
}
