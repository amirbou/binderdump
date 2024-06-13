// will handle ringbuf polling and comsuming
use super::{events, tracepoints::binder::BinderSkel};
use anyhow::{Context, Result};
use ctrlc;
use libbpf_rs::RingBufferBuilder;
use log::{error, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

pub struct EventChannel {
    consumer_thread: Option<thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
    binder_events_channel: mpsc::Receiver<events::BinderEvent>,
}

impl EventChannel {
    pub fn get_channel(&self) -> &mpsc::Receiver<events::BinderEvent> {
        &self.binder_events_channel
    }
}

impl Drop for EventChannel {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        let thread = self.consumer_thread.take();
        if let Some(handle) = thread {
            handle.join().expect("Failed to join with events thread");
            println!("Joined with events thread");
        }
    }
}

fn handle_binder_event(sender: &mpsc::Sender<events::BinderEvent>, data: &[u8]) -> i32 {
    match data.try_into() {
        Ok(event) => match sender.send(event) {
            Ok(_) => 0,
            Err(err) => {
                error!("Failed to send ringbuffer event {}", err);
                1
            }
        },
        Err(err) => {
            warn!("Invalid event received from ring buffer: {}", err);
            0
        }
    }
}

pub fn create_events_channel(skel: &mut BinderSkel) -> Result<EventChannel> {
    let (sender, recv) = mpsc::channel();

    let mut events_buffer_builder = RingBufferBuilder::new();
    let mut maps = skel.maps_mut();
    let binder_events_buffer = maps.binder_events_buffer();
    events_buffer_builder.add(&binder_events_buffer, move |data| -> i32 {
        handle_binder_event(&sender, data)
    })?;
    let events_buffer = events_buffer_builder.build()?;

    let running = Arc::new(AtomicBool::new(true));
    let running_copy = running.clone();
    let thread = std::thread::spawn(move || {
        while running_copy.load(Ordering::Relaxed) {
            match events_buffer.poll(Duration::from_millis(10)) {
                Ok(_) => (),
                Err(err) => match err.kind() {
                    libbpf_rs::ErrorKind::Interrupted => (),
                    _ => panic!("error polling ringbuf: {}", err),
                },
            }
        }
        println!("Events thread exiting...");
    });
    let running_copy = running.clone();
    ctrlc::set_handler(move || {
        if running_copy.load(Ordering::Relaxed) {
            running_copy.store(false, Ordering::Relaxed);
            // if we get sighup, eprintln! will panic
            eprintln!("Ctrl-C received, exiting cleanly...");
        } else {
            eprintln!("Second Ctrl-C received, exiting immediately!");
            std::process::exit(1);
        }
    })
    .context("failed to set ctrlc handler")?;
    Ok(EventChannel {
        consumer_thread: Some(thread),
        running: running,
        binder_events_channel: recv,
    })
}
