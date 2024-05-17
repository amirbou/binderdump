use log::debug;

pub fn main() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("binderdump")
            .with_max_level(log::LevelFilter::Debug)
    );
    #[cfg(not(target_os = "android"))]
    env_logger::init();
    
    debug!("Hello world");
}
