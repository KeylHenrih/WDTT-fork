#![no_main]

use libfuzzer_sys::fuzz_target;
use wdtt_proto::{FrameView, inspect_wg_packet};

fuzz_target!(|data: &[u8]| {
    let _ = FrameView::decode(data);
    let _ = inspect_wg_packet(data);
});
