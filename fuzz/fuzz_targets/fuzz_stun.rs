#![no_main]

use libfuzzer_sys::fuzz_target;
use wdtt_turn::{StunMessage, decode_channel_data, is_channel_data};

fuzz_target!(|data: &[u8]| {
    let _ = StunMessage::decode(data);
    if is_channel_data(data) {
        let _ = decode_channel_data(data);
    }
});
