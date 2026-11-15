#![no_main]

use libfuzzer_sys::fuzz_target;
use wdtt_proto::TunnelConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(cfg) = TunnelConfig::parse(s)
    {
        let _ = format!("{cfg:?}");
        let _ = format!("{cfg}");
        let _ = cfg.to_wdtt2_url();
    }
});
