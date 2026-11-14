#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod frame;
pub mod resequencer;
pub mod url;
pub mod wireguard;

pub use error::ProtoError;
pub use frame::{
    FRAME_HEADER_LEN, FrameHeader, FrameType, FrameView, HandshakeInitPayload,
    HandshakeRespPayload, PingPayload, PongPayload, StreamFeedbackPayload, WDTT_MAGIC,
    encode_frame, flags,
};
pub use resequencer::{
    DEFAULT_GAP_TIMEOUT, DEFAULT_RESEQUENCER_CAPACITY, MAX_RECEIVER_STREAMS, ReceiverStreamState,
    ResequencerStats, WgResequencer,
};
pub use url::{SprayMode, TunnelConfig, TunnelMode};
pub use wireguard::{WgHeaderView, WgPacketType, inspect_wg_packet};
