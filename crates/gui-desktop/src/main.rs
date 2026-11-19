//! Native lightweight desktop GUI application for WDTT.
//!
//! Opens a WebKit window that talks to the local `wdttd` daemon over its
//! Unix-domain-socket IPC endpoint (`/tmp/wdttd.ipc`). The page sends commands
//! through `window.ipc.postMessage`, the host translates them into
//! [`wdtt_ipc::IpcRequest`] values, and the daemon's reply is pushed back into
//! the page via `window.__onResult`.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wdtt_ipc::{IpcRequest, IpcResponse};
use wry::WebViewBuilder;

#[cfg(target_os = "linux")]
use {tao::platform::unix::WindowExtUnix, wry::WebViewBuilderExtUnix};

/// Default daemon IPC endpoint.
const DEFAULT_SOCKET: &str = "/tmp/wdttd.ipc";

/// Events delivered from the WebKit IPC handler to the event loop.
enum UserEvent {
    /// Raw command string posted by the page.
    Command(String),
}

/// The UI page. Kept inline so the binary is self-contained.
const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WDTT</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font: 14px/1.4 system-ui, sans-serif; background: #1b1d23; color: #e7e9ee; }
  header { padding: 14px 18px; background: #232631; border-bottom: 1px solid #333746; }
  h1 { margin: 0; font-size: 16px; font-weight: 600; letter-spacing: .02em; }
  main { padding: 18px; display: grid; gap: 14px; }
  .card { background: #232631; border: 1px solid #333746; border-radius: 10px; padding: 14px; }
  .row { display: flex; align-items: center; gap: 10px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: #8b8f9c; }
  .dot.on { background: #4ade80; box-shadow: 0 0 8px #4ade80; }
  .dot.off { background: #f87171; }
  label { display: block; font-size: 12px; opacity: .75; margin-bottom: 6px; }
  input { width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 8px;
          border: 1px solid #3a3f52; background: #1b1d23; color: inherit; font: inherit; }
  button { padding: 9px 14px; border-radius: 8px; border: 1px solid #3a3f52;
           background: #2c3040; color: inherit; font: inherit; cursor: pointer; }
  button:hover { background: #343a4d; }
  button.primary { background: #3b5bdb; border-color: #3b5bdb; }
  button.primary:hover { background: #4c6ef5; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .stat .v { font-size: 20px; font-variant-numeric: tabular-nums; }
  .stat .k { font-size: 11px; opacity: .65; text-transform: uppercase; letter-spacing: .06em; }
  .msg { min-height: 18px; font-size: 12px; color: #fbbf24; }
</style>
</head>
<body>
<header><h1>WDTT control</h1></header>
<main>
  <div class="card">
    <div class="row">
      <span class="dot" id="dot"></span>
      <strong id="state">daemon: unknown</strong>
      <span style="flex:1"></span>
      <button onclick="refresh()">Refresh</button>
    </div>
  </div>
  <div class="card stats">
    <div class="stat"><div class="v" id="tx">–</div><div class="k">tx bytes/s</div></div>
    <div class="stat"><div class="v" id="rx">–</div><div class="k">rx bytes/s</div></div>
    <div class="stat"><div class="v" id="rtt">–</div><div class="k">rtt ms</div></div>
  </div>
  <div class="card">
    <label for="uri">Call link / config URI</label>
    <input id="uri" placeholder="https://vk.ru/call/join/…">
    <div class="row" style="margin-top:12px">
      <button class="primary" onclick="connect()">Connect</button>
      <button onclick="disconnect()">Disconnect</button>
    </div>
    <div class="msg" id="msg"></div>
  </div>
</main>
<script>
  function post(cmd) { window.ipc.postMessage(cmd); }
  function refresh() { post("get_status"); }
  function connect() { post("connect:" + document.getElementById("uri").value.trim()); }
  function disconnect() { post("disconnect"); }

  window.__onResult = function (r) {
    const msg = document.getElementById("msg");
    if (r.kind === "status") {
      const dot = document.getElementById("dot");
      dot.className = "dot " + (r.connected ? "on" : "off");
      document.getElementById("state").textContent = "daemon: " + (r.connected ? "connected" : "down");
      document.getElementById("tx").textContent = r.tx_bytes_per_sec;
      document.getElementById("rx").textContent = r.rx_bytes_per_sec;
      document.getElementById("rtt").textContent = r.rtt_ms;
    } else if (r.kind === "ok") {
      msg.style.color = "#4ade80";
      msg.textContent = "OK";
    } else {
      msg.style.color = "#f87171";
      msg.textContent = "Error: " + r.message;
    }
  };

  setInterval(refresh, 2000);
  refresh();
</script>
</body>
</html>"##;

/// Performs a single request/response round-trip against the daemon.
fn ipc_call(socket: &str, req: &IpcRequest) -> Result<IpcResponse, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect: {e}"))?;
    let bytes = postcard::to_allocvec(req).map_err(|e| format!("encode: {e}"))?;
    stream.write_all(&bytes).map_err(|e| format!("write: {e}"))?;
    stream.shutdown(std::net::Shutdown::Write).ok();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| format!("read: {e}"))?;
    postcard::from_bytes(&buf).map_err(|e| format!("decode: {e}"))
}

/// Turns a page command into a request and a JSON payload for `__onResult`.
fn dispatch(socket: &str, command: &str) -> String {
    let (req, describe): (IpcRequest, fn(IpcResponse) -> String) =
        if let Some(uri) = command.strip_prefix("connect:") {
            (
                IpcRequest::Connect {
                    config_uri: uri.to_string(),
                },
                describe_default,
            )
        } else if command == "disconnect" {
            (IpcRequest::Disconnect, describe_default)
        } else {
            (IpcRequest::GetStatus, describe_status)
        };

    match ipc_call(socket, &req) {
        Ok(resp) => describe(resp),
        Err(e) => serde_json::json!({ "kind": "error", "message": e }).to_string(),
    }
}

/// Renders an [`IpcResponse`] as the JSON shape the page expects.
fn describe_default(resp: IpcResponse) -> String {
    match resp {
        IpcResponse::Ok => serde_json::json!({ "kind": "ok" }).to_string(),
        IpcResponse::Error(message) => {
            serde_json::json!({ "kind": "error", "message": message }).to_string()
        }
        other => describe_status(other),
    }
}

/// Renders tunnel status for the dashboard.
fn describe_status(resp: IpcResponse) -> String {
    match resp {
        IpcResponse::Status {
            connected,
            tx_bytes_per_sec,
            rx_bytes_per_sec,
            rtt_ms,
        } => serde_json::json!({
            "kind": "status",
            "connected": connected,
            "tx_bytes_per_sec": tx_bytes_per_sec,
            "rx_bytes_per_sec": rx_bytes_per_sec,
            "rtt_ms": rtt_ms,
        })
        .to_string(),
        other => describe_default(other),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let socket = args
        .iter()
        .position(|a| a == "--socket")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    tracing::info!("wdtt-gui initializing (daemon socket: {socket})");

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("WDTT")
        .with_inner_size(tao::dpi::LogicalSize::new(520.0, 560.0))
        .build(&event_loop)?;

    let builder = WebViewBuilder::new()
        .with_html(INDEX_HTML)
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let _ = proxy.send_event(UserEvent::Command(req.body().clone()));
        });

    #[cfg(target_os = "linux")]
    let webview = {
        let vbox = window
            .default_vbox()
            .expect("GTK default_vbox not available on window");
        builder.build_gtk(vbox)?
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::UserEvent(UserEvent::Command(command)) => {
                let payload = dispatch(&socket, &command);
                let js = format!("window.__onResult({payload});");
                if let Err(e) = webview.evaluate_script(&js) {
                    tracing::warn!("evaluate_script failed: {e}");
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}
