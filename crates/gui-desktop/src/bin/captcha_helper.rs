//! Standalone WebKit-based Captcha Helper for WDTT.
//!
//! Opens the native VK Captcha challenge in a WebKit WebView window,
//! listens for IPC messages from injected fetch/XHR hook or navigation containing success_token,
//! prints the token to stdout, and exits.

use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use url::Url;
use wry::WebViewBuilder;

#[cfg(target_os = "linux")]
use {
    tao::platform::unix::WindowExtUnix,
    webkit2gtk::{URIRequestExt, URIResponseExt, WebResourceExt, WebViewExt},
    wry::WebViewBuilderExtUnix,
    wry::WebViewExtUnix,
};

const INJECTED_HOOK_JS: &str = r#"
(function() {
    function reportSuccess(token) {
        if (token && window.ipc) {
            window.ipc.postMessage("SUCCESS_TOKEN:" + token);
        }
    }

    // 1. Listen for postMessage from VK ID (window.parent.postMessage / sendGetResultEvent)
    window.addEventListener('message', function(event) {
        try {
            const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
            if (data) {
                if (data.params && data.params.token) {
                    reportSuccess(data.params.token);
                } else if (data.token) {
                    reportSuccess(data.token);
                } else if (data.success_token) {
                    reportSuccess(data.success_token);
                }
            }
        } catch(e) {}
    });

    // 2. Global error reporter so we can see any JS errors in stderr
    window.addEventListener('error', function(e) {
        if (window.ipc) {
            window.ipc.postMessage("JS_ERR:" + e.message + " (" + e.filename + ":" + e.lineno + ")");
        }
    });

    // 3. Proper fetch wrapper (ALWAYS use window as receiver!)
    if (typeof window.fetch === 'function') {
        const origFetch = window.fetch;
        window.fetch = function() {
            const args = arguments;
            const url = args[0] || '';
            return origFetch.apply(window, args).then(function(response) {
                try {
                    if (typeof url === 'string' && (url.includes('captcha') || url.includes('check'))) {
                        response.clone().json().then(function(data) {
                            if (data && data.success_token) {
                                reportSuccess(data.success_token);
                            } else if (data && data.response && data.response.success_token) {
                                reportSuccess(data.response.success_token);
                            }
                        }).catch(function() {});
                    }
                } catch(e) {}
                return response;
            });
        };
    }
})();
"#;

fn sanitize_url(raw: &str) -> String {
    if let Ok(mut parsed) = Url::parse(raw) {
        parsed.set_query(None);
        parsed.set_fragment(None);
        parsed.to_string()
    } else {
        "url".to_string()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let target_url = match args
        .iter()
        .position(|a| a == "--url")
        .and_then(|i| args.get(i + 1))
    {
        Some(u) => u.clone(),
        None => {
            eprintln!("Usage: wdtt-captcha-helper --url <VK_CAPTCHA_URL> [--devtools]");
            std::process::exit(1);
        }
    };

    let enable_devtools = args.iter().any(|a| a == "--devtools");

    #[cfg(target_os = "linux")]
    {
        if let Some(backend) = args
            .iter()
            .position(|a| a == "--backend")
            .and_then(|i| args.get(i + 1))
        {
            unsafe {
                std::env::set_var("GDK_BACKEND", backend);
            }
        }
        if args.iter().any(|a| a == "--disable-dmabuf") {
            unsafe {
                std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            }
        }
        if args.iter().any(|a| a == "--disable-compositing") {
            unsafe {
                std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
            }
        }
    }

    eprintln!("[wdtt-captcha-helper] Opening WebKit window for captcha resolution...");
    eprintln!(
        "[wdtt-captcha-helper] Target URL: {} (devtools: {})",
        sanitize_url(&target_url),
        enable_devtools
    );
    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "[wdtt-captcha-helper] Env GDK_BACKEND: {:?}",
            std::env::var("GDK_BACKEND").ok()
        );
        eprintln!(
            "[wdtt-captcha-helper] Env WEBKIT_DISABLE_DMABUF_RENDERER: {:?}",
            std::env::var("WEBKIT_DISABLE_DMABUF_RENDERER").ok()
        );
        eprintln!(
            "[wdtt-captcha-helper] Env WEBKIT_DISABLE_COMPOSITING_MODE: {:?}",
            std::env::var("WEBKIT_DISABLE_COMPOSITING_MODE").ok()
        );
    }

    let event_loop = EventLoopBuilder::new().build();
    let window = WindowBuilder::new()
        .with_title("WDTT - VK Captcha Resolution")
        .with_inner_size(tao::dpi::LogicalSize::new(560.0, 720.0))
        .build(&event_loop)?;

    let builder = WebViewBuilder::new()
        .with_url(&target_url)
        .with_devtools(enable_devtools)
        .with_initialization_script(INJECTED_HOOK_JS)
        .with_on_page_load_handler(move |event, url| {
            let sanitized = sanitize_url(&url);
            match event {
                wry::PageLoadEvent::Started => {
                    eprintln!("[wdtt-captcha-helper] Page load event: Started (url: {sanitized})");
                }
                wry::PageLoadEvent::Finished => {
                    eprintln!("[wdtt-captcha-helper] Page load event: Finished (url: {sanitized})");
                }
            }
        })
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let msg = req.body();
            if let Some(token) = msg.strip_prefix("SUCCESS_TOKEN:") {
                println!("SUCCESS_TOKEN:{}", token.trim());
                std::process::exit(0);
            } else if let Some(err) = msg.strip_prefix("JS_ERR:") {
                eprintln!("[WebKit Console] {err}");
            }
        })
        .with_navigation_handler(move |uri: String| {
            if let Ok(parsed) = Url::parse(&uri) {
                for (key, val) in parsed.query_pairs() {
                    if key == "success_token" || key == "token" {
                        println!("SUCCESS_TOKEN:{}", val);
                        std::process::exit(0);
                    }
                }
            }
            true
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

    #[cfg(target_os = "linux")]
    {
        let webkit = webview.webview();
        webkit.connect_load_failed(|_wv, _load_event, failing_uri, error| {
            let sanitized = sanitize_url(failing_uri);
            eprintln!(
                "[wdtt-captcha-helper] Page load FAILED: error={}, url={}",
                error, sanitized
            );
            false
        });
        webkit.connect_load_failed_with_tls_errors(|_wv, failing_uri, _cert, _errors| {
            let sanitized = sanitize_url(failing_uri);
            eprintln!(
                "[wdtt-captcha-helper] Page load FAILED with TLS errors on url={}",
                sanitized
            );
            false
        });
        webkit.connect_resource_load_started(|_wv, resource, req| {
            let res_uri = req
                .uri()
                .map(|u| sanitize_url(u.as_str()))
                .unwrap_or_default();
            resource.connect_response_notify(move |res| {
                if let Some(resp) = res.response() {
                    let status = resp.status_code();
                    eprintln!(
                        "[wdtt-captcha-helper] Resource response HTTP status: {} (url: {})",
                        status, res_uri
                    );
                }
            });
        });
    }

    if enable_devtools {
        webview.open_devtools();
    }

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {}
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
