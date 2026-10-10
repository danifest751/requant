//! Stop requests from the operating system: SIGTERM, SIGINT and SIGHUP on Unix (systemd's stop, Ctrl-C, a
//! closed terminal), console control events on Windows (Ctrl-C, Ctrl-Break, closing the window, log-off,
//! shutdown). The handler only raises a flag; the main thread sees it, saves the node's state and exits.
//! A second signal on Unix ends the process at once, for a shutdown that hangs.

use std::sync::atomic::{AtomicBool, Ordering};

static REQUESTED: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);

/// Whether a stop was requested.
pub fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// The state is saved; the process may end (lets a waiting Windows handler return).
pub fn done() {
    DONE.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
mod sys {
    use super::REQUESTED;
    use std::sync::atomic::Ordering;

    extern "C" {
        fn signal(sig: i32, handler: usize) -> usize;
        fn _exit(code: i32) -> !;
    }

    extern "C" fn on_signal(_: i32) {
        // only async-signal-safe work here: an atomic swap, and `_exit` on a repeated signal
        if REQUESTED.swap(true, Ordering::SeqCst) {
            unsafe { _exit(130) }
        }
    }

    pub fn install() {
        // SIGHUP, SIGINT, SIGTERM (the same numbers on Linux and the BSDs)
        for sig in [1, 2, 15] {
            unsafe {
                signal(sig, on_signal as extern "C" fn(i32) as usize);
            }
        }
    }
}

#[cfg(windows)]
mod sys {
    use super::{DONE, REQUESTED};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    type Handler = unsafe extern "system" fn(u32) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<Handler>, add: i32) -> i32;
    }

    unsafe extern "system" fn on_ctrl(_: u32) -> i32 {
        REQUESTED.store(true, Ordering::SeqCst);
        // for close, log-off and shutdown events Windows ends the process when this returns: give the node
        // up to 5 s (the system's limit) to save its state
        for _ in 0..100 {
            if DONE.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        1
    }

    pub fn install() {
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
    }
}

/// Catch stop requests from now on (see the module documentation).
pub fn install() {
    sys::install();
}
