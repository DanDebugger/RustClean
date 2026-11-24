//! Background jobs so scanning and cleanup never block the UI thread.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use rustclean_core::Progress;

pub struct Job<T> {
    pub progress: Arc<Progress>,
    rx: Receiver<T>,
}

pub enum Poll<T> {
    Pending,
    Done(T),
    /// The worker thread exited without a result (it panicked).
    Crashed,
}

impl<T: Send + 'static> Job<T> {
    pub fn spawn(
        name: &str,
        ctx: egui::Context,
        work: impl FnOnce(&Progress) -> T + Send + 'static,
    ) -> std::io::Result<Self> {
        let progress = Arc::new(Progress::new());
        let worker_progress = Arc::clone(&progress);
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                let result = work(&worker_progress);
                let _ = tx.send(result);
                ctx.request_repaint();
            })?;
        Ok(Self { progress, rx })
    }

    pub fn poll(&self) -> Poll<T> {
        match self.rx.try_recv() {
            Ok(v) => Poll::Done(v),
            Err(TryRecvError::Empty) => Poll::Pending,
            Err(TryRecvError::Disconnected) => Poll::Crashed,
        }
    }
}
