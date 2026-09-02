use std::{
    collections::BTreeSet, env::current_dir, future::ready, net::Ipv4Addr, path::PathBuf, sync::Arc,
};

use async_executor::{Executor, Task};
use async_fs::read_dir;
use async_lock::Semaphore;
use async_tungstenite::{WebSocketStream, tungstenite::protocol::WebSocketConfig};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, generic_array::GenericArray},
};
use clap::{Parser, Subcommand};
use crossterm::event::{self, KeyCode};
use futures_util::{Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use genawaiter_try_stream::try_stream;
use object_rainbow::{
    FullHash, ParseSliceRefless, ReflessObject, Singular, SizeExt, ToOutput, zero_terminated::Zt,
};
use object_rainbow_bridge::{consume, provide};
use object_rainbow_cdc::{Chunks, dirtree::FileTree};
use object_rainbow_dirtree::DirEntry;
use object_rainbow_encrypted::{Encrypted, Key, encrypt_point};
use object_rainbow_point::{IntoPoint, Point, RawPointInner};
use ratatui::{
    style::Modifier,
    widgets::{List, ListState},
};

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    ChunkHashes { path: PathBuf },
    MeasureDup,
    ChunksHash { path: PathBuf },
    BeaconRecv { path: PathBuf },
    BeaconSend { to: Ipv4Addr, path: PathBuf },
    BeaconBrowse { path: PathBuf },
}

fn ws_config() -> Option<WebSocketConfig> {
    Some(
        WebSocketConfig::default()
            .max_message_size(Some(100_000_000))
            .max_frame_size(Some(100_000_000)),
    )
}

fn split<In: ReflessObject, Out: ReflessObject>(
    stream: WebSocketStream<async_net::TcpStream>,
) -> (
    impl Sink<Out, Error = object_rainbow::Error>,
    impl Stream<Item = object_rainbow::Result<In>>,
) {
    let (send, recv) = stream.split();
    let send = send
        .sink_map_err(object_rainbow::Error::fetch)
        .with(|msg: Out| core::future::ready(Ok::<_, object_rainbow::Error>(msg.vec().into())));
    let recv = recv
        .map_err(object_rainbow::Error::fetch)
        .try_filter(|msg| core::future::ready(msg.is_binary()))
        .map_ok(|msg| msg.into_data())
        .and_then(|msg| core::future::ready(In::parse_slice_refless(&msg)));
    (send, recv)
}

fn main() -> object_rainbow::Result<()> {
    async_io::block_on(async {
        dotenvy::dotenv().ok();
        let Args { cmd } = Args::parse();
        match cmd {
            Cmd::ChunkHashes { path } => {
                let chunks = Chunks::from_file(path).await?;
                chunks
                    .as_stream()
                    .map_ok(|data| data.data_hash())
                    .try_for_each(|hash| {
                        println!("{hash}");
                        ready(Ok(()))
                    })
                    .await?;
            }
            Cmd::MeasureDup => {
                let hashes = read_dir(current_dir()?)
                    .await?
                    .map_err(object_rainbow::Error::from)
                    .try_filter_map(async |entry| {
                        if entry.file_type().await?.is_file() {
                            let chunks = Chunks::from_file(entry.path()).await?;
                            Ok(Some(chunks))
                        } else {
                            Ok(None)
                        }
                    })
                    .map_ok(|chunks| chunks.into_stream())
                    .try_flatten()
                    .map_ok(|data| (data.data_hash(), data.len()))
                    .try_collect::<Vec<_>>()
                    .await?;
                println!(
                    "total : {} ({})",
                    hashes.len(),
                    hashes.iter().map(|(_, len)| len).sum::<usize>(),
                );
                let hashes = hashes.into_iter().collect::<BTreeSet<_>>();
                println!(
                    "unique: {} ({})",
                    hashes.len(),
                    hashes.iter().map(|(_, len)| len).sum::<usize>(),
                );
            }
            Cmd::ChunksHash { path } => {
                let chunks = Chunks::from_file(path).await?;
                println!("{}", chunks.full_hash());
            }
            Cmd::BeaconRecv { path } => {
                let password = dialoguer::Password::new()
                    .with_prompt("password")
                    .interact()
                    .map_err(object_rainbow::Error::operation)?;
                let listener = async_net::TcpListener::bind("0.0.0.0:11426").await?;
                let (stream, _) = listener.accept().await?;
                let stream = async_tungstenite::accept_async_with_config(stream, ws_config())
                    .await
                    .map_err(object_rainbow::Error::fetch)?;
                let (send, recv) = split(stream);
                let lock = Semaphore::new(1);
                consume(send, recv)
                    .try_for_each_concurrent(None, |(chunks, _)| {
                        let path = path.clone();
                        let point = RawPointInner::from_singular(chunks)
                            .cast::<Encrypted<ChaCha, FileTree>, _>(ChaCha(From::from(
                                password.data_hash().to_array(),
                            )))
                            .into_point();
                        let acquire = lock.acquire();
                        async move {
                            let _guard = acquire.await;
                            Chunks::write_tree(path, point.fetch().await?.into_inner()).await?;
                            Ok(())
                        }
                    })
                    .await?;
            }
            Cmd::BeaconSend { to, path } => {
                let password = dialoguer::Password::new()
                    .with_prompt("password")
                    .interact()
                    .map_err(object_rainbow::Error::operation)?;
                let to = format!("{to}:11426");
                let stream = async_net::TcpStream::connect(to.as_str()).await?;
                let (stream, _) = async_tungstenite::client_async_with_config(
                    format!("ws://{to}"),
                    stream,
                    ws_config(),
                )
                .await
                .map_err(object_rainbow::Error::fetch)?;
                let (send, recv) = split(stream);
                provide(
                    send,
                    recv,
                    futures_util::stream::once(core::future::ready(Ok((
                        Arc::new(
                            encrypt_point::<_, FileTree>(
                                ChaCha(From::from(password.data_hash().to_array())),
                                Chunks::read_tree(path).await?.point(),
                            )
                            .await?,
                        ) as _,
                        Vec::new(),
                    )))),
                )
                .await?;
            }
            Cmd::BeaconBrowse { path } => {
                struct Notify;
                enum BrowseEvent {
                    Crossterm(crossterm::event::Event),
                    Chunks(Arc<dyn Singular>),
                    Notify(Notify),
                }
                enum BrowseFrame {
                    Pending {
                        done: Task<object_rainbow::Result<BrowseFrame>>,
                    },
                    File {
                        chunks: Chunks,
                        len: usize,
                    },
                    Directory {
                        children: Vec<(Zt<String>, Arc<FileTree>)>,
                        state: ListState,
                    },
                }
                impl BrowseFrame {
                    fn into_entry(self) -> Option<FileTree> {
                        match self {
                            Self::Pending { .. } => None,
                            Self::File { chunks, .. } => Some(DirEntry::File(chunks.point())),
                            Self::Directory { children, .. } => Some(DirEntry::Directory {
                                children: children.into_iter().collect(),
                                directory: (),
                            }),
                        }
                    }
                }
                struct NotifyGuard {
                    send: flume::WeakSender<Notify>,
                }
                impl Drop for NotifyGuard {
                    fn drop(&mut self) {
                        if let Some(send) = self.send.upgrade() {
                            send.try_send(Notify).ok();
                        }
                    }
                }
                let path = &*path;
                let password = dialoguer::Password::new()
                    .with_prompt("password")
                    .interact()
                    .map_err(object_rainbow::Error::operation)?;
                let mut consume = try_stream(async move |co| {
                    let listener = async_net::TcpListener::bind("0.0.0.0:11426").await?;
                    let (stream, _) = listener.accept().await?;
                    let stream = async_tungstenite::accept_async_with_config(stream, ws_config())
                        .await
                        .map_err(object_rainbow::Error::fetch)?;
                    let (send, recv) = split(stream);
                    consume(send, recv)
                        .try_for_each(async |item| {
                            co.yield_(item).await;
                            Ok(())
                        })
                        .await
                })
                .fuse();
                let executor = Executor::new();
                let (send_notify, recv_notify) = flume::unbounded();
                let ng = || NotifyGuard {
                    send: send_notify.downgrade(),
                };
                ratatui::run(|terminal| {
                    async_io::block_on(executor.run(async {
                        let stream = event::EventStream::new()
                            .map_err(object_rainbow::Error::from)
                            .map_ok(BrowseEvent::Crossterm);
                        let stream = futures_util::stream::select(
                            stream,
                            recv_notify.into_stream().map(BrowseEvent::Notify).map(Ok),
                        );
                        let mut stream = futures_util::stream::select(
                            stream,
                            (&mut consume)
                                .map_ok(|(chunks, _)| BrowseEvent::Chunks(Arc::new(chunks))),
                        );
                        let mut frames = Vec::<BrowseFrame>::new();
                        let mut segments = Vec::<Zt<String>>::new();
                        let mut needs_close = false;
                        let mut save_task: Option<Task<object_rainbow::Result<()>>> = None;
                        loop {
                            if let Some(BrowseFrame::Pending { done, .. }) = frames.last_mut()
                                && done.is_finished()
                                && let Some(BrowseFrame::Pending { done, .. }) = frames.pop()
                            {
                                frames.push(done.await?);
                            }
                            if let Some(task) = &save_task
                                && task.is_finished()
                                && let Some(task) = save_task
                            {
                                task.await?;
                                break;
                            }
                            terminal.draw(|frame| {
                                if save_task.is_some() {
                                    frame.render_widget("saving...", frame.area());
                                } else if let Some(state) = frames.last_mut() {
                                    match state {
                                        BrowseFrame::Pending { .. } => {
                                            frame.render_widget("loading...", frame.area());
                                        }
                                        BrowseFrame::File { len, .. } => {
                                            frame.render_widget(
                                                format!("this is a file ({len} bytes)"),
                                                frame.area(),
                                            );
                                        }
                                        BrowseFrame::Directory { children, state } => {
                                            let children = children
                                                .iter()
                                                .map(|(segment, dir)| {
                                                    (dir.is_file(), segment.to_string())
                                                })
                                                .map(|(is_file, segment)| {
                                                    format!(
                                                        "{segment}{}",
                                                        if is_file { "" } else { "/" },
                                                    )
                                                });
                                            frame.render_stateful_widget(
                                                List::new(children)
                                                    .highlight_style(Modifier::REVERSED),
                                                frame.area(),
                                                state,
                                            );
                                        }
                                    }
                                } else {
                                    frame.render_widget("nothing available", frame.area());
                                }
                            })?;
                            let tree_to_frame = async |tree: FileTree| {
                                Ok::<_, object_rainbow::Error>(match tree {
                                    DirEntry::File(chunks) => {
                                        let chunks = chunks.fetch().await?;
                                        let len = chunks.len()?;
                                        BrowseFrame::File { chunks, len }
                                    }
                                    DirEntry::Directory {
                                        children,
                                        directory: (),
                                    } => {
                                        let mut children = children.collect::<Vec<_>>().await?;
                                        children.sort_by_key(|x| x.1.is_file());
                                        BrowseFrame::Directory {
                                            children,
                                            state: ListState::default().with_selected(Some(0)),
                                        }
                                    }
                                })
                            };
                            match stream.try_next().await? {
                                Some(BrowseEvent::Chunks(chunks)) => {
                                    needs_close = true;
                                    frames.clear();
                                    segments.clear();
                                    let point: Point<Encrypted<ChaCha, FileTree>> =
                                        RawPointInner::from_singular(chunks)
                                            .cast(ChaCha(From::from(
                                                password.data_hash().to_array(),
                                            )))
                                            .into_point();
                                    let done = executor.spawn({
                                        let guard = ng();
                                        async move {
                                            let _guard = guard;
                                            tree_to_frame(point.fetch().await?.into_inner()).await
                                        }
                                    });
                                    frames.push(BrowseFrame::Pending { done });
                                }
                                Some(BrowseEvent::Notify(_)) => {}
                                Some(BrowseEvent::Crossterm(e))
                                    if let Some(e) = e.as_key_press_event() =>
                                {
                                    if e.code == KeyCode::Esc || e.code == KeyCode::Char('c') {
                                        break;
                                    }
                                    if e.code == KeyCode::Char('w')
                                        && frames.len() == 1
                                        && let Some(frame) = frames.last()
                                        && matches!(
                                            frame,
                                            BrowseFrame::File { .. }
                                                | BrowseFrame::Directory { .. },
                                        )
                                        && let Some(frame) = frames.pop()
                                        && let Some(tree) = frame.into_entry()
                                    {
                                        let guard = ng();
                                        save_task = Some(executor.spawn(async move {
                                            let _guard = guard;
                                            Chunks::write_tree(path, tree).await
                                        }));
                                    }
                                    if e.code == KeyCode::Left
                                        && frames.len() > 1
                                        && let Some(frame) = frames.pop()
                                        && let Some(segment) = segments.pop()
                                        && let Some(new) = frame.into_entry()
                                        && let Some(BrowseFrame::Directory { children, .. }) =
                                            frames.last_mut()
                                        && let Some((_, old)) =
                                            children.iter_mut().find(|x| x.0 == segment)
                                    {
                                        *old = new.into();
                                    }
                                    if let Some(BrowseFrame::Directory { children, state }) =
                                        frames.last_mut()
                                    {
                                        let selected = state.selected_mut().get_or_insert_default();
                                        if e.code == KeyCode::Up {
                                            *selected = (*selected).saturating_sub(1);
                                        }
                                        if e.code == KeyCode::Down {
                                            *selected = (*selected).saturating_add(1);
                                        }
                                        if e.code == KeyCode::Delete && *selected < children.len() {
                                            children.remove(*selected);
                                        }
                                        if e.code == KeyCode::Right
                                            && let Some((segment, child)) = children.get(*selected)
                                        {
                                            let done = executor.spawn({
                                                let guard = ng();
                                                let child = (**child).clone();
                                                async move {
                                                    let _guard = guard;
                                                    tree_to_frame(child).await
                                                }
                                            });
                                            segments.push(segment.clone());
                                            frames.push(BrowseFrame::Pending { done });
                                        }
                                    }
                                }
                                Some(BrowseEvent::Crossterm(_)) => {}
                                None => {
                                    break;
                                }
                            }
                        }
                        drop(frames);
                        if needs_close {
                            consume
                                .try_for_each(|_| core::future::ready(Ok(())))
                                .await?;
                        }
                        Ok::<_, object_rainbow::Error>(())
                    }))
                })?;
            }
        }
        Ok(())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChaCha([u8; 32]);

impl Key for ChaCha {
    type Error = chacha20poly1305::Error;

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let cipher = {
            use chacha20poly1305::KeyInit;
            ChaCha20Poly1305::new(&self.0.into())
        };
        let nonce = &{
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize()
        };
        let nonce = &nonce.as_slice()[..12];
        let encrypted = cipher
            .encrypt(GenericArray::from_slice(nonce), data)
            .expect("we do not handle encryption errors");
        [nonce, encrypted.as_slice()].concat()
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let cipher = {
            use chacha20poly1305::KeyInit;
            ChaCha20Poly1305::new(&self.0.into())
        };
        cipher.decrypt(GenericArray::from_slice(&data[..12]), &data[12..])
    }
}
