use std::{
    collections::BTreeSet, env::current_dir, future::ready, net::Ipv4Addr, path::PathBuf, sync::Arc,
};

use async_fs::read_dir;
use async_lock::Semaphore;
use async_tungstenite::{WebSocketStream, tungstenite::protocol::WebSocketConfig};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, generic_array::GenericArray},
};
use clap::{Parser, Subcommand};
use futures_util::{Sink, SinkExt, Stream, TryStreamExt};
use object_rainbow::{FullHash, ParseSliceRefless, ReflessObject, SizeExt, ToOutput};
use object_rainbow_bridge::{consume, provide};
use object_rainbow_cdc::{Chunks, dirtree::FileTree};
use object_rainbow_encrypted::{Encrypted, Key, encrypt_point};
use object_rainbow_point::{IntoPoint, RawPointInner};

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
