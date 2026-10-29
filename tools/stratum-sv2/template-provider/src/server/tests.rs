use super::*;

use crate::{EXAMPLE_PRIVATE_KEY_HEX, Network, NodeConfig, RETAINED_TEMPLATES, RuntimeInputs};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolObserver, MutationEnvelope};
use bitcoin_rs_mining::{GenerateRequest, GenerateSelection, GeneratedBlock, solve_block};
use bitcoin_rs_primitives::{
    Amount, BlockHash, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
};
use futures_executor::block_on;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use stratum_apps::{
    network_helpers::{
        connect_with_noise,
        noise_stream::{NoiseTcpReadHalf, NoiseTcpStream},
    },
    stratum_core::{
        bitcoin::{self, hashes::Hash as _},
        codec_sv2::ENCRYPTED_SV2_FRAME_HEADER_SIZE,
        common_messages_sv2::SetupConnectionOwned,
        template_distribution_sv2::{
            CoinbaseOutputConstraintsOwned, RequestTransactionDataOwned, SubmitSolutionOwned,
        },
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::JoinHandle,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(5);
const LOOSE: CoinbaseBudget = CoinbaseBudget {
    additional_size: 1000,
    additional_sigops: 1,
};

#[tokio::test]
async fn transient_accept_error_waits_before_retrying() {
    let (_stop, mut cancel) = watch::channel(false);
    for error in [
        std::io::Error::from(std::io::ErrorKind::ConnectionAborted),
        std::io::Error::other("temporary resource exhaustion"),
    ] {
        let started = Instant::now();
        wait_after_accept_error(error, &mut cancel).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(100));
    }
}

#[tokio::test]
async fn accept_error_backoff_can_be_cancelled_by_shutdown() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    let (stop, mut cancel) = watch::channel(false);
    let wait = wait_after_accept_error(
        std::io::Error::other("temporary resource exhaustion"),
        &mut cancel,
    );
    tokio::pin!(wait);
    let mut context = Context::from_waker(Waker::noop());
    assert!(wait.as_mut().poll(&mut context).is_pending());
    stop.send_replace(true);
    assert!(matches!(
        wait.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));
}

#[tokio::test]
async fn permanent_accept_error_remains_fatal() {
    let (_stop, mut cancel) = watch::channel(false);
    let result = wait_after_accept_error(
        std::io::Error::from(std::io::ErrorKind::InvalidInput),
        &mut cancel,
    )
    .await;
    assert!(result.is_err());
}

struct EmbeddedNode {
    node: Arc<Node>,
    shutdown: crossbeam_channel::Sender<()>,
    _dir: tempfile::TempDir,
}

impl EmbeddedNode {
    async fn start(observer: Option<Arc<dyn MempoolObserver>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.rpc.bind = "127.0.0.1:0".parse().unwrap();
        config.p2p.listen.clear();
        config.p2p.dns_seeds_enabled = false;
        config.storage.dbcache_mb = 16;
        config.mining.payout_script = [
            vec![0, 32],
            bitcoin::hashes::sha256::Hash::hash(&[0x51])
                .to_byte_array()
                .to_vec(),
        ]
        .concat();
        let (shutdown, rx) = crossbeam_channel::bounded(1);
        let node = tokio::task::spawn_blocking(move || {
            block_on(Node::start(
                config,
                RuntimeInputs {
                    shutdown: Some(rx),
                    mempool_observer: observer,
                },
            ))
        })
        .await
        .unwrap()
        .unwrap();
        Self {
            _dir: dir,
            node: Arc::new(node),
            shutdown,
        }
    }

    fn candidate(&self) -> Arc<Candidate> {
        let BlockTemplateResult::Template(template) = self
            .node
            .mining_control()
            .unwrap()
            .get_block_template(BlockTemplateRequest {
                mode: BlockTemplateMode::Template,
                capabilities: vec![],
                rules: vec![],
                long_poll_id: None,
                coinbase_budget: None,
            })
            .unwrap()
        else {
            panic!("template")
        };
        template.candidate
    }

    async fn mine(&self, count: u32) -> Vec<GeneratedBlock> {
        let payout = self.candidate().coinbase.outputs[0]
            .script_pubkey
            .as_bytes()
            .to_vec();
        let node = Arc::clone(&self.node);
        tokio::task::spawn_blocking(move || {
            node.mining_control().unwrap().generate(GenerateRequest {
                payout,
                count,
                max_tries: 1_000_000,
                selection: GenerateSelection::Mempool,
                submit: true,
            })
        })
        .await
        .unwrap()
        .unwrap()
    }

    async fn pool_one_spend(&self) {
        let generated = self.mine(101).await;
        let funding = self
            .node
            .block_by_hash(generated[0].hash)
            .await
            .unwrap()
            .unwrap()
            .txs[0]
            .clone();
        let spend = Tx {
            version: 2,
            lock_time: bitcoin_rs_primitives::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(funding.txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(funding.outputs[0].value.to_sat() - 2000),
                script_pubkey: funding.outputs[0].script_pubkey.clone(),
            }],
        };
        let node = Arc::clone(&self.node);
        tokio::task::spawn_blocking(move || block_on(node.broadcast(spend)))
            .await
            .unwrap()
            .unwrap();
    }

    async fn shutdown(self) {
        self.shutdown.send(()).unwrap();
        let node = Arc::try_unwrap(self.node).unwrap_or_else(|_| panic!("session retained Node"));
        tokio::task::spawn_blocking(move || block_on(node.shutdown()))
            .await
            .unwrap()
            .unwrap();
    }
}

fn key() -> Secp256k1SecretKey {
    Secp256k1SecretKey(
        secp256k1::SecretKey::from_slice(&hex::decode(EXAMPLE_PRIVATE_KEY_HEX).unwrap()).unwrap(),
    )
}

async fn start_session(
    node: Arc<Node>,
    hub: Hub,
) -> (
    std::net::SocketAddr,
    watch::Sender<bool>,
    JoinHandle<Result<(), String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let secret = key();
    let (stop, cancel) = watch::channel(false);
    let session = Session {
        hub,
        node,
        stop: cancel,
        keys: (Secp256k1PublicKey::from(secret), secret),
        cert_validity_secs: 3600,
    };
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        session.serve(stream).await
    });
    (address, stop, task)
}

async fn connect(address: std::net::SocketAddr) -> NoiseTcpStream {
    tokio::time::timeout(
        DEADLINE,
        connect_with_noise(
            TcpStream::connect(address).await.unwrap(),
            Some(Secp256k1PublicKey::from(key())),
        ),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn setup(
    reader: &mut NoiseTcpReadHalf,
    writer: &mut NoiseTcpWriteHalf,
    budget: CoinbaseBudget,
) {
    send(
        writer,
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
            protocol: Protocol::TemplateDistributionProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "localhost".try_into().unwrap(),
            endpoint_port: 0,
            vendor: "test".try_into().unwrap(),
            hardware_version: "".try_into().unwrap(),
            firmware: "".try_into().unwrap(),
            device_id: "".try_into().unwrap(),
        })),
    )
    .await
    .unwrap();
    let mut frame = tokio::time::timeout(DEADLINE, reader.read_frame())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        parse_common(&mut frame),
        Some(CommonMessagesOwned::SetupConnectionSuccess(_))
    ));
    constrain(writer, budget).await;
}

async fn constrain(writer: &mut NoiseTcpWriteHalf, budget: CoinbaseBudget) {
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(
            TemplateDistributionOwned::CoinbaseOutputConstraints(CoinbaseOutputConstraintsOwned {
                coinbase_output_max_additional_size: budget.additional_size,
                coinbase_output_max_additional_sigops: budget.additional_sigops,
            }),
        ),
    )
    .await
    .unwrap();
}

async fn receive(reader: &mut NoiseTcpReadHalf) -> TemplateDistributionOwned {
    let mut frame = tokio::time::timeout(DEADLINE, reader.read_frame())
        .await
        .unwrap()
        .unwrap();
    TemplateDistribution::try_from((frame.header().msg_type(), frame.payload()))
        .unwrap()
        .into_owned()
}

async fn receive_job(reader: &mut NoiseTcpReadHalf) -> u64 {
    let TemplateDistributionOwned::NewTemplate(template) = receive(reader).await else {
        panic!("expected NewTemplate");
    };
    assert!(
        matches!(receive(reader).await, TemplateDistributionOwned::SetNewPrevHash(t) if t.template_id == template.template_id)
    );
    template.template_id
}

async fn transaction_count(
    reader: &mut NoiseTcpReadHalf,
    writer: &mut NoiseTcpWriteHalf,
    template_id: u64,
) -> Result<usize, ()> {
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::RequestTransactionData(
            RequestTransactionDataOwned { template_id },
        )),
    )
    .await
    .unwrap();
    match receive(reader).await {
        TemplateDistributionOwned::RequestTransactionDataSuccess(success) => {
            assert_eq!(success.template_id, template_id);
            Ok(success.transaction_list.into_inner().len())
        }
        TemplateDistributionOwned::RequestTransactionDataError(error) => {
            assert_eq!(error.template_id, template_id);
            Err(())
        }
        other => panic!("unexpected reply {other:?}"),
    }
}

fn solve(job: &TemplateState) -> (SubmitSolutionOwned, BlockHash) {
    let mut block = job.candidate.into_unsolved_block().unwrap();
    solve_block(&mut block, 1_000_000).unwrap();
    let solution = SubmitSolutionOwned {
        template_id: job.id,
        version: block.header.version as u32,
        header_timestamp: block.header.time,
        header_nonce: block.header.nonce,
        coinbase_tx: consensus_bytes(&block.txs[0]).try_into().unwrap(),
    };
    (solution, block.block_hash())
}

async fn submit(writer: &mut NoiseTcpWriteHalf, solution: SubmitSolutionOwned) {
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::SubmitSolution(solution)),
    )
    .await
    .unwrap();
}

fn headroom(candidate: &Candidate) -> u32 {
    let admits = |additional_size| {
        candidate
            .admits(CoinbaseBudget {
                additional_size,
                additional_sigops: 1,
            })
            .is_ok()
    };
    let (mut fits, mut over) = (0, u32::MAX);
    assert!(admits(fits) && !admits(over));
    while over - fits > 1 {
        let middle = fits + (over - fits) / 2;
        if admits(middle) {
            fits = middle;
        } else {
            over = middle;
        }
    }
    fits
}

#[tokio::test]
async fn partial_noise_frame_survives_a_job_refresh() -> TestResult {
    let embedded = EmbeddedNode::start(None).await;
    let hub = Hub::new();
    let (address, stop, session) = start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let (arm, arm_rx) = oneshot::channel();
    let (armed, armed_rx) = oneshot::channel();
    let (partial, partial_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (client, _) = proxy_listener.accept().await.unwrap();
        let upstream = TcpStream::connect(address).await.unwrap();
        let (mut from_client, mut to_client) = client.into_split();
        let (mut from_server, mut to_server) = upstream.into_split();
        let forward = async move {
            let mut arm_rx = arm_rx;
            let mut buf = [0; 4096];
            loop {
                tokio::select! {
                    _ = &mut arm_rx => break,
                    count = from_client.read(&mut buf) => {
                        let count = count.unwrap();
                        assert_ne!(count, 0);
                        to_server.write_all(&buf[..count]).await.unwrap();
                    }
                }
            }
            armed.send(()).unwrap();
            let mut prefix = [0; ENCRYPTED_SV2_FRAME_HEADER_SIZE + 1];
            from_client.read_exact(&mut prefix).await.unwrap();
            to_server.write_all(&prefix).await.unwrap();
            partial.send(()).unwrap();
            release_rx.await.unwrap();
            tokio::io::copy(&mut from_client, &mut to_server).await
        };
        let backward = async {
            let result = tokio::io::copy(&mut from_server, &mut to_client).await;
            to_client.shutdown().await.unwrap();
            result
        };
        tokio::join!(forward, backward)
    });
    let (mut reader, mut writer) = connect(proxy_address).await.into_split();
    setup(&mut reader, &mut writer, LOOSE).await;
    let first = receive_job(&mut reader).await;
    arm.send(()).unwrap();
    tokio::time::timeout(DEADLINE, armed_rx).await??;
    send(
        &mut writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::RequestTransactionData(
            RequestTransactionDataOwned { template_id: first },
        )),
    )
    .await?;
    tokio::time::timeout(DEADLINE, partial_rx).await??;
    tokio::task::yield_now().await;
    embedded.mine(1).await;
    hub.wake();
    let second = receive_job(&mut reader).await;
    assert_ne!(second, first);
    release.send(()).unwrap();
    assert!(
        matches!(receive(&mut reader).await, TemplateDistributionOwned::RequestTransactionDataSuccess(t) if t.template_id == first)
    );
    assert_eq!(
        transaction_count(&mut reader, &mut writer, second).await,
        Ok(0)
    );
    stop.send_replace(true);
    proxy.abort();
    let _ = proxy.await;
    tokio::time::timeout(DEADLINE, session).await???;
    embedded.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn tight_budget_gets_a_fitting_job_and_budgets_stay_independent() -> TestResult {
    let embedded = EmbeddedNode::start(None).await;
    embedded.pool_one_spend().await;
    let unconstrained = embedded.candidate();
    assert_eq!(unconstrained.transactions.len(), 1);
    let tight = CoinbaseBudget {
        additional_size: headroom(&unconstrained) + 1,
        additional_sigops: 1,
    };
    assert!(unconstrained.admits(tight).is_err());
    let hub = Hub::new();
    let (address_a, stop_a, session_a) =
        start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let (address_b, stop_b, session_b) =
        start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let (mut reader_a, mut writer_a) = connect(address_a).await.into_split();
    let (mut reader_b, mut writer_b) = connect(address_b).await.into_split();
    setup(&mut reader_a, &mut writer_a, tight).await;
    setup(&mut reader_b, &mut writer_b, LOOSE).await;
    let tight_id = receive_job(&mut reader_a).await;
    let loose_id = receive_job(&mut reader_b).await;
    assert_ne!(tight_id, loose_id);
    let tight_job = hub.lookup(tight_id).unwrap();
    let loose_job = hub.lookup(loose_id).unwrap();
    assert!(tight_job.candidate.admits(tight).is_ok());
    assert!(loose_job.candidate.admits(LOOSE).is_ok());
    assert!(tight_job.candidate.transactions.is_empty());
    assert_eq!(loose_job.candidate.transactions.len(), 1);
    assert_eq!(
        transaction_count(&mut reader_a, &mut writer_a, tight_id).await,
        Ok(0)
    );
    assert_eq!(
        transaction_count(&mut reader_b, &mut writer_b, loose_id).await,
        Ok(1)
    );
    constrain(&mut writer_a, LOOSE).await;
    assert_eq!(receive_job(&mut reader_a).await, loose_id);
    assert_eq!(
        transaction_count(&mut reader_a, &mut writer_a, tight_id).await,
        Ok(0)
    );
    stop_a.send_replace(true);
    stop_b.send_replace(true);
    tokio::time::timeout(DEADLINE, session_a).await???;
    tokio::time::timeout(DEADLINE, session_b).await???;
    embedded.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn pinned_job_outlives_peer_churn_and_evicted_ids_never_substitute() -> TestResult {
    let embedded = EmbeddedNode::start(None).await;
    embedded.pool_one_spend().await;
    let edge = headroom(&embedded.candidate());
    let hub = Hub::new();
    let (address_a, stop_a, session_a) =
        start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let (address_b, stop_b, session_b) =
        start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let (mut reader_a, mut writer_a) = connect(address_a).await.into_split();
    let (mut reader_b, mut writer_b) = connect(address_b).await.into_split();
    setup(&mut reader_a, &mut writer_a, LOOSE).await;
    let pinned = receive_job(&mut reader_a).await;
    let pinned_job = hub.lookup(pinned).unwrap();
    let churn = u32::try_from(RETAINED_TEMPLATES).unwrap();
    let tight = |step: u32| CoinbaseBudget {
        additional_size: edge + step,
        additional_sigops: 1,
    };
    setup(&mut reader_b, &mut writer_b, tight(1)).await;
    let evicted = receive_job(&mut reader_b).await;
    let evicted_job = hub.lookup(evicted).unwrap();
    let mut latest = evicted;
    for step in 2..=churn + 1 {
        constrain(&mut writer_b, tight(step)).await;
        latest = receive_job(&mut reader_b).await;
    }
    assert_eq!(hub.issued.lock().unwrap().len(), RETAINED_TEMPLATES);
    assert!(hub.lookup(pinned).is_none(), "peer churn evicted the job");
    assert!(hub.lookup(evicted).is_none());
    assert_eq!(
        transaction_count(&mut reader_a, &mut writer_a, pinned).await,
        Ok(1)
    );
    assert_eq!(
        transaction_count(&mut reader_b, &mut writer_b, evicted).await,
        Err(())
    );
    let height = embedded.node.snapshot().tip_height;
    submit(&mut writer_b, solve(&evicted_job).0).await;
    assert_eq!(
        transaction_count(&mut reader_b, &mut writer_b, latest).await,
        Ok(0)
    );
    assert_eq!(embedded.node.snapshot().tip_height, height);
    let (solution, hash) = solve(&pinned_job);
    submit(&mut writer_a, solution).await;
    assert_eq!(
        transaction_count(&mut reader_a, &mut writer_a, pinned).await,
        Ok(1)
    );
    assert_eq!(embedded.node.snapshot().tip_height, height + 1);
    assert_eq!(
        embedded
            .node
            .block_by_hash(hash)
            .await?
            .unwrap()
            .block_hash(),
        hash
    );
    stop_a.send_replace(true);
    stop_b.send_replace(true);
    tokio::time::timeout(DEADLINE, session_a).await???;
    tokio::time::timeout(DEADLINE, session_b).await???;
    embedded.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn infeasible_budget_closes_only_its_session() -> TestResult {
    let embedded = EmbeddedNode::start(None).await;
    let hub = Hub::new();
    let (address_a, stop_a, session_a) =
        start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let (address_b, _stop_b, session_b) =
        start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let (mut reader_a, mut writer_a) = connect(address_a).await.into_split();
    let (mut reader_b, mut writer_b) = connect(address_b).await.into_split();
    setup(&mut reader_a, &mut writer_a, LOOSE).await;
    setup(&mut reader_b, &mut writer_b, LOOSE).await;
    let id = receive_job(&mut reader_a).await;
    assert_eq!(receive_job(&mut reader_b).await, id);
    constrain(
        &mut writer_b,
        CoinbaseBudget {
            additional_size: u32::MAX,
            additional_sigops: 0,
        },
    )
    .await;
    let closed = tokio::time::timeout(DEADLINE, session_b).await??;
    assert!(
        closed
            .as_ref()
            .is_err_and(|error| error.contains("coinbase reservation exhausts")),
        "{closed:?}"
    );
    assert!(
        tokio::time::timeout(DEADLINE, reader_b.read_frame())
            .await?
            .is_err()
    );
    assert!(!session_a.is_finished());
    assert_eq!(
        transaction_count(&mut reader_a, &mut writer_a, id).await,
        Ok(0)
    );
    stop_a.send_replace(true);
    tokio::time::timeout(DEADLINE, session_a).await???;
    embedded.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn failed_delivery_leaves_the_previous_job_pinned() {
    let secret = key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (pool, server) = tokio::join!(connect(address), async {
        let (stream, _) = listener.accept().await.unwrap();
        accept_noise_connection(stream, Secp256k1PublicKey::from(secret), secret, 3600)
            .await
            .map_err(|e| e.to_string())
            .unwrap()
    });
    let (_reader, mut writer) = server.into_split();
    let hub = Hub::new();
    let mut pin = None;
    let held = hub.issue(crate::tests::empty_candidate(1));
    push_template(&mut writer, &mut pin, Arc::clone(&held), LOOSE)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(pin.as_ref().unwrap(), &held));
    drop(pool);
    let mut delivered = held.id;
    for parent in 2..=65 {
        let job = hub.issue(crate::tests::empty_candidate(parent));
        match push_template(&mut writer, &mut pin, Arc::clone(&job), LOOSE).await {
            Ok(()) => {
                assert_eq!(pin.as_ref().unwrap().id, job.id);
                delivered = job.id;
            }
            Err(_) => {
                assert_eq!(pin.as_ref().unwrap().id, delivered);
                assert_ne!(delivered, job.id);
                return;
            }
        }
        tokio::task::yield_now().await;
    }
    panic!("writes to a vanished pool never failed");
}

struct SubmissionGate {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: crossbeam_channel::Receiver<()>,
    released: AtomicBool,
}

impl MempoolObserver for SubmissionGate {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if envelope.origin == AdmissionOrigin::Block {
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            self.released.store(
                self.release.recv_timeout(DEADLINE).is_ok(),
                Ordering::SeqCst,
            );
        }
    }
}

#[tokio::test]
async fn session_shutdown_drains_a_running_native_submission() -> TestResult {
    let (entered, entered_rx) = oneshot::channel();
    let (release, release_rx) = crossbeam_channel::bounded(1);
    let gate = Arc::new(SubmissionGate {
        entered: Mutex::new(Some(entered)),
        release: release_rx,
        released: AtomicBool::new(false),
    });
    let embedded = EmbeddedNode::start(Some(gate.clone())).await;
    embedded.pool_one_spend().await;
    let hub = Hub::new();
    let (address, stop, mut session) = start_session(Arc::clone(&embedded.node), hub.clone()).await;
    let (mut reader, mut writer) = connect(address).await.into_split();
    setup(&mut reader, &mut writer, LOOSE).await;
    let id = receive_job(&mut reader).await;
    let job = hub.lookup(id).unwrap();
    assert_eq!(job.candidate.transactions.len(), 1);
    let (solution, hash) = solve(&job);
    submit(&mut writer, solution).await;
    tokio::time::timeout(DEADLINE, entered_rx).await??;
    stop.send_replace(true);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut session)
            .await
            .is_err(),
        "session exited with its native submission still blocked"
    );
    release.send(())?;
    tokio::time::timeout(DEADLINE, session).await???;
    assert!(gate.released.load(Ordering::SeqCst));
    assert_eq!(embedded.node.snapshot().tip_height, 102);
    assert_eq!(
        embedded
            .node
            .block_by_hash(hash)
            .await?
            .unwrap()
            .block_hash(),
        hash
    );
    embedded.shutdown().await;
    Ok(())
}
