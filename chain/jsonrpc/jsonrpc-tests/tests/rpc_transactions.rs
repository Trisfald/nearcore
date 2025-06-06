use std::sync::Arc;

use actix::{Actor, System};
use futures::{FutureExt, TryFutureExt, future};
use parking_lot::Mutex;

use near_actix_test_utils::run_actix;
use near_crypto::InMemorySigner;
use near_jsonrpc::client::new_client;
use near_jsonrpc_primitives::types::transactions::{RpcTransactionStatusRequest, TransactionInfo};
use near_network::test_utils::WaitOrTimeoutActor;
use near_o11y::testonly::{init_integration_logger, init_test_logger};
use near_primitives::hash::{CryptoHash, hash};
use near_primitives::serialize::to_base64;
use near_primitives::transaction::SignedTransaction;
use near_primitives::types::BlockReference;
use near_primitives::views::{FinalExecutionStatus, TxExecutionStatus};
use near_time::Clock;

use near_jsonrpc_tests::{self as test_utils, test_with_client};

/// Test sending transaction via json rpc without waiting.
#[test]
fn test_send_tx_async() {
    init_test_logger();

    run_actix(async {
        let (_, addr, _runtime_temp_dir) =
            test_utils::start_all(Clock::real(), test_utils::NodeType::Validator);

        let client = new_client(&format!("http://{}", addr));

        let tx_hash2 = Arc::new(Mutex::new(None));
        let tx_hash2_1 = tx_hash2.clone();
        let tx_hash2_2 = tx_hash2;
        let signer_account_id = "test1".to_string();

        actix::spawn(client.block(BlockReference::latest()).then(move |res| {
            let block_hash = res.unwrap().header.hash;
            let signer = InMemorySigner::test_signer(&"test1".parse().unwrap());
            let tx = SignedTransaction::send_money(
                1,
                signer_account_id.parse().unwrap(),
                "test2".parse().unwrap(),
                &signer,
                100,
                block_hash,
            );
            let bytes = borsh::to_vec(&tx).unwrap();
            let tx_hash = tx.get_hash().to_string();
            *tx_hash2_1.lock() = Some(tx.get_hash());
            client
                .broadcast_tx_async(to_base64(&bytes))
                .map_ok(move |result| assert_eq!(tx_hash, result))
                .map(drop)
        }));
        let client1 = new_client(&format!("http://{}", addr));
        WaitOrTimeoutActor::new(
            Box::new(move |_| {
                let signer_account_id = "test1".parse().unwrap();
                if let Some(tx_hash) = *tx_hash2_2.lock() {
                    actix::spawn(
                        client1
                            .tx(RpcTransactionStatusRequest {
                                transaction_info: TransactionInfo::TransactionId {
                                    tx_hash,
                                    sender_account_id: signer_account_id,
                                },
                                wait_until: TxExecutionStatus::Executed,
                            })
                            .map_err(|err| println!("Error: {:?}", err))
                            .map_ok(|result| {
                                if let FinalExecutionStatus::SuccessValue(_) =
                                    result.final_execution_outcome.unwrap().into_outcome().status
                                {
                                    System::current().stop();
                                }
                            })
                            .map(drop),
                    );
                }
            }),
            100,
            2000,
        )
        .start();
    });
}

/// Test sending transaction and waiting for it to be committed to a block.
#[test]
fn test_send_tx_commit() {
    test_with_client!(test_utils::NodeType::Validator, client, async move {
        let block_hash = client.block(BlockReference::latest()).await.unwrap().header.hash;
        let signer = InMemorySigner::test_signer(&"test1".parse().unwrap());
        let tx = SignedTransaction::send_money(
            1,
            "test1".parse().unwrap(),
            "test2".parse().unwrap(),
            &signer,
            100,
            block_hash,
        );
        let bytes = borsh::to_vec(&tx).unwrap();
        let result = client.broadcast_tx_commit(to_base64(&bytes)).await.unwrap();
        assert_eq!(
            result.final_execution_outcome.unwrap().into_outcome().status,
            FinalExecutionStatus::SuccessValue(Vec::new())
        );
        assert!(
            [TxExecutionStatus::Executed, TxExecutionStatus::Final]
                .contains(&result.final_execution_status),
            "All the receipts should be already executed"
        );
    });
}

/// Test that expired transaction should be rejected
#[test]
fn test_expired_tx() {
    init_integration_logger();
    run_actix(async {
        let (_, addr, _runtime_tempdir) = test_utils::start_all_with_validity_period(
            Clock::real(),
            test_utils::NodeType::Validator,
            1,
            false,
        );

        let block_hash = Arc::new(Mutex::new(None));
        let block_height = Arc::new(Mutex::new(None));

        WaitOrTimeoutActor::new(
            Box::new(move |_| {
                let block_hash = block_hash.clone();
                let block_height = block_height.clone();
                let client = new_client(&format!("http://{}", addr));
                actix::spawn(client.block(BlockReference::latest()).then(move |res| {
                    let header = res.unwrap().header;
                    let hash = *block_hash.lock();
                    let height = *block_height.lock();
                    if let Some(block_hash) = hash {
                        if let Some(height) = height {
                            if header.height - height >= 2 {
                                let signer = InMemorySigner::test_signer(&"test1".parse().unwrap());
                                let tx = SignedTransaction::send_money(
                                    1,
                                    "test1".parse().unwrap(),
                                    "test2".parse().unwrap(),
                                    &signer,
                                    100,
                                    block_hash,
                                );
                                let bytes = borsh::to_vec(&tx).unwrap();
                                actix::spawn(
                                    client
                                        .broadcast_tx_commit(to_base64(&bytes))
                                        .map_err(|err| {
                                            assert_eq!(
                                                *err.data.unwrap(),
                                                serde_json::json!({"TxExecutionError": {
                                                    "InvalidTxError": "Expired"
                                                }})
                                            );
                                            System::current().stop();
                                        })
                                        .map(|_| ()),
                                );
                            }
                        }
                    } else {
                        *block_hash.lock() = Some(header.hash);
                        *block_height.lock() = Some(header.height);
                    };
                    future::ready(())
                }));
            }),
            100,
            1000,
        )
        .start();
    });
}

/// Test sending transaction based on a different fork should be rejected
#[test]
fn test_replay_protection() {
    test_with_client!(test_utils::NodeType::Validator, client, async move {
        let signer = InMemorySigner::test_signer(&"test1".parse().unwrap());
        let tx = SignedTransaction::send_money(
            1,
            "test1".parse().unwrap(),
            "test2".parse().unwrap(),
            &signer,
            100,
            hash(&[1]),
        );
        let bytes = borsh::to_vec(&tx).unwrap();
        if let Ok(_) = client.broadcast_tx_commit(to_base64(&bytes)).await {
            panic!("transaction should not succeed");
        }
    });
}

#[test]
fn test_tx_status_missing_tx() {
    test_with_client!(test_utils::NodeType::Validator, client, async move {
        let request = RpcTransactionStatusRequest {
            transaction_info: TransactionInfo::TransactionId {
                tx_hash: CryptoHash::new(),
                sender_account_id: "test1".parse().unwrap(),
            },
            wait_until: TxExecutionStatus::None,
        };
        match client.tx(request).await {
            Err(e) => {
                let s = serde_json::to_string(&e.data.unwrap()).unwrap();
                assert_eq!(s, "\"Transaction 11111111111111111111111111111111 doesn't exist\"");
            }
            Ok(_) => panic!("transaction should not succeed"),
        }
    });
}

#[test]
fn test_check_invalid_tx() {
    test_with_client!(test_utils::NodeType::Validator, client, async move {
        let signer = InMemorySigner::test_signer(&"test1".parse().unwrap());
        // invalid base hash
        let request = RpcTransactionStatusRequest {
            transaction_info: TransactionInfo::from_signed_tx(SignedTransaction::send_money(
                1,
                "test1".parse().unwrap(),
                "test2".parse().unwrap(),
                &signer,
                100,
                hash(&[1]),
            )),
            wait_until: TxExecutionStatus::None,
        };
        match client.tx(request).await {
            Err(e) => {
                let s = serde_json::to_string(&e.data.unwrap()).unwrap();
                assert_eq!(s, "{\"TxExecutionError\":{\"InvalidTxError\":\"Expired\"}}");
            }
            Ok(_) => panic!("transaction should not succeed"),
        }
    });
}
