use near_chain_configs::Genesis;
use near_client::ProcessTxResponse;
use near_crypto::{InMemorySigner, Signer};
use near_parameters::ExtCosts;
use near_primitives::test_utils::encode;
use near_primitives::transaction::{
    Action, ExecutionMetadata, FunctionCallAction, Transaction, TransactionV0,
};
use near_primitives::version::ProtocolFeature;
use near_primitives_core::hash::CryptoHash;
use near_primitives_core::types::Gas;

use crate::env::nightshade_setup::TestEnvNightshadeSetupExt;
use crate::env::test_env::TestEnv;
use crate::utils::process_blocks::deploy_test_contract_with_protocol_version;

/// Check that after flat storage upgrade:
/// - value read from contract is the same;
/// - touching trie node cost for read decreases to zero.
#[test]
fn test_flat_storage_upgrade() {
    // The immediate protocol upgrade needs to be set for this test to pass in
    // the release branch where the protocol upgrade date is set.
    unsafe { std::env::set_var("NEAR_TESTS_PROTOCOL_UPGRADE_OVERRIDE", "now") };

    let mut genesis = Genesis::test(vec!["test0".parse().unwrap(), "test1".parse().unwrap()], 1);
    let epoch_length = 12;
    let new_protocol_version = ProtocolFeature::FlatStorageReads.protocol_version();
    let old_protocol_version = new_protocol_version - 1;
    genesis.config.epoch_length = epoch_length;
    genesis.config.protocol_version = old_protocol_version;
    let runtime_config = near_parameters::RuntimeConfigStore::new(None);
    let mut env = TestEnv::builder(&genesis.config)
        .nightshade_runtimes_with_runtime_config_store(&genesis, vec![runtime_config])
        .build();

    // We assume that it is enough to process 4 blocks to get a single txn included and processed.
    // At the same time, once we process `>= 2 * epoch_length` blocks, protocol can get
    // auto-upgraded to latest version. We use this value to process 3 transactions for older
    // protocol version. So we choose this value to be `epoch_length / 3` and we process only
    // `epoch_length` blocks in total.
    // TODO (#8703): resolve this properly
    let blocks_to_process_txn = epoch_length / 3;

    // Deploy contract to state.
    deploy_test_contract_with_protocol_version(
        &mut env,
        "test0".parse().unwrap(),
        near_test_contracts::backwards_compatible_rs_contract(),
        blocks_to_process_txn,
        1,
        old_protocol_version,
    );

    let signer: Signer = InMemorySigner::test_signer(&"test0".parse().unwrap());
    let gas = 20_000_000_000_000;
    let tx = TransactionV0 {
        signer_id: "test0".parse().unwrap(),
        receiver_id: "test0".parse().unwrap(),
        public_key: signer.public_key(),
        actions: vec![],
        nonce: 0,
        block_hash: CryptoHash::default(),
    };

    // Write key-value pair to state.
    {
        let write_value_action = vec![Action::FunctionCall(Box::new(FunctionCallAction {
            args: encode(&[1u64, 10u64]),
            method_name: "write_key_value".to_string(),
            gas,
            deposit: 0,
        }))];
        let tip = env.clients[0].chain.head().unwrap();
        let signed_transaction = Transaction::V0(TransactionV0 {
            nonce: 10,
            block_hash: tip.last_block_hash,
            actions: write_value_action,
            ..tx.clone()
        })
        .sign(&signer);
        let tx_hash = signed_transaction.get_hash();
        assert_eq!(
            env.tx_request_handlers[0].process_tx(signed_transaction, false, false),
            ProcessTxResponse::ValidTx
        );
        for i in 0..blocks_to_process_txn {
            env.produce_block(0, tip.height + i + 1);
        }

        env.clients[0].chain.get_final_transaction_result(&tx_hash).unwrap().assert_success();
    }

    let touching_trie_node_costs: Vec<_> = (0..2)
        .map(|i| {
            let read_value_action = vec![Action::FunctionCall(Box::new(FunctionCallAction {
                args: encode(&[1u64]),
                method_name: "read_value".to_string(),
                gas,
                deposit: 0,
            }))];
            let tip = env.clients[0].chain.head().unwrap();
            let signed_transaction = Transaction::V0(TransactionV0 {
                nonce: 20 + i,
                block_hash: tip.last_block_hash,
                actions: read_value_action,
                ..tx.clone()
            })
            .sign(&signer);
            let tx_hash = signed_transaction.get_hash();
            assert_eq!(
                env.tx_request_handlers[0].process_tx(signed_transaction, false, false),
                ProcessTxResponse::ValidTx
            );
            for i in 0..blocks_to_process_txn {
                env.produce_block(0, tip.height + i + 1);
            }
            if i == 0 {
                env.upgrade_protocol_to_latest_version();
            }

            let final_transaction_result =
                env.clients[0].chain.get_final_transaction_result(&tx_hash).unwrap();
            final_transaction_result.assert_success();
            let receipt_id = final_transaction_result.receipts_outcome[0].id;
            let metadata = env.clients[0]
                .chain
                .get_execution_outcome(&receipt_id)
                .unwrap()
                .outcome_with_id
                .outcome
                .metadata;
            if let ExecutionMetadata::V3(profile_data) = metadata {
                profile_data.get_ext_cost(ExtCosts::touching_trie_node)
            } else {
                panic!("Too old version of metadata: {metadata:?}");
            }
        })
        .collect();

    // Guaranteed touching trie node cost in all protocol versions until
    // `ProtocolFeature::FlatStorageReads`, included.
    let touching_trie_node_base_cost: Gas = 16_101_955_926;

    // For the first read, cost should be 3 TTNs because trie path is:
    // (Branch) -> (Extension) -> (Leaf) -> (Value)
    // but due to a bug in storage_read we don't charge for Value.
    assert_eq!(touching_trie_node_costs[0], touching_trie_node_base_cost * 3);

    // For the second read, we don't go to Flat storage and don't charge TTN.
    assert_eq!(touching_trie_node_costs[1], 0);
}
