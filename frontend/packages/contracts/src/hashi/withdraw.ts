/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/** Module: withdraw */

import {
  MoveStruct,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import { type Transaction } from "@mysten/sui/transactions";
import * as utxo from "./utxo.js";
import * as withdrawal_queue from "./withdrawal_queue.js";
const $moduleName = "@local-pkg/hashi::withdraw";
export const RequestApprovalMessage = new MoveStruct({
  name: `${$moduleName}::RequestApprovalMessage`,
  fields: {
    request_id: bcs.Address,
  },
});
export const WithdrawalCommitmentMessage = new MoveStruct({
  name: `${$moduleName}::WithdrawalCommitmentMessage`,
  fields: {
    request_ids: bcs.vector(bcs.Address),
    selected_utxos: bcs.vector(utxo.UtxoId),
    outputs: bcs.vector(withdrawal_queue.OutputUtxo),
    txid: bcs.Address,
  },
});
export const WithdrawalSignedMessage = new MoveStruct({
  name: `${$moduleName}::WithdrawalSignedMessage`,
  fields: {
    withdrawal_id: bcs.Address,
    request_ids: bcs.vector(bcs.Address),
    signatures: bcs.vector(bcs.vector(bcs.u8())),
  },
});
export const WithdrawalConfirmationMessage = new MoveStruct({
  name: `${$moduleName}::WithdrawalConfirmationMessage`,
  fields: {
    withdrawal_id: bcs.Address,
  },
});
export interface RequestWithdrawalArguments {
  hashi: RawTransactionArgument<string>;
  btc: RawTransactionArgument<string>;
  bitcoinAddress: RawTransactionArgument<number[]>;
}
export interface RequestWithdrawalOptions {
  package?: string;
  arguments:
    | RequestWithdrawalArguments
    | [
        hashi: RawTransactionArgument<string>,
        btc: RawTransactionArgument<string>,
        bitcoinAddress: RawTransactionArgument<number[]>,
      ];
}
export function requestWithdrawal(options: RequestWithdrawalOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "0x2::clock::Clock",
    null,
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = ["hashi", "btc", "bitcoinAddress"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "withdraw",
      function: "request_withdrawal",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface ApproveRequestArguments {
  hashi: RawTransactionArgument<string>;
  requestId: RawTransactionArgument<string>;
  epoch: RawTransactionArgument<number | bigint>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface ApproveRequestOptions {
  package?: string;
  arguments:
    | ApproveRequestArguments
    | [
        hashi: RawTransactionArgument<string>,
        requestId: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function approveRequest(options: ApproveRequestOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "address",
    "u64",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = [
    "hashi",
    "requestId",
    "epoch",
    "signature",
    "signersBitmap",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "withdraw",
      function: "approve_request",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface CommitWithdrawalTxArguments {
  hashi: RawTransactionArgument<string>;
  requestIds: RawTransactionArgument<string[]>;
  selectedUtxos: RawTransactionArgument<number[][]>;
  outputs: RawTransactionArgument<number[][]>;
  txid: RawTransactionArgument<string>;
  epoch: RawTransactionArgument<number | bigint>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface CommitWithdrawalTxOptions {
  package?: string;
  arguments:
    | CommitWithdrawalTxArguments
    | [
        hashi: RawTransactionArgument<string>,
        requestIds: RawTransactionArgument<string[]>,
        selectedUtxos: RawTransactionArgument<number[][]>,
        outputs: RawTransactionArgument<number[][]>,
        txid: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function commitWithdrawalTx(options: CommitWithdrawalTxOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "vector<address>",
    "vector<vector<u8>>",
    "vector<vector<u8>>",
    "address",
    "u64",
    "vector<u8>",
    "vector<u8>",
    "0x2::clock::Clock",
    "0x2::random::Random",
  ] satisfies (string | null)[];
  const parameterNames = [
    "hashi",
    "requestIds",
    "selectedUtxos",
    "outputs",
    "txid",
    "epoch",
    "signature",
    "signersBitmap",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "withdraw",
      function: "commit_withdrawal_tx",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface SignWithdrawalArguments {
  hashi: RawTransactionArgument<string>;
  withdrawalId: RawTransactionArgument<string>;
  requestIds: RawTransactionArgument<string[]>;
  signatures: RawTransactionArgument<number[][]>;
  epoch: RawTransactionArgument<number | bigint>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface SignWithdrawalOptions {
  package?: string;
  arguments:
    | SignWithdrawalArguments
    | [
        hashi: RawTransactionArgument<string>,
        withdrawalId: RawTransactionArgument<string>,
        requestIds: RawTransactionArgument<string[]>,
        signatures: RawTransactionArgument<number[][]>,
        epoch: RawTransactionArgument<number | bigint>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function signWithdrawal(options: SignWithdrawalOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "address",
    "vector<address>",
    "vector<vector<u8>>",
    "u64",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = [
    "hashi",
    "withdrawalId",
    "requestIds",
    "signatures",
    "epoch",
    "signature",
    "signersBitmap",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "withdraw",
      function: "sign_withdrawal",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface ConfirmWithdrawalArguments {
  hashi: RawTransactionArgument<string>;
  withdrawalId: RawTransactionArgument<string>;
  epoch: RawTransactionArgument<number | bigint>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface ConfirmWithdrawalOptions {
  package?: string;
  arguments:
    | ConfirmWithdrawalArguments
    | [
        hashi: RawTransactionArgument<string>,
        withdrawalId: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function confirmWithdrawal(options: ConfirmWithdrawalOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "address",
    "u64",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = [
    "hashi",
    "withdrawalId",
    "epoch",
    "signature",
    "signersBitmap",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "withdraw",
      function: "confirm_withdrawal",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface CancelWithdrawalArguments {
  hashi: RawTransactionArgument<string>;
  requestId: RawTransactionArgument<string>;
}
export interface CancelWithdrawalOptions {
  package?: string;
  arguments:
    | CancelWithdrawalArguments
    | [
        hashi: RawTransactionArgument<string>,
        requestId: RawTransactionArgument<string>,
      ];
}
export function cancelWithdrawal(options: CancelWithdrawalOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", "0x2::clock::Clock"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["hashi", "requestId"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "withdraw",
      function: "cancel_withdrawal",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface DeleteExpiredSpentUtxoArguments {
  hashi: RawTransactionArgument<string>;
  txid: RawTransactionArgument<string>;
  vout: RawTransactionArgument<number>;
}
export interface DeleteExpiredSpentUtxoOptions {
  package?: string;
  arguments:
    | DeleteExpiredSpentUtxoArguments
    | [
        hashi: RawTransactionArgument<string>,
        txid: RawTransactionArgument<string>,
        vout: RawTransactionArgument<number>,
      ];
}
export function deleteExpiredSpentUtxo(options: DeleteExpiredSpentUtxoOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", "u32"] satisfies (string | null)[];
  const parameterNames = ["hashi", "txid", "vout"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "withdraw",
      function: "delete_expired_spent_utxo",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
