/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/** Totally Ordered Broadcast (TOB) */

import {
  MoveStruct,
  MoveEnum,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import { type Transaction } from "@mysten/sui/transactions";
import * as linked_table from "./deps/sui/linked_table.js";
import * as committee from "./committee.js";
const $moduleName = "@local-pkg/hashi::tob";
export const TobKey = new MoveStruct({
  name: `${$moduleName}::TobKey`,
  fields: {
    epoch: bcs.u64(),
    batch_index: bcs.option(bcs.u32()),
  },
});
export const ProtocolType = new MoveEnum({
  name: `${$moduleName}::ProtocolType`,
  fields: {
    Dkg: null,
    KeyRotation: null,
    NonceGeneration: null,
  },
});
export const EpochCertsV1 = new MoveStruct({
  name: `${$moduleName}::EpochCertsV1`,
  fields: {
    epoch: bcs.u64(),
    protocol_type: ProtocolType,
    /** Dealer submissions indexed by dealer address (first-submission-wins). */
    certs: linked_table.LinkedTable(bcs.Address),
  },
});
export const DealerMessagesHashV1 = new MoveStruct({
  name: `${$moduleName}::DealerMessagesHashV1`,
  fields: {
    dealer_address: bcs.Address,
    messages_hash: bcs.vector(bcs.u8()),
  },
});
export const DealerSubmissionV1 = new MoveStruct({
  name: `${$moduleName}::DealerSubmissionV1`,
  fields: {
    message: DealerMessagesHashV1,
    signature: committee.CommitteeSignature,
  },
});
export interface ProtocolTypeDkgOptions {
  package?: string;
  arguments?: [];
}
export function protocolTypeDkg(options: ProtocolTypeDkgOptions = {}) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "tob",
      function: "protocol_type_dkg",
    });
}
export interface ProtocolTypeKeyRotationOptions {
  package?: string;
  arguments?: [];
}
export function protocolTypeKeyRotation(
  options: ProtocolTypeKeyRotationOptions = {},
) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "tob",
      function: "protocol_type_key_rotation",
    });
}
export interface ProtocolTypeNonceGenerationOptions {
  package?: string;
  arguments?: [];
}
export function protocolTypeNonceGeneration(
  options: ProtocolTypeNonceGenerationOptions = {},
) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "tob",
      function: "protocol_type_nonce_generation",
    });
}
export interface TobKeyArguments {
  epoch: RawTransactionArgument<number | bigint>;
  batchIndex: RawTransactionArgument<number | null>;
}
export interface TobKeyOptions {
  package?: string;
  arguments:
    | TobKeyArguments
    | [
        epoch: RawTransactionArgument<number | bigint>,
        batchIndex: RawTransactionArgument<number | null>,
      ];
}
export function tobKey(options: TobKeyOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = ["u64", "0x1::option::Option<u32>"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["epoch", "batchIndex"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "tob",
      function: "tob_key",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface EpochArguments {
  self: RawTransactionArgument<string>;
}
export interface EpochOptions {
  package?: string;
  arguments: EpochArguments | [self: RawTransactionArgument<string>];
}
export function epoch(options: EpochOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null] satisfies (string | null)[];
  const parameterNames = ["self"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "tob",
      function: "epoch",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
