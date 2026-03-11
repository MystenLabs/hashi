/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/** Module: validator */

import {
  MoveStruct,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import { type Transaction } from "@mysten/sui/transactions";
const $moduleName = "@local-pkg/hashi::validator";
export const ValidatorRegistered = new MoveStruct({
  name: `${$moduleName}::ValidatorRegistered`,
  fields: {
    validator: bcs.Address,
  },
});
export const ValidatorUpdated = new MoveStruct({
  name: `${$moduleName}::ValidatorUpdated`,
  fields: {
    validator: bcs.Address,
  },
});
export interface RegisterArguments {
  self: RawTransactionArgument<string>;
}
export interface RegisterOptions {
  package?: string;
  arguments: RegisterArguments | [self: RawTransactionArgument<string>];
}
export function register(options: RegisterOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "0x3::sui_system::SuiSystemState"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["self"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "validator",
      function: "register",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface UpdateNextEpochPublicKeyArguments {
  self: RawTransactionArgument<string>;
  validator: RawTransactionArgument<string>;
  nextEpochPublicKey: RawTransactionArgument<number[]>;
  proofOfPossessionSignature: RawTransactionArgument<number[]>;
}
export interface UpdateNextEpochPublicKeyOptions {
  package?: string;
  arguments:
    | UpdateNextEpochPublicKeyArguments
    | [
        self: RawTransactionArgument<string>,
        validator: RawTransactionArgument<string>,
        nextEpochPublicKey: RawTransactionArgument<number[]>,
        proofOfPossessionSignature: RawTransactionArgument<number[]>,
      ];
}
export function updateNextEpochPublicKey(
  options: UpdateNextEpochPublicKeyOptions,
) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "address",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = [
    "self",
    "validator",
    "nextEpochPublicKey",
    "proofOfPossessionSignature",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "validator",
      function: "update_next_epoch_public_key",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface UpdateOperatorAddressArguments {
  self: RawTransactionArgument<string>;
  validator: RawTransactionArgument<string>;
  operator: RawTransactionArgument<string>;
}
export interface UpdateOperatorAddressOptions {
  package?: string;
  arguments:
    | UpdateOperatorAddressArguments
    | [
        self: RawTransactionArgument<string>,
        validator: RawTransactionArgument<string>,
        operator: RawTransactionArgument<string>,
      ];
}
export function updateOperatorAddress(options: UpdateOperatorAddressOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", "address"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["self", "validator", "operator"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "validator",
      function: "update_operator_address",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface UpdateEndpointUrlArguments {
  self: RawTransactionArgument<string>;
  validator: RawTransactionArgument<string>;
  endpointUrl: RawTransactionArgument<string>;
}
export interface UpdateEndpointUrlOptions {
  package?: string;
  arguments:
    | UpdateEndpointUrlArguments
    | [
        self: RawTransactionArgument<string>,
        validator: RawTransactionArgument<string>,
        endpointUrl: RawTransactionArgument<string>,
      ];
}
export function updateEndpointUrl(options: UpdateEndpointUrlOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", "0x1::string::String"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["self", "validator", "endpointUrl"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "validator",
      function: "update_endpoint_url",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface UpdateTlsPublicKeyArguments {
  self: RawTransactionArgument<string>;
  validator: RawTransactionArgument<string>;
  tlsPublicKey: RawTransactionArgument<number[]>;
}
export interface UpdateTlsPublicKeyOptions {
  package?: string;
  arguments:
    | UpdateTlsPublicKeyArguments
    | [
        self: RawTransactionArgument<string>,
        validator: RawTransactionArgument<string>,
        tlsPublicKey: RawTransactionArgument<number[]>,
      ];
}
export function updateTlsPublicKey(options: UpdateTlsPublicKeyOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", "vector<u8>"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["self", "validator", "tlsPublicKey"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "validator",
      function: "update_tls_public_key",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface UpdateNextEpochEncryptionPublicKeyArguments {
  self: RawTransactionArgument<string>;
  validator: RawTransactionArgument<string>;
  nextEpochEncryptionPublicKey: RawTransactionArgument<number[]>;
}
export interface UpdateNextEpochEncryptionPublicKeyOptions {
  package?: string;
  arguments:
    | UpdateNextEpochEncryptionPublicKeyArguments
    | [
        self: RawTransactionArgument<string>,
        validator: RawTransactionArgument<string>,
        nextEpochEncryptionPublicKey: RawTransactionArgument<number[]>,
      ];
}
export function updateNextEpochEncryptionPublicKey(
  options: UpdateNextEpochEncryptionPublicKeyOptions,
) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", "vector<u8>"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["self", "validator", "nextEpochEncryptionPublicKey"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "validator",
      function: "update_next_epoch_encryption_public_key",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
