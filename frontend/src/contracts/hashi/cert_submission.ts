/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { type Transaction } from "@mysten/sui/transactions";
import {
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
export interface SubmitDkgCertArguments {
  hashi: RawTransactionArgument<string>;
  epoch: RawTransactionArgument<number | bigint>;
  dealer: RawTransactionArgument<string>;
  messagesHash: RawTransactionArgument<number[]>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface SubmitDkgCertOptions {
  package?: string;
  arguments:
    | SubmitDkgCertArguments
    | [
        hashi: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        dealer: RawTransactionArgument<string>,
        messagesHash: RawTransactionArgument<number[]>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function submitDkgCert(options: SubmitDkgCertOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "u64",
    "address",
    "vector<u8>",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = [
    "hashi",
    "epoch",
    "dealer",
    "messagesHash",
    "signature",
    "signersBitmap",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "cert_submission",
      function: "submit_dkg_cert",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface SubmitRotationCertArguments {
  hashi: RawTransactionArgument<string>;
  epoch: RawTransactionArgument<number | bigint>;
  dealer: RawTransactionArgument<string>;
  messagesHash: RawTransactionArgument<number[]>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface SubmitRotationCertOptions {
  package?: string;
  arguments:
    | SubmitRotationCertArguments
    | [
        hashi: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        dealer: RawTransactionArgument<string>,
        messagesHash: RawTransactionArgument<number[]>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function submitRotationCert(options: SubmitRotationCertOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "u64",
    "address",
    "vector<u8>",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = [
    "hashi",
    "epoch",
    "dealer",
    "messagesHash",
    "signature",
    "signersBitmap",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "cert_submission",
      function: "submit_rotation_cert",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface SubmitNonceCertArguments {
  hashi: RawTransactionArgument<string>;
  epoch: RawTransactionArgument<number | bigint>;
  batchIndex: RawTransactionArgument<number>;
  dealer: RawTransactionArgument<string>;
  messagesHash: RawTransactionArgument<number[]>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface SubmitNonceCertOptions {
  package?: string;
  arguments:
    | SubmitNonceCertArguments
    | [
        hashi: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        batchIndex: RawTransactionArgument<number>,
        dealer: RawTransactionArgument<string>,
        messagesHash: RawTransactionArgument<number[]>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function submitNonceCert(options: SubmitNonceCertOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "u64",
    "u32",
    "address",
    "vector<u8>",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = [
    "hashi",
    "epoch",
    "batchIndex",
    "dealer",
    "messagesHash",
    "signature",
    "signersBitmap",
  ];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "cert_submission",
      function: "submit_nonce_cert",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface DestroyAllCertsArguments {
  hashi: RawTransactionArgument<string>;
  epoch: RawTransactionArgument<number | bigint>;
  batchIndex: RawTransactionArgument<number | null>;
}
export interface DestroyAllCertsOptions {
  package?: string;
  arguments:
    | DestroyAllCertsArguments
    | [
        hashi: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        batchIndex: RawTransactionArgument<number | null>,
      ];
}
export function destroyAllCerts(options: DestroyAllCertsOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "u64", "0x1::option::Option<u32>"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["hashi", "epoch", "batchIndex"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "cert_submission",
      function: "destroy_all_certs",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
