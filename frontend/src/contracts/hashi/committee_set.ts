/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import * as bag from "./deps/sui/bag.js";
import * as group_ops from "./deps/sui/group_ops.js";
const $moduleName = "@local-pkg/hashi::committee_set";
export const CommitteeSet = new MoveStruct({
  name: `${$moduleName}::CommitteeSet`,
  fields: {
    members: bag.Bag,
    /** The current epoch. */
    epoch: bcs.u64(),
    committees: bag.Bag,
    pending_epoch_change: bcs.option(bcs.u64()),
    /** The MPC committee's threshold public key. */
    mpc_public_key: bcs.vector(bcs.u8()),
  },
});
export const MemberInfo = new MoveStruct({
  name: `${$moduleName}::MemberInfo`,
  fields: {
    /** Sui Validator Address of this node */
    validator_address: bcs.Address,
    /** Sui Address of an operations account */
    operator_address: bcs.Address,
    /**
     * bls12381 public key to be used in the next epoch.
     *
     * The public key for this node which is active in the current epoch can be found
     * in the `Committee` struct.
     *
     * This public key can be rotated but will only take effect at the beginning of the
     * next epoch.
     */
    next_epoch_public_key: group_ops.Element,
    /**
     * The HTTPS network address where the instance of the `hashi` service for this
     * validator can be reached.
     *
     * This HTTPS address can be rotated and any such updates will take effect
     * immediately.
     */
    endpoint_url: bcs.string(),
    /**
     * ed25519 public key used to verify TLS self-signed x509 certs
     *
     * This public key can be rotated and any such updates will take effect
     * immediately.
     */
    tls_public_key: bcs.vector(bcs.u8()),
    /**
     * A 32-byte ristretto255 Ristretto encryption public key (ristretto255
     * RistrettoPoint) for MPC ECIES, to be used in the next epoch.
     *
     * This public key can be rotated but will only take effect at the beginning of the
     * next epoch.
     */
    next_epoch_encryption_public_key: bcs.vector(bcs.u8()),
  },
});
