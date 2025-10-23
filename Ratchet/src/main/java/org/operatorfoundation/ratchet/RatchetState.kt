package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PublicKey

/**
 * Represents the complete state of the double ratchet algorithm at a given point.
 *
 * @property rootKey The current root key
 * @property chainKey The current chain key
 * @property sharedKey The current shared key derived from ECDH
 * @property messageKey The current message key for encryption/decryption
 * @property localEphemeralKeypair The local ephemeral key pair
 * @property remoteEphemeralPublicKey The remote party's ephemeral public key
 */
data class RatchetState(
    val rootKey: RootKey,
    val chainKey: ChainKey,
    val sharedKey: SharedKey,
    val messageKey: MessageKey,
    val localEphemeralKeypair: Curve25519KeyPair,
    val remoteEphemeralPublicKey: Curve25519PublicKey
)
