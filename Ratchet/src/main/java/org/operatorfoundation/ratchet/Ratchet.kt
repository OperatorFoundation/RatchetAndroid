package org.operatorfoundation.ratchet

import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey

/**
 * Main API for the Double Ratchet algorithm.
 *
 * The Double Ratchet provides forward secrecy and break-in recovery for
 * asynchronous messaging by combining a Diffie-Hellman ratchet with a
 * symmetric key ratchet.
 */
object Ratchet
{
    /**
     * Creates a new ratchet state from long-term keys.
     * This initializes the double ratchet algorithm.
     *
     * @param localLongtermPrivateKey The local party's long-term private key
     * @param remoteLongtermPublicKey The remote party's long-term public key
     * @return The initial ratchet state
     */
    fun newRatchetState(
        localLongtermPrivateKey: Curve25519PrivateKey,
        remoteLongtermPublicKey: Curve25519PublicKey): RatchetState
    {
        TODO("Implementation pending")
    }

    /**
     * Advances the ratchet with new ephemeral keys (DH ratchet step).
     * This should be called when receiving a message with a new public key.
     *
     * @param oldState The current ratchet state
     * @param newLocalEphemeralKeypair New local ephemeral key pair
     * @param newRemoteEphemeralPublicKey New remote ephemeral public key
     * @return The updated ratchet state
     */
    fun ratchetWithNewKey(
        oldState: RatchetState,
        newLocalEphemeralKeypair: Curve25519KeyPair,
        newRemoteEphemeralPublicKey: Curve25519PublicKey
    ): RatchetState
    {
        TODO("Implementation pending")
    }

    /**
     * Advances the ratchet without new keys (symmetric ratchet step).
     * This should be called when sending/receiving multiple messages
     * without a key change.
     *
     * @param oldState The current ratchet state
     * @return The updated ratchet state with new chain and message keys
     */
    fun ratchetWithoutNewKey(oldState: RatchetState): RatchetState
    {
        TODO("Implementation pending")
    }

    /**
     * Encrypts a plaintext message using the message key.
     * Uses AES-GCM for authenticated encryption.
     *
     * @param key The message key to use for encryption
     * @param plaintext The plaintext message to encrypt
     * @return The ciphertext
     */
    fun encrypt(key: MessageKey, plaintext: PlaintextMessage): Ciphertext
    {
        TODO("Implementation pending")
    }

    /**
     * Decrypts a ciphertext message using the message key.
     * Uses AES-GCM for authenticated decryption.
     *
     * @param key The message key to use for decryption
     * @param ciphertext The ciphertext to decrypt
     * @return The decrypted plaintext message
     */
    fun decrypt(key: MessageKey, ciphertext: Ciphertext): PlaintextMessage
    {
        TODO("Implementation pending")
    }
}