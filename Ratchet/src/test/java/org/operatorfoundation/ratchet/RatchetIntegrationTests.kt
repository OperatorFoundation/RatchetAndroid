package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.madh.MADH

class RatchetIntegrationTest
{

    @Test
    fun `newRatchetState creates valid initial state`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        val state = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        assertNotNull(state.rootKey)
        assertNotNull(state.chainKey)
        assertNotNull(state.sharedKey)
        assertNotNull(state.messageKey)
        assertNotNull(state.localEphemeralKeypair)
        assertNotNull(state.remoteEphemeralPublicKey)
    }

    @Test
    fun `both parties derive same initial root key`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        val aliceState = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        val bobState = ratchet.newRatchetState(
            localLongtermPrivateKey = bobKeypair.privateKey,
            remoteLongtermPublicKey = aliceKeypair.publicKey
        )

        assertEquals(aliceState.rootKey, bobState.rootKey)
    }

    @Test
    fun `ratchetWithNewKey performs DH ratchet step`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        val initialState = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        val newLocalKeypair = madh.generateKeypair()
        val newRemotePublicKey = madh.generateKeypair().publicKey

        val newState = ratchet.ratchetWithNewKey(
            oldState = initialState,
            newLocalEphemeralKeypair = newLocalKeypair,
            newRemoteEphemeralPublicKey = newRemotePublicKey
        )

        // All keys should be updated after DH ratchet
        assertNotEquals(initialState.rootKey, newState.rootKey)
        assertNotEquals(initialState.chainKey, newState.chainKey)
        assertNotEquals(initialState.messageKey, newState.messageKey)
        assertNotEquals(initialState.sharedKey, newState.sharedKey)

        // Ephemeral keys should be the new ones
        assertEquals(newLocalKeypair, newState.localEphemeralKeypair)
        assertEquals(newRemotePublicKey, newState.remoteEphemeralPublicKey)
    }

    @Test
    fun `ratchetWithoutNewKey performs symmetric ratchet step`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        val initialState = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        val newState = ratchet.ratchetWithoutNewKey(initialState)

        // Chain and message keys should change (symmetric ratchet)
        assertNotEquals(initialState.chainKey, newState.chainKey)
        assertNotEquals(initialState.messageKey, newState.messageKey)

        // Root key, shared key, and ephemeral keys should remain unchanged
        assertEquals(initialState.rootKey, newState.rootKey)
        assertEquals(initialState.sharedKey, newState.sharedKey)
        assertEquals(initialState.localEphemeralKeypair, newState.localEphemeralKeypair)
        assertEquals(initialState.remoteEphemeralPublicKey, newState.remoteEphemeralPublicKey)
    }

    @Test
    fun `encrypt and decrypt round trip preserves message`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        val state = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        val originalMessage = PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = "Hello, World!".toByteArray()
        )

        val ciphertext = ratchet.encrypt(state.messageKey, originalMessage)
        val decryptedMessage = ratchet.decrypt(state.messageKey, ciphertext)

        assertEquals(originalMessage.type, decryptedMessage.type)
        assertArrayEquals(originalMessage.bytes, decryptedMessage.bytes)
    }

    @Test
    fun `multiple messages can be sent with symmetric ratcheting`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        var state = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        val messages = listOf("First", "Second", "Third")

        for (messageText in messages) {
            val plaintext = PlaintextMessage(
                PlaintextMessageType.UNCOMPRESSED_TEXT,
                messageText.toByteArray()
            )

            val ciphertext = ratchet.encrypt(state.messageKey, plaintext)
            val decrypted = ratchet.decrypt(state.messageKey, ciphertext)

            assertArrayEquals(plaintext.bytes, decrypted.bytes)

            // Advance ratchet for next message
            state = ratchet.ratchetWithoutNewKey(state)
        }
    }

    @Test
    fun `Alice and Bob can exchange messages bidirectionally`() {
        val madh = MADH()
        // Alice and Bob generate long-term keys
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        // Both initialize their ratchet states
        val ratchet = Ratchet()
        var aliceState = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        var bobState = ratchet.newRatchetState(
            localLongtermPrivateKey = bobKeypair.privateKey,
            remoteLongtermPublicKey = aliceKeypair.publicKey
        )

        // Alice sends a message to Bob
        val aliceMessage = PlaintextMessage(
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            "Hello Bob".toByteArray()
        )
        val aliceCiphertext = ratchet.encrypt(aliceState.messageKey, aliceMessage)

        // Bob decrypts
        val bobDecrypted = ratchet.decrypt(bobState.messageKey, aliceCiphertext)
        assertArrayEquals(aliceMessage.bytes, bobDecrypted.bytes)

        // Both advance their ratchets
        aliceState = ratchet.ratchetWithoutNewKey(aliceState)
        bobState = ratchet.ratchetWithoutNewKey(bobState)

        // Bob replies
        val bobMessage = PlaintextMessage(
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            "Hello Alice".toByteArray()
        )
        val bobCiphertext = ratchet.encrypt(bobState.messageKey, bobMessage)

        // Alice decrypts
        val aliceDecrypted = ratchet.decrypt(aliceState.messageKey, bobCiphertext)
        assertArrayEquals(bobMessage.bytes, aliceDecrypted.bytes)
    }

    @Test
    fun `DH ratchet provides forward secrecy`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        val state1 = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        // Perform DH ratchet with new ephemeral keys
        val newLocalKeypair = madh.generateKeypair()
        val newRemotePublicKey = madh.generateKeypair().publicKey

        val state2 = ratchet.ratchetWithNewKey(
            oldState = state1,
            newLocalEphemeralKeypair = newLocalKeypair,
            newRemoteEphemeralPublicKey = newRemotePublicKey
        )

        // All keys should be completely different (forward secrecy)
        assertNotEquals(state1.rootKey, state2.rootKey)
        assertNotEquals(state1.chainKey, state2.chainKey)
        assertNotEquals(state1.messageKey, state2.messageKey)
        assertNotEquals(state1.sharedKey, state2.sharedKey)
    }

    @Test
    fun `same plaintext with different keys produces different ciphertexts`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        var state = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        val message = PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = "Same message".toByteArray()
        )

        val ciphertext1 = ratchet.encrypt(state.messageKey, message)

        // Advance ratchet to get new message key
        state = ratchet.ratchetWithoutNewKey(state)

        val ciphertext2 = ratchet.encrypt(state.messageKey, message)

        // Same plaintext with different keys should produce different ciphertexts
        assertFalse(ciphertext1.encrypted.contentEquals(ciphertext2.encrypted))
    }

    @Test
    fun `different message types can be encrypted and decrypted`() {
        val madh = MADH()
        val aliceKeypair = madh.generateKeypair()
        val bobKeypair = madh.generateKeypair()

        val ratchet = Ratchet()
        val state = ratchet.newRatchetState(
            localLongtermPrivateKey = aliceKeypair.privateKey,
            remoteLongtermPublicKey = bobKeypair.publicKey
        )

        val messageTypes = listOf(
            PlaintextMessageType.HANDSHAKE,
            PlaintextMessageType.RATCHET,
            PlaintextMessageType.ERROR,
            PlaintextMessageType.COMPRESSED_TEXT,
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            PlaintextMessageType.DATA
        )

        for (messageType in messageTypes) {
            val message = PlaintextMessage(messageType, "test".toByteArray())
            val ciphertext = ratchet.encrypt(state.messageKey, message)
            val decrypted = ratchet.decrypt(state.messageKey, ciphertext)

            assertEquals(messageType, decrypted.type)
        }
    }
}