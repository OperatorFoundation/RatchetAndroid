package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.madh.Curve25519PrivateKey

class RatchetUnitTests
{
    private val testBytes1 = byteArrayOf(1, 2, 3, 4, 5)
    private val testBytes2 = byteArrayOf(1, 2, 3, 4, 5)
    private val differentBytes = byteArrayOf(5, 4, 3, 2, 1)

    // PlaintextMessageType Tests
    @Test
    fun `PlaintextMessageType has correct byte values`() {
        assertEquals(0x48.toByte(), PlaintextMessageType.HANDSHAKE.value)
        assertEquals(0x52.toByte(), PlaintextMessageType.RATCHET.value)
        assertEquals(0x45.toByte(), PlaintextMessageType.ERROR.value)
        assertEquals(0x43.toByte(), PlaintextMessageType.COMPRESSED_TEXT.value)
        assertEquals(0x55.toByte(), PlaintextMessageType.UNCOMPRESSED_TEXT.value)
        assertEquals(0x44.toByte(), PlaintextMessageType.DATA.value)
    }

    @Test
    fun `PlaintextMessageType fromByte returns correct type`() {
        assertEquals(PlaintextMessageType.HANDSHAKE, PlaintextMessageType.fromByte(0x48))
        assertEquals(PlaintextMessageType.RATCHET, PlaintextMessageType.fromByte(0x52))
        assertEquals(PlaintextMessageType.ERROR, PlaintextMessageType.fromByte(0x45))
        assertEquals(PlaintextMessageType.COMPRESSED_TEXT, PlaintextMessageType.fromByte(0x43))
        assertEquals(PlaintextMessageType.UNCOMPRESSED_TEXT, PlaintextMessageType.fromByte(0x55))
        assertEquals(PlaintextMessageType.DATA, PlaintextMessageType.fromByte(0x44))
    }

    @Test
    fun `PlaintextMessageType fromByte returns null for invalid byte`() {
        assertNull(PlaintextMessageType.fromByte(0x00))
        assertNull(PlaintextMessageType.fromByte(0xFF.toByte()))
    }

    // PlaintextMessage Tests
    @Test
    fun `PlaintextMessage equality requires both type and bytes to match`() {
        val message1 = PlaintextMessage(PlaintextMessageType.HANDSHAKE, testBytes1)
        val message2 = PlaintextMessage(PlaintextMessageType.HANDSHAKE, testBytes2)
        val message3 = PlaintextMessage(PlaintextMessageType.HANDSHAKE, differentBytes)
        val message4 = PlaintextMessage(PlaintextMessageType.RATCHET, testBytes1)

        assertEquals(message1, message2)
        assertNotEquals(message1, message3) // Different bytes
        assertNotEquals(message1, message4) // Different type
    }

    @Test
    fun `PlaintextMessage hashCode combines type and bytes`() {
        val message1 = PlaintextMessage(PlaintextMessageType.HANDSHAKE, testBytes1)
        val message2 = PlaintextMessage(PlaintextMessageType.HANDSHAKE, testBytes2)

        assertEquals(message1.hashCode(), message2.hashCode())
    }

    @Test
    fun `PlaintextMessage handles UTF-8 text correctly`() {
        val originalText = "Hello 世界 🌍"
        val message = PlaintextMessage(
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            originalText.toByteArray(Charsets.UTF_8)
        )
        val decodedText = String(message.bytes, Charsets.UTF_8)

        assertEquals(originalText, decodedText)
    }

    @Test
    fun `PlaintextMessage works with empty bytes`() {
        val message = PlaintextMessage(PlaintextMessageType.ERROR, byteArrayOf())
        assertArrayEquals(byteArrayOf(), message.bytes)
    }

    // Key Wrapper Tests - Just test one as a representative
    @Test
    fun `RootKey equality uses byte array content not reference`() {
        val key1 = RootKey(testBytes1)
        val key2 = RootKey(testBytes2)
        val key3 = RootKey(differentBytes)

        assertEquals(key1, key2) // Same content, different arrays
        assertNotEquals(key1, key3)
    }

    @Test
    fun `RootKey can be used as map key`() {
        val key1 = RootKey(testBytes1)
        val key2 = RootKey(testBytes2)
        val map = mutableMapOf<RootKey, String>()

        map[key1] = "value"
        assertEquals("value", map[key2]) // key2 should retrieve the same value
    }

    @Test
    fun `different key types with same bytes are not equal`() {
        val rootKey = RootKey(testBytes1)
        val chainKey = ChainKey(testBytes1)
        val sharedKey = SharedKey(testBytes1)
        val messageKey = MessageKey(testBytes1)

        // All have same bytes but are different types
        assertNotEquals(rootKey as Any, chainKey as Any)
        assertNotEquals(rootKey as Any, sharedKey as Any)
        assertNotEquals(rootKey as Any, messageKey as Any)
        assertNotEquals(chainKey as Any, sharedKey as Any)
    }

    // RatchetState Tests
    @Test
    fun `RatchetState constructs with all required fields`() {
        val publicKey = Curve25519PublicKey(testBytes1)
        val privateKey = Curve25519PrivateKey(testBytes1)
        val keypair = Curve25519KeyPair(publicKey, privateKey)

        val state = RatchetState(
            rootKey = RootKey(testBytes1),
            chainKey = ChainKey(testBytes1),
            sharedKey = SharedKey(testBytes1),
            messageKey = MessageKey(testBytes1),
            localEphemeralKeypair = keypair,
            remoteEphemeralPublicKey = publicKey
        )

        assertNotNull(state.rootKey)
        assertNotNull(state.chainKey)
        assertNotNull(state.sharedKey)
        assertNotNull(state.messageKey)
        assertNotNull(state.localEphemeralKeypair)
        assertNotNull(state.remoteEphemeralPublicKey)
    }

    @Test
    fun `RatchetState copy creates independent instance`() {
        val publicKey = Curve25519PublicKey(testBytes1)
        val privateKey = Curve25519PrivateKey(testBytes1)
        val keypair = Curve25519KeyPair(publicKey, privateKey)

        val state1 = RatchetState(
            rootKey = RootKey(testBytes1),
            chainKey = ChainKey(testBytes1),
            sharedKey = SharedKey(testBytes1),
            messageKey = MessageKey(testBytes1),
            localEphemeralKeypair = keypair,
            remoteEphemeralPublicKey = publicKey
        )

        val state2 = state1.copy()
        assertEquals(state1, state2)

        // Modify state2
        val state3 = state2.copy(rootKey = RootKey(differentBytes))
        assertNotEquals(state1, state3)
        assertEquals(RootKey(testBytes1), state1.rootKey) // state1 unchanged
    }

    @Test
    fun `RatchetState destructuring works correctly`() {
        val publicKey = Curve25519PublicKey(testBytes1)
        val privateKey = Curve25519PrivateKey(testBytes1)
        val keypair = Curve25519KeyPair(publicKey, privateKey)

        val state = RatchetState(
            rootKey = RootKey(testBytes1),
            chainKey = ChainKey(testBytes1),
            sharedKey = SharedKey(testBytes1),
            messageKey = MessageKey(testBytes1),
            localEphemeralKeypair = keypair,
            remoteEphemeralPublicKey = publicKey
        )

        val (rootKey, chainKey, sharedKey, messageKey, localKeypair, remotePublicKey) = state

        assertEquals(state.rootKey, rootKey)
        assertEquals(state.chainKey, chainKey)
        assertEquals(state.sharedKey, sharedKey)
        assertEquals(state.messageKey, messageKey)
        assertEquals(state.localEphemeralKeypair, localKeypair)
        assertEquals(state.remoteEphemeralPublicKey, remotePublicKey)
    }
}