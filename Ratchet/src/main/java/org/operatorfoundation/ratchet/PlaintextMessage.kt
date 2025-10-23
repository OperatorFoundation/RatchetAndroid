package org.operatorfoundation.ratchet

data class PlaintextMessage(val type: PlaintextMessageType, val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PlaintextMessage) return false
        if (type != other.type) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        // Use prime multiplier for better hash distribution when combining fields
        val HASH_PRIME = 31
        var result = type.hashCode()
        result = HASH_PRIME * result + bytes.contentHashCode()
        return result
    }
}
