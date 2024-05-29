package free5gc.nas.nasType

class MaximumNumberOfSupportedPacketFilters {
    var iei: UByte = 0u
    var octet = UByteArray(2)

    @JvmName("getIeiMaximumNumberOfSupportedPacketFilters")
    fun getIei(): UByte = iei

    @JvmName("setIeiMaximumNumberOfSupportedPacketFilters")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getMaximumNumberOfSupportedPacketFilters(): UInt {
        return ((octet[0].toUInt() shl 2) + ((octet[1].toUInt() and getBitMask(8, 2)) shr 6))
    }

    fun setMaximumNumberOfSupportedPacketFilters(maximumNumberOfSupportedPacketFilters: UInt) {
        octet[0] = ((maximumNumberOfSupportedPacketFilters shr 2) and 255u).toUByte()
        octet[1] = ((octet[1] and getBitMask(6, 6).toUByte()) + ((maximumNumberOfSupportedPacketFilters and 3u) shl 6).toUByte()).toUByte()
    }

    companion object {
        fun getBitMask(startPos: Int, endPos: Int): UInt {
            var mask = 0u
            for (i in startPos downTo endPos) {
                mask = mask or (1u shl i)
            }
            return mask
        }

        fun newMaximumNumberOfSupportedPacketFilters(iei: UByte): MaximumNumberOfSupportedPacketFilters {
            val maximumNumberOfSupportedPacketFilters = MaximumNumberOfSupportedPacketFilters()
            maximumNumberOfSupportedPacketFilters.setIei(iei)
            return maximumNumberOfSupportedPacketFilters
        }
    }
}
