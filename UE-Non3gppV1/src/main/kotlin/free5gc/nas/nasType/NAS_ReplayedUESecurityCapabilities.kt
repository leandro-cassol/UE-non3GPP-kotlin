package free5gc.nas.nasType

class ReplayedUESecurityCapabilities {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    companion object {
        fun newReplayedUESecurityCapabilities(iei: UByte): ReplayedUESecurityCapabilities {
            val replayedUESecurityCapabilities = ReplayedUESecurityCapabilities()
            replayedUESecurityCapabilities.setIei(iei)
            return replayedUESecurityCapabilities
        }

        private fun getBitMask(start: Int, end: Int): UInt {
            var mask: UInt = 0u
            for (i in start downTo end) {
                mask = mask or (1u shl i)
            }
            return mask
        }
    }

    @JvmName("getIeiReplayedUESecurityCapabilities")
    fun getIei(): UByte = iei

    @JvmName("setIeiReplayedUESecurityCapabilities")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("setLenReplayedUESecurityCapabilities")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    @JvmName("getLenReplayedUESecurityCapabilities")
    fun getLen(): UByte {
        return len
    }

/*
    fun getEA0_5G(): UInt {
        return buffer[0] and getBitMask(8, 7) shr 7
    }

    fun setEA0_5G(eA0_5G: UInt) {
        buffer[0] = (buffer[0] and 127u) + ((eA0_5G and 1u) shl 7)
    }

    fun getEA1_128_5G(): UInt {
        return buffer[0] and getBitMask(7, 6) shr 6
    }

    fun setEA1_128_5G(eA1_128_5G: UInt) {
        buffer[0] = (buffer[0] and 191u) + ((eA1_128_5G and 1u) shl 6)
    }

    fun getEA2_128_5G(): UInt {
        return buffer[0] and getBitMask(6, 5) shr 5
    }

    fun setEA2_128_5G(eA2_128_5G: UInt) {
        buffer[0] = (buffer[0] and 223u) + ((eA2_128_5G and 1u) shl 5)
    }

    fun getEA3_128_5G(): UInt {
        return buffer[0] and getBitMask(5, 4) shr 4
    }

    fun setEA3_128_5G(eA3_128_5G: UInt) {
        buffer[0] = (buffer[0] and 239u) + ((eA3_128_5G and 1u) shl 4)
    }

    fun getEA4_5G(): UInt {
        return buffer[0] and getBitMask(4, 3) shr 3
    }

    fun setEA4_5G(eA4_5G: UInt) {
        buffer[0] = (buffer[0] and 247u) + ((eA4_5G and 1u) shl 3)
    }

    fun getEA5_5G(): UInt {
        return buffer[0] and getBitMask(3, 2) shr 2
    }

    fun setEA5_5G(eA5_5G: UInt) {
        buffer[0] = (buffer[0] and 251u) + ((eA5_5G and 1u) shl 2)
    }

    fun getEA6_5G(): UInt {
        return buffer[0] and getBitMask(2, 1) shr 1
    }

    fun setEA6_5G(eA6_5G: UInt) {
        buffer[0] = (buffer[0] and 253u) + ((eA6_5G and 1u) shl 1)
    }

    fun getEA7_5G(): UInt {
        return buffer[0] and getBitMask(1, 0)
    }

    fun setEA7_5G(eA7_5G: UInt) {
        buffer[0] = (buffer[0] and 254u) + (eA7_5G and 1u)
    }

    fun getIA0_5G(): UInt {
        return buffer[1] and getBitMask(8, 7) shr 7
    }

    fun setIA0_5G(iA0_5G: UInt) {
        buffer[1] = (buffer[1] and 127u) + ((iA0_5G and 1u) shl 7)
    }

    fun getIA1_128_5G(): UInt {
        return buffer[1] and getBitMask(7, 6) shr 6
    }

    fun setIA1_128_5G(iA1_128_5G: UInt) {
        buffer[1] = (buffer[1] and 191u) + ((iA1_128_5G and 1u) shl 6)
    }

    fun getIA2_128_5G(): UInt {
        return buffer[1] and getBitMask(6, 5) shr 5
    }

    fun setIA2_128_5G(iA2_128_5G: UInt) {
        buffer[1] = (buffer[1] and 223u) + ((iA2_128_5G and 1u) shl 5)
    }

    fun getIA3_128_5G(): UInt {
        return buffer[1] and getBitMask(5, 4) shr 4
    }

    fun setIA3_128_5G(iA3_128_5G: UInt) {
        buffer[1] = (buffer[1] and 239u) + ((iA3_128_5G and 1u) shl 4)
    }

    fun getIA4_5G(): UInt {
        return buffer[1] and getBitMask(4, 3) shr 3
    }

    fun setIA4_5G(iA4_5G: UInt) {
        buffer[1] = (buffer[1] and 247u) + ((iA4_5G and 1u) shl 3)
    }

    fun getIA5_5G(): UInt {
        return buffer[1] and getBitMask(3, 2) shr 2
    }

    fun setIA5_5G(iA5_5G: UInt) {
        buffer[1] = (buffer[1] and 251u) + ((iA5_5G and 1u) shl 2)
    }

    fun getIA6_5G(): UInt {
        return buffer[1] and getBitMask(2, 1) shr 1
    }

    fun setIA6_5G(iA6_5G: UInt) {
        buffer[1] = (buffer[1] and 253u) + ((iA6_5G and 1u) shl 1)
    }

    fun getIA7_5G(): UInt {
        return buffer[1] and getBitMask(1, 0)
    }

    fun setIA7_5G(iA7_5G: UInt) {
        buffer[1] = (buffer[1] and 254u) + (iA7_5G and 1u)
    }

    fun getEEA0(): UInt {
        return buffer[2] and getBitMask(8, 7) shr 7
    }

    fun setEEA0(eEA0: UInt) {
        buffer[2] = (buffer[2] and 127u) + ((eEA0 and 1u) shl 7)
    }

    fun getEEA1_128(): UInt {
        return buffer[2] and getBitMask(7, 6) shr 6
    }

    fun setEEA1_128(eEA1_128: UInt) {
        buffer[2] = (buffer[2] and 191u) + ((eEA1_128 and 1u) shl 6)
    }

    fun getEEA2_128(): UInt {
        return buffer[2] and getBitMask(6, 5) shr 5
    }

    fun setEEA2_128(eEA2_128: UInt) {
        buffer[2] = (buffer[2] and 223u) + ((eEA2_128 and 1u) shl 5)
    }

    fun getEEA3_128(): UInt {
        return buffer[2] and getBitMask(5, 4) shr 4
    }

    fun setEEA3_128(eEA3_128: UInt) {
        buffer[2] = (buffer[2] and 239u) + ((eEA3_128 and 1u) shl 4)
    }

    fun getEEA4(): UInt {
        return buffer[2] and getBitMask(4, 3) shr 3
    }

    fun setEEA4(eEA4: UInt) {
        buffer[2] = (buffer[2] and 247u) + ((eEA4 and 1u) shl 3)
    }

    fun getEEA5(): UInt {
        return buffer[2] and getBitMask(3, 2) shr 2
    }

    fun setEEA5(eEA5: UInt) {
        buffer[2] = (buffer[2] and 251u) + ((eEA5 and 1u) shl 2)
    }

    fun getEEA6(): UInt {
        return buffer[2] and getBitMask(2, 1) shr 1
    }

    fun setEEA6(eEA6: UInt) {
        buffer[2] = (buffer[2] and 253u) + ((eEA6 and 1u) shl 1)
    }

    fun getEEA7(): UInt {
        return buffer[2] and getBitMask(1, 0)
    }

    fun setEEA7(eEA7: UInt) {
        buffer[2] = (buffer[2] and 254u) + (eEA7 and 1u)
    }

    fun getEIA0(): UInt {
        return buffer[3] and getBitMask(8, 7) shr 7
    }

    fun setEIA0(eIA0: UInt) {
        buffer[3] = (buffer[3] and 127u) + ((eIA0 and 1u) shl 7)
    }

    fun getEIA1_128(): UInt {
        return buffer[3] and getBitMask(7, 6) shr 6
    }

    fun setEIA1_128(eIA1_128: UInt) {
        buffer[3] = (buffer[3] and 191u) + ((eIA1_128 and 1u) shl 6)
    }

    fun getEIA2_128(): UInt {
        return buffer[3] and getBitMask(6, 5) shr 5
    }

    fun setEIA2_128(eIA2_128: UInt) {
        buffer[3] = (buffer[3] and 223u) + ((eIA2_128 and 1u) shl 5)
    }

    fun getEIA3_128(): UInt {
        return buffer[3] and getBitMask(5, 4) shr 4
    }

    fun setEIA3_128(eIA3_128: UInt) {
        buffer[3] = (buffer[3] and 239u) + ((eIA3_128 and 1u) shl 4)
    }

    fun getEIA4(): UInt {
        return buffer[3] and getBitMask(4, 3) shr 3
    }

    fun setEIA4(eIA4: UInt) {
        buffer[3] = (buffer[3] and 247u) + ((eIA4 and 1u) shl 3)
    }

    fun getEIA5(): UInt {
        return buffer[3] and getBitMask(3, 2) shr 2
    }

    fun setEIA5(eIA5: UInt) {
        buffer[3] = (buffer[3] and 251u) + ((eIA5 and 1u) shl 2)
    }

    fun getEIA6(): UInt {
        return buffer[3] and getBitMask(2, 1) shr 1
    }

    fun setEIA6(eIA6: UInt) {
        buffer[3] = (buffer[3] and 253u) + ((eIA6 and 1u) shl 1)
    }

    fun getEIA7(): UInt {
        return buffer[3] and getBitMask(1, 0)
    }

    fun setEIA7(eIA7: UInt) {
        buffer[3] = (buffer[3] and 254u) + (eIA7 and 1u)
    }
*/

    fun getSpare(): UByteArray {
        return buffer.sliceArray(4 until 8)
    }

    fun setSpare(spare: UByteArray) {
        for (i in 4 until 8) {
            buffer[i] = spare[i - 4]
        }
    }
}
