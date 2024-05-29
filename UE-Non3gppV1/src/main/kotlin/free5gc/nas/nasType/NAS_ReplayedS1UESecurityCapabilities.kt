package free5gc.nas.nasType

class ReplayedS1UESecurityCapabilities {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    companion object {
        fun newReplayedS1UESecurityCapabilities(iei: UByte): ReplayedS1UESecurityCapabilities {
            val replayedS1UESecurityCapabilities = ReplayedS1UESecurityCapabilities()
            replayedS1UESecurityCapabilities.setIei(iei)
            return replayedS1UESecurityCapabilities
        }

        private fun getBitMask(high: Int, low: Int): UInt {
            return ((1u shl (high - low + 1)) - 1u) shl low
        }
    }

    @JvmName("getIeiReplayedS1UESecurityCapabilities")
    fun getIei(): UByte = iei

    @JvmName("setIeiReplayedS1UESecurityCapabilities")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("setLenReplayedS1UESecurityCapabilities")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    @JvmName("getLenReplayedS1UESecurityCapabilities")
    fun getLen(): UByte {
        return len
    }

    /*
    fun getEEA0(): UInt {
        return buffer[0] and getBitMask(8, 7) shr 7
    }

    fun setEEA0(eEA0: UInt) {
        buffer[0] = (buffer[0] and 127u) + ((eEA0 and 1u) shl 7)
    }

    fun getEEA1_128(): UInt {
        return buffer[0] and getBitMask(7, 6) shr 6
    }

    fun setEEA1_128(eEA1_128: UInt) {
        buffer[0] = (buffer[0] and 191u) + ((eEA1_128 and 1u) shl 6)
    }

    fun getEEA2_128(): UInt {
        return buffer[0] and getBitMask(6, 5) shr 5
    }

    fun setEEA2_128(eEA2_128: UInt) {
        buffer[0] = (buffer[0] and 223u) + ((eEA2_128 and 1u) shl 5)
    }

    fun getEEA3_128(): UInt {
        return buffer[0] and getBitMask(5, 4) shr 4
    }

    fun setEEA3_128(eEA3_128: UInt) {
        buffer[0] = (buffer[0] and 239u) + ((eEA3_128 and 1u) shl 4)
    }

    fun getEEA4(): UInt {
        return buffer[0] and getBitMask(4, 3) shr 3
    }

    fun setEEA4(eEA4: UInt) {
        buffer[0] = (buffer[0] and 247u) + ((eEA4 and 1u) shl 3)
    }

    fun getEEA5(): UInt {
        return buffer[0] and getBitMask(3, 2) shr 2
    }

    fun setEEA5(eEA5: UInt) {
        buffer[0] = (buffer[0] and 251u) + ((eEA5 and 1u) shl 2)
    }

    fun getEEA6(): UInt {
        return buffer[0] and getBitMask(2, 1) shr 1
    }

    fun setEEA6(eEA6: UInt) {
        buffer[0] = (buffer[0] and 253u) + ((eEA6 and 1u) shl 1)
    }

    fun getEEA7(): UInt {
        return buffer[0] and getBitMask(1, 0)
    }

    fun setEEA7(eEA7: UInt) {
        buffer[0] = (buffer[0] and 254u) + (eEA7 and 1u)
    }

    fun getEIA0(): UInt {
        return buffer[1] and getBitMask(8, 7) shr 7
    }

    fun setEIA0(eIA0: UInt) {
        buffer[1] = (buffer[1] and 127u) + ((eIA0 and 1u) shl 7)
    }

    fun getEIA1_128(): UInt {
        return buffer[1] and getBitMask(7, 6) shr 6
    }

    fun setEIA1_128(eIA1_128: UInt) {
        buffer[1] = (buffer[1] and 191u) + ((eIA1_128 and 1u) shl 6)
    }

    fun getEIA2_128(): UInt {
        return buffer[1] and getBitMask(6, 5) shr 5
    }

    fun setEIA2_128(eIA2_128: UInt) {
        buffer[1] = (buffer[1] and 223u) + ((eIA2_128 and 1u) shl 5)
    }

    fun getEIA3_128(): UInt {
        return buffer[1] and getBitMask(5, 4) shr 4
    }

    fun setEIA3_128(eIA3_128: UInt) {
        buffer[1] = (buffer[1] and 239u) + ((eIA3_128 and 1u) shl 4)
    }

    fun getEIA4(): UInt {
        return buffer[1] and getBitMask(4, 3) shr 3
    }

    fun setEIA4(eIA4: UInt) {
        buffer[1] = (buffer[1] and 247u) + ((eIA4 and 1u) shl 3)
    }

    fun getEIA5(): UInt {
        return buffer[1] and getBitMask(3, 2) shr 2
    }

    fun setEIA5(eIA5: UInt) {
        buffer[1] = (buffer[1] and 251u) + ((eIA5 and 1u) shl 2)
    }

    fun getEIA6(): UInt {
        return buffer[1] and getBitMask(2, 1) shr 1
    }

    fun setEIA6(eIA6: UInt) {
        buffer[1] = (buffer[1] and 253u) + ((eIA6 and 1u) shl 1)
    }

    fun getEIA7(): UInt {
        return buffer[1] and getBitMask(1, 0)
    }

    fun setEIA7(eIA7: UInt) {
        buffer[1] = (buffer[1] and 254u) + (eIA7 and 1u)
    }

    fun getUEA0(): UInt {
        return buffer[2] and getBitMask(8, 7) shr 7
    }

    fun setUEA0(uEA0: UInt) {
        buffer[2] = (buffer[2] and 127u) + ((uEA0 and 1u) shl 7)
    }

    fun getUEA1(): UInt {
        return buffer[2] and getBitMask(7, 6) shr 6
    }

    fun setUEA1(uEA1: UInt) {
        buffer[2] = (buffer[2] and 191u) + ((uEA1 and 1u) shl 6)
    }

    fun getUEA2(): UInt {
        return buffer[2] and getBitMask(6, 5) shr 5
    }

    fun setUEA2(uEA2: UInt) {
        buffer[2] = (buffer[2] and 223u) + ((uEA2 and 1u) shl 5)
    }

    fun getUEA3(): UInt {
        return buffer[2] and getBitMask(5, 4) shr 4
    }

    fun setUEA3(uEA3: UInt) {
        buffer[2] = (buffer[2] and 239u) + ((uEA3 and 1u) shl 4)
    }

    fun getUEA4(): UInt {
        return buffer[2] and getBitMask(4, 3) shr 3
    }

    fun setUEA4(uEA4: UInt) {
        buffer[2] = (buffer[2] and 247u) + ((uEA4 and 1u) shl 3)
    }

    fun getUEA5(): UInt {
        return buffer[2] and getBitMask(3, 2) shr 2
    }

    fun setUEA5(uEA5: UInt) {
        buffer[2] = (buffer[2] and 251u) + ((uEA5 and 1u) shl 2)
    }

    fun getUEA6(): UInt {
        return buffer[2] and getBitMask(2, 1) shr 1
    }

    fun setUEA6(uEA6: UInt) {
        buffer[2] = (buffer[2] and 253u) + ((uEA6 and 1u) shl 1)
    }

    fun getUEA7(): UInt {
        return buffer[2] and getBitMask(1, 0)
    }

    fun setUEA7(uEA7: UInt) {
        buffer[2] = (buffer[2] and 254u) + (uEA7 and 1u)
    }

    fun getUIA1(): UInt {
        return buffer[3] and getBitMask(7, 6) shr 6
    }

    fun setUIA1(uIA1: UInt) {
        buffer[3] = (buffer[3] and 191u) + ((uIA1 and 1u) shl 6)
    }

    fun getUIA2(): UInt {
        return buffer[3] and getBitMask(6, 5) shr 5
    }

    fun setUIA2(uIA2: UInt) {
        buffer[3] = (buffer[3] and 223u) + ((uIA2 and 1u) shl 5)
    }

    fun getUIA3(): UInt {
        return buffer[3] and getBitMask(5, 4) shr 4
    }

    fun setUIA3(uIA3: UInt) {
        buffer[3] = (buffer[3] and 239u) + ((uIA3 and 1u) shl 4)
    }

    fun getUIA4(): UInt {
        return buffer[3] and getBitMask(4, 3) shr 3
    }

    fun setUIA4(uIA4: UInt) {
        buffer[3] = (buffer[3] and 247u) + ((uIA4 and 1u) shl 3)
    }

    fun getUIA5(): UInt {
        return buffer[3] and getBitMask(3, 2) shr 2
    }

    fun setUIA5(uIA5: UInt) {
        buffer[3] = (buffer[3] and 251u) + ((uIA5 and 1u) shl 2)
    }

    fun getUIA6(): UInt {
        return buffer[3] and getBitMask(2, 1) shr 1
    }

    fun setUIA6(uIA6: UInt) {
        buffer[3] = (buffer[3] and 253u) + ((uIA6 and 1u) shl 1)
    }

    fun getUIA7(): UInt {
        return buffer[3] and getBitMask(1, 0)
    }

    fun setUIA7(uIA7: UInt) {
        buffer[3] = (buffer[3] and 254u) + (uIA7 and 1u)
    }

    fun getGEA1(): UInt {
        return buffer[4] and getBitMask(7, 6) shr 6
    }

    fun setGEA1(gEA1: UInt) {
        buffer[4] = (buffer[4] and 191u) + ((gEA1 and 1u) shl 6)
    }

    fun getGEA2(): UInt {
        return buffer[4] and getBitMask(6, 5) shr 5
    }

    fun setGEA2(gEA2: UInt) {
        buffer[4] = (buffer[4] and 223u) + ((gEA2 and 1u) shl 5)
    }

    fun getGEA3(): UInt {
        return buffer[4] and getBitMask(5, 4) shr 4
    }

    fun setGEA3(gEA3: UInt) {
        buffer[4] = (buffer[4] and 239u) + ((gEA3 and 1u) shl 4)
    }

    fun getGEA4(): UInt {
        return buffer[4] and getBitMask(4, 3) shr 3
    }

    fun setGEA4(gEA4: UInt) {
        buffer[4] = (buffer[4] and 247u) + ((gEA4 and 1u) shl 3)
    }

    fun getGEA5(): UInt {
        return buffer[4] and getBitMask(3, 2) shr 2
    }

    fun setGEA5(gEA5: UInt) {
        buffer[4] = (buffer[4] and 251u) + ((gEA5 and 1u) shl 2)
    }

    fun getGEA6(): UInt {
        return buffer[4] and getBitMask(2, 1) shr 1
    }

    fun setGEA6(gEA6: UInt) {
        buffer[4] = (buffer[4] and 253u) + ((gEA6 and 1u) shl 1)
    }

    fun getGEA7(): UInt {
        return buffer[4] and getBitMask(1, 0)
    }

    fun setGEA7(gEA7: UInt) {
        buffer[4] = (buffer[4] and 254u) + (gEA7 and 1u)
    }
*/
}