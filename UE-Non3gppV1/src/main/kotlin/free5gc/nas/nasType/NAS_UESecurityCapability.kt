package free5gc.nas.nasType

class UESecurityCapability {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiUESecurityCapability")
    fun getIei(): UByte = iei

    @JvmName("setIeiUESecurityCapability")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenUESecurityCapability")
    fun getLen(): UByte = len

    @JvmName("setLenUESecurityCapability")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    companion object {
        fun newUESecurityCapability(iei: UByte): UESecurityCapability {
            val uESecurityCapability = UESecurityCapability()
            uESecurityCapability.setIei(iei)
            return uESecurityCapability
        }

        private fun getBitMask(high: Int, low: Int): UInt {
            return ((1u shl (high - low + 1)) - 1u) shl low
        }
    }

    fun getEA0_5G(): UInt {
        return (buffer[0].toUInt() and getBitMask(8, 7)) shr 7
    }

    fun setEA0_5G(eA0_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 127u) or ((eA0_5G and 1u) shl 7)).toUByte()
    }

    fun getEA1_128_5G(): UInt {
        return (buffer[0].toUInt() and getBitMask(7, 6)) shr 6
    }

    fun setEA1_128_5G(eA1_128_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 191u) or ((eA1_128_5G and 1u) shl 6)).toUByte()
    }

    fun getEA2_128_5G(): UInt {
        return (buffer[0].toUInt() and getBitMask(6, 5)) shr 5
    }

    fun setEA2_128_5G(eA2_128_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 223u) or ((eA2_128_5G and 1u) shl 5)).toUByte()
    }

    fun getEA3_128_5G(): UInt {
        return (buffer[0].toUInt() and getBitMask(5, 4)) shr 4
    }

    fun setEA3_128_5G(eA3_128_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 239u) or ((eA3_128_5G and 1u) shl 4)).toUByte()
    }

    fun getEA4_5G(): UInt {
        return (buffer[0].toUInt() and getBitMask(4, 3)) shr 3
    }

    fun setEA4_5G(eA4_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 247u) or ((eA4_5G and 1u) shl 3)).toUByte()
    }

    fun getEA5_5G(): UInt {
        return (buffer[0].toUInt() and getBitMask(3, 2)) shr 2
    }

    fun setEA5_5G(eA5_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 251u) or ((eA5_5G and 1u) shl 2)).toUByte()
    }

    fun getEA6_5G(): UInt {
        return (buffer[0].toUInt() and getBitMask(2, 1)) shr 1
    }

    fun setEA6_5G(eA6_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 253u) or ((eA6_5G and 1u) shl 1)).toUByte()
    }

    fun getEA7_5G(): UInt {
        return buffer[0].toUInt() and getBitMask(1, 0)
    }

    fun setEA7_5G(eA7_5G: UInt) {
        buffer[0] = ((buffer[0].toUInt() and 254u) or (eA7_5G and 1u)).toUByte()
    }

    fun getIA0_5G(): UInt {
        return (buffer[1].toUInt() and getBitMask(8, 7)) shr 7
    }

    fun setIA0_5G(iA0_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 127u) or ((iA0_5G and 1u) shl 7)).toUByte()
    }

    fun getIA1_128_5G(): UInt {
        return (buffer[1].toUInt() and getBitMask(7, 6)) shr 6
    }

    fun setIA1_128_5G(iA1_128_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 191u) or ((iA1_128_5G and 1u) shl 6)).toUByte()
    }

    fun getIA2_128_5G(): UInt {
        return (buffer[1].toUInt() and getBitMask(6, 5)) shr 5
    }

    fun setIA2_128_5G(iA2_128_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 223u) or ((iA2_128_5G and 1u) shl 5)).toUByte()
    }

    fun getIA3_128_5G(): UInt {
        return (buffer[1].toUInt() and getBitMask(5, 4)) shr 4
    }

    fun setIA3_128_5G(iA3_128_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 239u) or ((iA3_128_5G and 1u) shl 4)).toUByte()
    }

    fun getIA4_5G(): UInt {
        return (buffer[1].toUInt() and getBitMask(4, 3)) shr 3
    }

    fun setIA4_5G(iA4_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 247u) or ((iA4_5G and 1u) shl 3)).toUByte()
    }

    fun getIA5_5G(): UInt {
        return (buffer[1].toUInt() and getBitMask(3, 2)) shr 2
    }

    fun setIA5_5G(iA5_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 251u) or ((iA5_5G and 1u) shl 2)).toUByte()
    }

    fun getIA6_5G(): UInt {
        return (buffer[1].toUInt() and getBitMask(2, 1)) shr 1
    }

    fun setIA6_5G(iA6_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 253u) or ((iA6_5G and 1u) shl 1)).toUByte()
    }

    fun getIA7_5G(): UInt {
        return buffer[1].toUInt() and getBitMask(1, 0)
    }

    fun setIA7_5G(iA7_5G: UInt) {
        buffer[1] = ((buffer[1].toUInt() and 254u) or (iA7_5G and 1u)).toUByte()
    }

    fun getEEA0(): UInt {
        return (buffer[2].toUInt() and getBitMask(8, 7)) shr 7
    }

    fun setEEA0(eEA0: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 127u) or ((eEA0 and 1u) shl 7)).toUByte()
    }

    fun getEEA1_128(): UInt {
        return (buffer[2].toUInt() and getBitMask(7, 6)) shr 6
    }

    fun setEEA1_128(eEA1_128: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 191u) or ((eEA1_128 and 1u) shl 6)).toUByte()
    }

    fun getEEA2_128(): UInt {
        return (buffer[2].toUInt() and getBitMask(6, 5)) shr 5
    }

    fun setEEA2_128(eEA2_128: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 223u) or ((eEA2_128 and 1u) shl 5)).toUByte()
    }

    fun getEEA3_128(): UInt {
        return (buffer[2].toUInt() and getBitMask(5, 4)) shr 4
    }

    fun setEEA3_128(eEA3_128: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 239u) or ((eEA3_128 and 1u) shl 4)).toUByte()
    }

    fun getEEA4(): UInt {
        return (buffer[2].toUInt() and getBitMask(4, 3)) shr 3
    }

    fun setEEA4(eEA4: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 247u) or ((eEA4 and 1u) shl 3)).toUByte()
    }

    fun getEEA5(): UInt {
        return (buffer[2].toUInt() and getBitMask(3, 2)) shr 2
    }

    fun setEEA5(eEA5: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 251u) or ((eEA5 and 1u) shl 2)).toUByte()
    }

    fun getEEA6(): UInt {
        return (buffer[2].toUInt() and getBitMask(2, 1)) shr 1
    }

    fun setEEA6(eEA6: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 253u) or ((eEA6 and 1u) shl 1)).toUByte()
    }

    fun getEEA7(): UInt {
        return buffer[2].toUInt() and getBitMask(1, 0)
    }

    fun setEEA7(eEA7: UInt) {
        buffer[2] = ((buffer[2].toUInt() and 254u) or (eEA7 and 1u)).toUByte()
    }

    fun getEIA0(): UInt {
        return (buffer[3].toUInt() and getBitMask(8, 7)) shr 7
    }

    fun setEIA0(eIA0: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 127u) or ((eIA0 and 1u) shl 7)).toUByte()
    }

    fun getEIA1_128(): UInt {
        return (buffer[3].toUInt() and getBitMask(7, 6)) shr 6
    }

    fun setEIA1_128(eIA1_128: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 191u) or ((eIA1_128 and 1u) shl 6)).toUByte()
    }

    fun getEIA2_128(): UInt {
        return (buffer[3].toUInt() and getBitMask(6, 5)) shr 5
    }

    fun setEIA2_128(eIA2_128: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 223u) or ((eIA2_128 and 1u) shl 5)).toUByte()
    }

    fun getEIA3_128(): UInt {
        return (buffer[3].toUInt() and getBitMask(5, 4)) shr 4
    }

    fun setEIA3_128(eIA3_128: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 239u) or ((eIA3_128 and 1u) shl 4)).toUByte()
    }

    fun getEIA4(): UInt {
        return (buffer[3].toUInt() and getBitMask(4, 3)) shr 3
    }

    fun setEIA4(eIA4: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 247u) or ((eIA4 and 1u) shl 3)).toUByte()
    }

    fun getEIA5(): UInt {
        return (buffer[3].toUInt() and getBitMask(3, 2)) shr 2
    }

    fun setEIA5(eIA5: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 251u) or ((eIA5 and 1u) shl 2)).toUByte()
    }

    fun getEIA6(): UInt {
        return (buffer[3].toUInt() and getBitMask(2, 1)) shr 1
    }

    fun setEIA6(eIA6: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 253u) or ((eIA6 and 1u) shl 1)).toUByte()
    }

    fun getEIA7(): UInt {
        return buffer[3].toUInt() and getBitMask(1, 0)
    }

    fun setEIA7(eIA7: UInt) {
        buffer[3] = ((buffer[3].toUInt() and 254u) or (eIA7 and 1u)).toUByte()
    }

    fun getSpare(): UByteArray {
        return buffer.copyOfRange(4, 8)
    }

    fun setSpare(spare: UByteArray) {
        for (i in 0..3) {
            buffer[i + 4] = spare[i]
        }
    }
}