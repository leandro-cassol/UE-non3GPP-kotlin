package free5gc.nas.security

class Count(var count: UInt) {

    fun maskTo24Bits() {
        count = count and 0x00ffffffu
    }

    fun set(overflow: UShort, sqn: UByte) {
        setOverflow(overflow)
        setSQN(sqn)
    }

    fun get(): UInt {
        maskTo24Bits()
        return count
    }

    fun addOne() {
        count++
        maskTo24Bits()
    }

    fun sqn(): UByte {
        return (count and 0x000000ffu).toUByte()
    }

    fun setSQN(sqn: UByte) {
        count = (count and 0xffffff00u) or sqn.toUInt()
    }

    fun overflow(): UShort {
        return ((count and 0x00ffff00u) shr 8).toUShort()
    }

    fun setOverflow(overflow: UShort) {
        count = (count and 0xff0000ffu) or (overflow.toUInt() shl 8)
    }
}


