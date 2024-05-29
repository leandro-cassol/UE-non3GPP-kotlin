package free5gc.nas.nasType

class Capability5GMM {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByteArray = UByteArray(13)

    @JvmName("getIeiCapability5GMM")
    fun getIei(): UByte = iei

    @JvmName("setIeiCapability5GMM")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenCapability5GMM")
    fun getLen(): UByte = len

    @JvmName("setLenCapability5GMM")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getLPP(): UByte {
        return ((octet[0].toInt() and getBitMask(3, 2).toInt()) shr 2).toUByte()
    }

    fun setLPP(lPP: UByte) {
        octet[0] = ((octet[0].toInt() and 251) + ((lPP.toInt() and 1) shl 2)).toUByte()
    }

    fun getHOAttach(): UByte {
        return ((octet[0].toInt() and getBitMask(2, 1).toInt()) shr 1).toUByte()
    }

    fun setHOAttach(hOAttach: UByte) {
        octet[0] = ((octet[0].toInt() and 253) + ((hOAttach.toInt() and 1) shl 1)).toUByte()
    }

    fun getS1Mode(): UByte {
        return octet[0] and getBitMask(1, 0).toUByte()
    }

    fun setS1Mode(s1Mode: UByte) {
        octet[0] = ((octet[0].toInt() and 254) + (s1Mode.toInt() and 1)).toUByte()
    }

    fun getSpare(): UByteArray {
        return octet.copyOfRange(1, 13)
    }

    fun setSpare(spare: UByteArray) {
        spare.copyInto(octet, 1, 0, 12)
    }



    companion object {
        private fun getBitMask(high: Int, low: Int): UByte {
            return ((1 shl (high - low + 1)) - 1).toUByte() and (1u shl low).toUByte()
        }

        fun newCapability5GMM(iei: UByte): Capability5GMM {
            val capability5GMM = Capability5GMM()
            capability5GMM.setIei(iei)
            return capability5GMM
        }
    }
}