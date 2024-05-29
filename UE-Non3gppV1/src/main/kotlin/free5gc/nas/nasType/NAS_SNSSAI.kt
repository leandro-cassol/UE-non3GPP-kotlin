package free5gc.nas.nasType

class SNSSAI {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet = UByteArray(8)

    @JvmName("getIeiSNSSAI")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiSNSSAI")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenSNSSAI")
    fun getLen(): UByte = len

    @JvmName("setLenSNSSAI")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getSST(): UByte {
        return octet[0]
    }

    fun setSST(sST: UByte) {
        octet[0] = sST
    }

    fun getSD(): UByteArray {
        return octet.sliceArray(1..3)
    }

    fun setSD(sD: UByteArray) {
        for (i in 1..3) {
            octet[i] = sD[i - 1]
        }
    }

    fun getMappedHPLMNSST(): UByte {
        return octet[4]
    }

    fun setMappedHPLMNSST(mappedHPLMNSST: UByte) {
        octet[4] = mappedHPLMNSST
    }

    fun getMappedHPLMNSD(): UByteArray {
        return octet.sliceArray(5..7)
    }

    fun setMappedHPLMNSD(mappedHPLMNSD: UByteArray) {
        for (i in 5..7) {
            octet[i] = mappedHPLMNSD[i - 5]
        }
    }

    companion object {
        fun newSNSSAI(iei: UByte): SNSSAI {
            val sNSSAI = SNSSAI()
            sNSSAI.setIei(iei)
            return sNSSAI
        }
    }
}