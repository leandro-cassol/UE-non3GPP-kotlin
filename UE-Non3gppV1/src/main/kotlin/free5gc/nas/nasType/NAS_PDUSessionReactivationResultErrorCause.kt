package free5gc.nas.nasType

class PDUSessionReactivationResultErrorCause {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiPDUSessionReactivationResultErrorCause")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiPDUSessionReactivationResultErrorCause")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenPDUSessionReactivationResultErrorCause")
    fun getLen(): UShort {
        return len
    }

    @JvmName("setLenPDUSessionReactivationResultErrorCause")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getPDUSessionIDAndCauseValue(): UByteArray {
        return buffer.copyOf()
    }

    fun setPDUSessionIDAndCauseValue(pDUSessionIDAndCauseValue: UByteArray) {
        buffer = pDUSessionIDAndCauseValue.copyOf()
    }

    companion object {
        fun newPDUSessionReactivationResultErrorCause(iei: UByte): PDUSessionReactivationResultErrorCause {
            val pDUSessionReactivationResultErrorCause = PDUSessionReactivationResultErrorCause()
            pDUSessionReactivationResultErrorCause.setIei(iei)
            return pDUSessionReactivationResultErrorCause
        }
    }
}