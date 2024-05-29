package free5gc.nas.nasType

class RequestedDRXParameters {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiRequestedDRXParameters")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiRequestedDRXParameters")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenRequestedDRXParameters")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenRequestedDRXParameters")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getDRXValue(): UByte {
        return octet and getBitMask(4, 0).toUByte()
    }

    fun setDRXValue(dRXValue: UByte) {
        octet = ((octet and 240.toUByte()) + (dRXValue and 15.toUByte())).toUByte()
    }

    companion object {
        fun newRequestedDRXParameters(iei: UByte): RequestedDRXParameters {
            val requestedDRXParameters = RequestedDRXParameters()
            requestedDRXParameters.setIei(iei)
            return requestedDRXParameters
        }

        private fun getBitMask(pos: Int, len: Int): Int {
            return ((1 shl len) - 1) shl pos
        }
    }
}
