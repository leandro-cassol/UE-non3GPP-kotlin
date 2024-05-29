package free5gc.nas.nasType

class IMEISVRequest {
    var octet: UByte = 0u

    @JvmName("getIeiIMEISVRequest")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiIMEISVRequest")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getIMEISVRequestValue(): UByte {
        return (octet.toInt() and getBitMask(3, 0).toInt()).toUByte()
    }

    fun setIMEISVRequestValue(iMEISVRequestValue: UByte) {
        octet = (octet.toInt() and 248 or (iMEISVRequestValue.toInt() and 7)).toUByte()
    }

    companion object {
        fun newIMEISVRequest(iei: UByte): IMEISVRequest {
            val iMEISVRequest = IMEISVRequest()
            iMEISVRequest.setIei(iei)
            return iMEISVRequest
        }

        private fun getBitMask(high: Int, low: Int): UByte {
            return ((1 shl (high - low + 1)) - 1 shl low).toUByte()
        }
    }
}


