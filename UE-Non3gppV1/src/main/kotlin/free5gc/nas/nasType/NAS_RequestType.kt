package free5gc.nas.nasType

class RequestType {
    var octet: UByte = 0u


    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getRequestTypeValue(): UByte {
        return (octet.toInt() and getBitMask(3, 0).toInt()).toUByte()
    }

    fun setRequestTypeValue(requestTypeValue: UByte) {
        octet = (octet.toInt() and 248 or (requestTypeValue.toInt() and 7)).toUByte()
    }

    companion object {
        fun newRequestType(iei: UByte): RequestType {
            val requestType = RequestType()
            requestType.setIei(iei)
            return requestType
        }

        private fun getBitMask(length: Int, position: Int): UByte {
            return ((1 shl length) - 1 shl position).toUByte()
        }
    }
}