package free5gc.nas.nasType

import java.nio.ByteBuffer

class DNN {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiDNN")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiDNN")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenDNN")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenDNN")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getDNN(): String = rfc1035tofqdn(buffer)

    fun setDNN(dNN: String) {
        try {
            val b = fqdnToRfc1035(dNN)
            buffer = b
            len = b.size.toUByte()
        } catch (e: Exception) {
            // Handle error
        }
    }

    companion object {
        fun newDNN(iei: UByte): DNN {
            val dnn = DNN()
            dnn.setIei(iei)
            return dnn
        }

        fun fqdnToRfc1035(fqdn: String): UByteArray {
            val rfc1035RR = ByteBuffer.allocate(256)
            val domainSegments = fqdn.split(".")
            for (segment in domainSegments) {
                if (segment.length > 63) {
                    throw Exception("fqdn limit the label to 63 octets or less")
                }
                rfc1035RR.put(segment.length.toByte())
                rfc1035RR.put(segment.toByteArray())
            }
            if (rfc1035RR.position() > 255) {
                throw Exception("fqdn should less then 255 octet")
            }
            return (rfc1035RR.array().sliceArray(0 until rfc1035RR.position())).toUByteArray()
        }

        fun rfc1035tofqdn(rfc1035RR: UByteArray): String {
            val rfc1035Reader = ByteBuffer.wrap(rfc1035RR.toByteArray())
            var fqdn = ""
            while (rfc1035Reader.hasRemaining()) {
                val labelLen = rfc1035Reader.get().toInt()
                val labelBytes = ByteArray(labelLen)
                rfc1035Reader.get(labelBytes)
                fqdn += String(labelBytes) + "."
            }
            return fqdn.dropLast(1)
        }
    }
}