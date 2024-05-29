package free5gc.util.ueauth

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

const val FC_FOR_CK_PRIME_IK_PRIME_DERIVATION = "20"
const val FC_FOR_KSEAF_DERIVATION = "6C"
const val FC_FOR_RES_STAR_XRES_STAR_DERIVATION = "6B"
const val FC_FOR_KAUSF_DERIVATION = "6A"
const val FC_FOR_KAMF_DERIVATION = "6D"
const val FC_FOR_KGNB_KN3IWF_DERIVATION = "6E"
const val FC_FOR_NH_DERIVATION = "6F"
const val FC_FOR_ALGORITHM_KEY_DERIVATION = "69"

fun kdfLen(input: ByteArray): ByteArray {
    val r = ByteArray(2)
    r[0] = (input.size shr 8 and 0xFF).toByte()
    r[1] = (input.size and 0xFF).toByte()
    return r
}

fun getKdfValue(key: ByteArray, fc: String, vararg param: ByteArray): ByteArray {
    val kdf = Mac.getInstance("HmacSHA256")
    kdf.init(SecretKeySpec(key, "HmacSHA256"))
    val s = mutableListOf<Byte>()

    val sTmp = fc.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    s.addAll(sTmp.toList())
    for (p in param) {
        s.addAll(p.toList())
    }
    kdf.update(s.toByteArray())
    return kdf.doFinal()
}