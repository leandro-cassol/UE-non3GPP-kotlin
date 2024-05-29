package free5gc.util.milenage

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor


fun milenageF1(opc: ByteArray, k: ByteArray, xRand: ByteArray, sqn: ByteArray, amf: ByteArray, macA: ByteArray?, macS: ByteArray?) {
    val tmp2 = ByteArray(16)
    val tmp3 = ByteArray(16)

    val rijndaelInput = ByteArray(16)

    for (i in 0 until 16) {
        rijndaelInput[i] = (xRand[i] xor opc[i])
    }

    val block = Cipher.getInstance("AES/ECB/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"))
    }

    val tmp1 = ByteArray(block.blockSize)
    block.doFinal(rijndaelInput, 0, 16, tmp1, 0)

    System.arraycopy(sqn, 0, tmp2, 0, 6)
    System.arraycopy(amf, 0, tmp2, 6, 2)
    System.arraycopy(tmp2, 0, tmp2, 8, 8)

    for (i in 0 until 16) {
        tmp3[(i + 8) % 16] = (tmp2[i] xor opc[i])
    }

    for (i in 0 until 16) {
        tmp3[i] = (tmp3[i] xor tmp1[i])
    }

    block.doFinal(tmp3, 0, 16, tmp1, 0)

    for (i in 0 until 16) {
        tmp1[i] = (tmp1[i] xor opc[i])
    }

    if (macA != null) {
        System.arraycopy(tmp1, 0, macA, 0, 8)
    }

    if (macS != null) {
        System.arraycopy(tmp1, 8, macS, 0, 8)
    }
}


fun milenageF2345(opc: ByteArray, k: ByteArray, xRand: ByteArray, res: ByteArray?, ck: ByteArray?, ik: ByteArray?, ak: ByteArray?, akstar: ByteArray?) {
    val tmp1 = ByteArray(16)
    for (i in 0 until 16) {
        tmp1[i] = (xRand[i] xor opc[i])
    }
    val block = SecretKeySpec(k, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, block)
    val tmp2 = cipher.doFinal(tmp1)
    for (i in 0 until 16) {
        tmp1[i] = (tmp2[i] xor opc[i])
    }
    tmp1[15] = (tmp1[15] xor 1)
    val tmp3 = cipher.doFinal(tmp1)
    for (i in 0 until 16) {
        tmp3[i] = (tmp3[i] xor opc[i])
    }
    if (res != null) {
        tmp3.copyInto(res, 0, 8, 16)
    }
    if (ak != null) {
        tmp3.copyInto(ak, 0, 0, 6)
    }
    if (ck != null) {
        for (i in 0 until 16) {
            tmp1[(i + 12) % 16] = (tmp2[i] xor opc[i])
        }
        tmp1[15] = (tmp1[15] xor 2)
        val ckCipher = Cipher.getInstance("AES/ECB/NoPadding")
        ckCipher.init(Cipher.ENCRYPT_MODE, block)
        ckCipher.doFinal(tmp1, 0, 16, ck, 0)
        for (i in 0 until 16) {
            ck[i] = (ck[i] xor opc[i])
        }
    }
    if (ik != null) {
        for (i in 0 until 16) {
            tmp1[(i + 8) % 16] = (tmp2[i] xor opc[i])
        }
        tmp1[15] = (tmp1[15] xor 4)
        val ikCipher = Cipher.getInstance("AES/ECB/NoPadding")
        ikCipher.init(Cipher.ENCRYPT_MODE, block)
        ikCipher.doFinal(tmp1, 0, 16, ik, 0)
        for (i in 0 until 16) {
            ik[i] = (ik[i] xor opc[i])
        }
    }
    if (akstar != null) {
        for (i in 0 until 16) {
            tmp1[(i + 4) % 16] = (tmp2[i] xor opc[i])
        }
        tmp1[15] = (tmp1[15] xor 8)
        val akstarCipher = Cipher.getInstance("AES/ECB/NoPadding")
        akstarCipher.init(Cipher.ENCRYPT_MODE, block)
        val akstarTmp = akstarCipher.doFinal(tmp1)
        for (i in 0 until 6) {
            akstar[i] = (akstarTmp[i] xor opc[i])
        }
    }
}

fun milenageGenerate(opc: ByteArray, amf: ByteArray, k: ByteArray, sqn: ByteArray, xRand: ByteArray, autn: ByteArray, ik: ByteArray, ck: ByteArray, ak: ByteArray, res: ByteArray, resLen: IntArray) {
    val macA = ByteArray(8)
    if (resLen[0] < 8) {
        resLen[0] = 0
        return
    }
    if (milenageF1(opc, k, xRand, sqn, amf, macA, null) != null || milenageF2345(opc, k, xRand, res, ck, ik, ak, null) != null) {
        resLen[0] = 0
        return
    }
    resLen[0] = 8

    for (i in 0 until 6) {
        autn[i] = (sqn[i] xor ak[i])
        System.arraycopy(amf, 0, autn, 6, 2)
        System.arraycopy(macA, 0, autn, 8, 8)
    }
}

fun milenageAuts(opc: ByteArray, k: ByteArray, xRand: ByteArray, auts: ByteArray, sqn: ByteArray): Int {
    val amf = byteArrayOf(0x00, 0x00)
    val ak = ByteArray(6)
    val macS = ByteArray(8)

    if (milenageF2345(opc, k, xRand, null, null, null, null, ak) != null) {
        return -1
    }
    for (i in 0 until 6) {
        sqn[i] = auts[i] xor ak[i]
    }
    if (milenageF1(opc, k, xRand, sqn, amf, null, macS) != null || !macS.contentEquals(auts.copyOfRange(6, 14))) {
        return -1
    }
    return 0
}

fun gsmMilenage(opc: ByteArray, k: ByteArray, xRand: ByteArray, sres: ByteArray, kc: ByteArray): Int {
    val res = ByteArray(8)
    val ck = ByteArray(16)
    val ik = ByteArray(16)
    if (milenageF2345(opc, k, xRand, res, ck, ik, null, null) != null) {
        return -1
    }
    for (i in 0 until 8) {
        kc[i] = ck[i] xor ck[i + 8] xor ik[i] xor ik[i + 8]
    }
    for (i in 0 until 4) {
        sres[i] = res[i] xor res[i + 4]
    }
    return 0
}

fun milenageCheck(opc: ByteArray, k: ByteArray, sqn: ByteArray, xRand: ByteArray, autn: ByteArray, ik: ByteArray?, ck: ByteArray?, res: ByteArray?, resLen: IntArray, auts: ByteArray): Int {
    val macA = ByteArray(8)
    val ak = ByteArray(6)
    val rxSqn = ByteArray(6)
    val amf: ByteArray?

    if (milenageF2345(opc, k, xRand, res, ck, ik, ak, null) != null) {
        return -1
    }
    resLen[0] = 8
    for (i in 0 until 6) {
        rxSqn[i] = autn[i] xor ak[i]
    }
    if (osMemcmp(rxSqn, sqn, 6) <= 0) {
        val autsAmf = byteArrayOf(0x00, 0x00)
        if (milenageF2345(opc, k, xRand, null, null, null, null, ak) != null) {
            return -1
        }
        for (i in 0 until 6) {
            auts[i] = sqn[i] xor ak[i]
        }
        if (milenageF1(opc, k, xRand, sqn, autsAmf, null, auts.copyOfRange(6, 14)) != null) {
            return -1
        }
        return -2
    }

    amf = autn.copyOfRange(6, autn.size)
    if (milenageF1(opc, k, xRand, rxSqn, amf, macA, null) != null) {
        return -1
    }
    if (!macA.contentEquals(autn.copyOfRange(8, 16))) {
        return -1
    }
    return 0
}

fun osMemcmp(a: ByteArray, b: ByteArray, num: Int): Int {
    for (i in 0 until num) {
        if (a[i] < b[i]) {
            return -i
        }
        if (a[i] > b[i]) {
            return i
        }
    }
    return 0
}

fun f1(opc: ByteArray, k: ByteArray, xRand: ByteArray, sqn: ByteArray, amf: ByteArray, macA: ByteArray, macS: ByteArray) {
    milenageF1(opc, k, xRand, sqn, amf, macA, macS)
}

fun f2345(opc: ByteArray, k: ByteArray, xRand: ByteArray, res: ByteArray, ck: ByteArray, ik: ByteArray, ak: ByteArray, akstar: ByteArray) {
    milenageF2345(opc, k, xRand, res, ck, ik, ak, akstar)
}

fun generateOPC(k: ByteArray, op: ByteArray): ByteArray {
    val block = SecretKeySpec(k, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, block)
    val opc = cipher.doFinal(op)
    for (i in 0 until 16) {
        opc[i] = opc[i] xor op[i]
    }
    return opc
}


fun insertData(op: ByteArray, k: ByteArray, xRand: ByteArray, sqn: ByteArray, amf: ByteArray, opParam: String, kParam: String, randParam: String, sqnParam: String, amfParam: String) {
    var res: ULong
    for (i in 0 until 16) {
        res = opParam.substring(i * 2, i * 2 + 2).toULong(16)
        op[i] = res.toByte()
    }

    for (i in 0 until 16) {
        res = kParam.substring(i * 2, i * 2 + 2).toULong(16)
        k[i] = res.toByte()
    }

    for (i in 0 until 16) {
        res = randParam.substring(i * 2, i * 2 + 2).toULong(16)
        xRand[i] = res.toByte()
    }

    for (i in 0 until 6) {
        res = sqnParam.substring(i * 2, i * 2 + 2).toULong(16)
        sqn[i] = res.toByte()
    }

    for (i in 0 until 2) {
        res = amfParam.substring(i * 2, i * 2 + 2).toULong(16)
        amf[i] = res.toByte()
    }
}