package free5gc.nas.security

import Zuc
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor


private val log = LoggerFactory.getLogger("security")

fun nasEncrypt(algoID: UByte, knasEnc: ByteArray, count: UInt, bearer: UByte, direction: UByte, payload: ByteArray) {
    if (bearer.toInt() > 0x1f) {
        throw Exception("Bearer is beyond 5 bits")
    }
    if (direction.toInt() > 1) {
        throw Exception("Direction is beyond 1 bits")
    }
    when (algoID) {
        AlgCiphering128NEA0 -> {
            log.debug("Use NEA0")
        }
        AlgCiphering128NEA1 -> {
            log.debug("Use NEA1")
            val output = nEA1(knasEnc, count, bearer.toUInt(), direction.toUInt(), payload, (payload.size * 8).toUInt())
            System.arraycopy(output, 0, payload, 0, output.size)
        }
        AlgCiphering128NEA2 -> {
            log.debug("Use NEA2")
            val output = nEA2(knasEnc, count, bearer, direction, payload)
            System.arraycopy(output, 0, payload, 0, output.size)
        }
        AlgCiphering128NEA3 -> {
            log.debug("Use NEA3")
            val output = nEA3(knasEnc, count, bearer, direction, payload, (payload.size * 8).toUInt())
            System.arraycopy(output, 0, payload, 0, output.size)
        }
        else -> {
            throw Exception("Unknown Algorithm Identity[$algoID]")
        }
    }
}

fun nasMacCalculate(algoID: UByte, knasInt: UByteArray, count: UInt, bearer: UByte, direction: UByte, msg: ByteArray): ByteArray {
    if (bearer > (0x1f).toUByte()) {
        throw Exception("Bearer is beyond 5 bits")
    }
    if (direction.toInt() > 1) {
        throw Exception("Direction is beyond 1 bits")
    }
    return when (algoID) {
        AlgIntegrity128NIA0 -> {
            log.warn("Integrity NIA0 is emergency.")
            ByteArray(4)
        }
        AlgIntegrity128NIA1 -> {
            log.debug("Use NIA1")
            nIA1(knasInt.toByteArray(), count, bearer.toByte(), direction.toUInt(), msg, (msg.size * 8).toULong())
        }
        AlgIntegrity128NIA2 -> {
            log.debug("Use NIA2")
            nIA2(knasInt.toByteArray(), count, bearer, direction, msg)
        }
        AlgIntegrity128NIA3 -> {
            log.debug("Use NIA3")
            nIA3(knasInt.toByteArray(), count, bearer, direction, msg, (msg.size * 8).toUInt())
        }
        else -> {
            throw Exception("Unknown Algorithm Identity[$algoID]")
        }
    }
}

fun nEA1(ck: ByteArray, countC: UInt, bearer: UInt, direction: UInt, ibs: ByteArray, length: UInt): ByteArray {
    val k = UIntArray(4)
    for (i in 0 until 4) {
        k[i] = ByteBuffer.wrap(ck.sliceArray(4 * (3 - i) until 4 * (3 - i + 1))).order(ByteOrder.BIG_ENDIAN).int.toUInt()
    }
    val iv = UIntArray(4) {
        when (it) {
            0, 2 -> (bearer shl 27) or (direction shl 26)
            1, 3 -> countC
            else -> 0u
        }
    }
    val l = (length + 31u) / 32u
    val r = length % 32u
    val ks = getKeyStream(k.toIntArray(), iv.toIntArray(), l.toInt())

    if (r != 0u) {
        ks[l.toInt() - 1] = ks[l.toInt() - 1] and ((1u shl ((32u - r).toInt())) - 1u).inv().toInt()
    }
    val obs = ByteArray(ibs.size)
    val i = 0u

    for (i in 0u until length / 32u) {
        for (j in 0u until 4u) {
            obs[(4u * i + j).toInt()] = (ibs[(4u * i + j).toInt()] xor ((ks[i.toInt()] shr (8 * (3 - j.toInt()))) and 0xff).toByte())
        }
    }

    if (r != 0u) {
        val ll = (r + 7u) / 8u
        for (j in 0u until ll) {
            obs[(4u * i + j).toInt()] = (ibs[(4u * i + j).toInt()] xor ((ks[i.toInt()] shr (8 * (3 - j.toInt()))) and 0xff).toByte())
        }
    }
    return obs
}

fun nEA2(key: ByteArray, count: UInt, bearer: UByte, direction: UByte, ibs: ByteArray): ByteArray {
    val counterBlk = ByteArray(16)
    ByteBuffer.wrap(counterBlk).order(ByteOrder.BIG_ENDIAN).putInt(count.toInt())
    counterBlk[4] = (bearer.toInt() shl 3 or (direction.toInt() shl 2)).toByte()
    return try {
        val block = Cipher.getInstance("AES/CTR/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val ivParameterSpec = IvParameterSpec(counterBlk)
        block.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec)
        val obs = block.doFinal(ibs)
        obs
    } catch (e: Exception) {
        ByteArray(0)
    }
}

fun nEA3(ck: ByteArray, count: UInt, bearer: UByte, direction: UByte, ibs: ByteArray, length: UInt): ByteArray {
    val iv = ByteArray(16)
    ByteBuffer.wrap(iv).order(ByteOrder.BIG_ENDIAN).putInt(count.toInt())
    iv[4] = ((bearer.toUInt() shl 3) or (direction.toUInt() shl 2)).toByte()

    for (i in 0 until 8) {
        iv[i + 8] = iv[i]
    }

    val l = ((length + 31u) / 32u).toInt()
    val stream = Zuc(ck, iv, l)

    val obs = ByteArray(ibs.size)

    for (i in 0 until l) {
        for (j in 0 until 4) {
            val index = i * 4 + j
            if (index < ((length + 7u) / 8u).toInt()) {
                obs[index] = (ibs[index].toInt() xor ((stream[i].toInt() ushr (8 * (3 - j))) and 0xff)).toByte()
            }
        }
    }

    if (length % 8u != 0u) {
        val lastObsIndex = (length / 8u).toInt()
        obs[lastObsIndex] = (obs[lastObsIndex].toInt() and (0xff shl (8 - (length % 8u).toInt()))).toByte()
    }

    for (j in (length / 8u + 1u).toInt() until obs.size) {
        obs[j] = 0
    }
    return obs
}

fun nIA1(ik: ByteArray, countI: UInt, bearer: Byte, direction: UInt, msg: ByteArray, length: ULong): ByteArray {
    val fresh = (bearer.toUInt() shl 27)
    val k = UIntArray(4) {
        ByteBuffer.wrap(ik.copyOfRange(4 * (3 - it), 4 * (3 - it + 1))).order(ByteOrder.BIG_ENDIAN).int.toUInt()
    }
    val iv = uintArrayOf(fresh xor (direction shl 15), countI xor (direction shl 31), fresh, countI)
    val d = ((length + 63u) / 64u) + 1u
    val z = getKeyStream(k.toIntArray(), iv.toIntArray(), 5)

    val p = (z[0].toULong() shl 32) or z[1].toULong()
    val q = (z[2].toULong() shl 32) or z[3].toULong()

    var eval: ULong = 0u
    for (i in 0uL until d - 2uL) {
        val m = ByteBuffer.wrap(msg.copyOfRange((8 * i.toLong()).toInt(), (8 * (i.toLong() + 1)).toInt())).order(ByteOrder.BIG_ENDIAN).long.toULong()
        eval = mul(eval.xor(m), p, 0x000000000000001bUL)
    }

    val tmp = msg.copyOfRange((8 * (d.toLong() - 2)).toInt(), msg.size)
    val m = ByteBuffer.wrap(tmp).order(ByteOrder.BIG_ENDIAN).long.toULong()
    eval = mul(eval.xor(m), p, 0x000000000000001bUL)

    eval = eval.xor(length)
    eval = mul(eval, q, 0x000000000000001bUL)
    val macI = (eval shr 32).toInt() xor z[4].toInt()

    return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(macI).array()
}

fun nIA2(key: ByteArray, count: UInt, bearer: UByte, direction: UByte, msg: ByteArray): ByteArray {
    // Couter[0..32] | BEARER[0..4] | DIRECTION[0] | 0^26
    val m = ByteArray(msg.size + 8)

    // First 32 bits are count
    val countBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(count.toInt()).array()
    System.arraycopy(countBytes, 0, m, 0, countBytes.size)

    // Put Bearer and direction together
    m[4] = ((bearer.toInt() shl 3) or (direction.toInt() shl 2)).toByte()

    System.arraycopy(msg, 0, m, 8, msg.size)

    // Uso de biblioteca externa BouncyCastle
    val cmac = CMac(AESEngine()) // Usando AES-CMAC
    val keyParam = KeyParameter(key) // Parâmetro da chave
    cmac.init(keyParam) // Inicializa o CMAC com a chave
    val output = ByteArray(cmac.macSize) // Tamanho do output do MAC
    cmac.update(m, 0, m.size) // Atualiza o CMAC com os dados
    cmac.doFinal(output, 0) // Gera o MAC
    val macBytes = output.copyOfRange(0, 4) // Retorna apenas os primeiros 4 bytes do Mac

    return macBytes
}

private fun UByteArray.setUInt32(index: Int, value: UInt) {
    this[index] = (value shr 24).toUByte()
    this[index + 1] = ((value shr 16) and 0xFFU).toUByte()
    this[index + 2] = ((value shr 8) and 0xFFU).toUByte()
    this[index + 3] = (value and 0xFFU).toUByte()
}

fun nIA3(ik: ByteArray, count: UInt, bearer: UByte, direction: UByte, msg: ByteArray, length: UInt): ByteArray {
    val iv = ByteArray(16)
    ByteBuffer.wrap(iv).order(ByteOrder.BIG_ENDIAN).putInt(count.toInt())
    iv[4] = (bearer.toInt() shl 3 and 0xF8).toByte()
    iv[5] = 0
    iv[6] = 0
    iv[7] = 0
    iv[8] = (direction.toInt() shl 7 xor iv[0].toInt()).toByte()
    for (i in 0 until 7) {
        iv[i + 9] = iv[i + 1]
    }
    iv[14] = (direction.toInt() shl 7 xor iv[6].toInt()).toByte()
    val l = (length + 31u) / 32u + 2u
    val stream = Zuc(ik, iv, l.toInt())
    val mac = genMac(msg, stream.toUIntArray(), length.toInt())
    return mac
}


private fun mulx(v: ULong, c: ULong): ULong {
    return if (v and 0x8000000000000000u != 0uL) {
        (v shl 1) xor c
    } else {
        v shl 1
    }
}

private fun mulxPow(v: ULong, i: ULong, c: ULong): ULong {
    return if (i == 0uL) {
        v
    } else {
        mulx(mulxPow(v, i - 1uL, c), c)
    }
}

private fun mul(v: ULong, p: ULong, c: ULong): ULong {
    var rst = 0uL
    for (i in 0uL until 64uL) {
        if ((p shr i.toInt()) and 1uL == 1uL) {
            rst = rst xor mulxPow(v, i, c)
        }
    }
    return rst
}

private fun genMac(m: ByteArray, stream: UIntArray, blength: Int): ByteArray {
    var t = 0u
    val l = stream.toIntArray().size
    for (i in 0 until blength) {
        if (m[i / 8].toInt() and (1 shl (7 - (i % 8))) != 0) {
            t = t xor getWord(stream, i)
        }
    }
    t = t xor getWord(stream, blength)
    t = t xor getWord(stream, 32 * (l - 1))
    val mac = ByteArray(4)
    val buffer = ByteBuffer.wrap(mac)
    buffer.order(ByteOrder.BIG_ENDIAN)
    buffer.putInt(t.toInt())
    return mac
}

private fun getWord(stream: UIntArray, i: Int): UInt {
    val cntBackBit = i % 32
    val cntFrontBit = 32 - cntBackBit
    val loc = i / 32
    return if (cntBackBit == 0) {
        stream[loc]
    } else {
        (stream[loc] shl cntBackBit) or (stream[loc + 1] shr cntFrontBit)
    }
}
