package free5gc.nas.security

import kotlin.experimental.and
import kotlin.experimental.xor

val sr = byteArrayOf(
    0x63.toByte(), 0x7c.toByte(), 0x77.toByte(), 0x7b.toByte(), 0xf2.toByte(), 0x6b.toByte(), 0x6f.toByte(), 0xc5.toByte(),
    0x30.toByte(), 0x01.toByte(), 0x67.toByte(), 0x2b.toByte(), 0xfe.toByte(), 0xd7.toByte(), 0xab.toByte(), 0x76.toByte(),
    0xca.toByte(), 0x82.toByte(), 0xc9.toByte(), 0x7d.toByte(), 0xfa.toByte(), 0x59.toByte(), 0x47.toByte(), 0xf0.toByte(),
    0xad.toByte(), 0xd4.toByte(), 0xa2.toByte(), 0xaf.toByte(), 0x9c.toByte(), 0xa4.toByte(), 0x72.toByte(), 0xc0.toByte(),
    0xb7.toByte(), 0xfd.toByte(), 0x93.toByte(), 0x26.toByte(), 0x36.toByte(), 0x3f.toByte(), 0xf7.toByte(), 0xcc.toByte(),
    0x34.toByte(), 0xa5.toByte(), 0xe5.toByte(), 0xf1.toByte(), 0x71.toByte(), 0xd8.toByte(), 0x31.toByte(), 0x15.toByte(),
    0x04.toByte(), 0xc7.toByte(), 0x23.toByte(), 0xc3.toByte(), 0x18.toByte(), 0x96.toByte(), 0x05.toByte(), 0x9a.toByte(),
    0x07.toByte(), 0x12.toByte(), 0x80.toByte(), 0xe2.toByte(), 0xeb.toByte(), 0x27.toByte(), 0xb2.toByte(), 0x75.toByte(),
    0x09.toByte(), 0x83.toByte(), 0x2c.toByte(), 0x1a.toByte(), 0x1b.toByte(), 0x6e.toByte(), 0x5a.toByte(), 0xa0.toByte(),
    0x52.toByte(), 0x3b.toByte(), 0xd6.toByte(), 0xb3.toByte(), 0x29.toByte(), 0xe3.toByte(), 0x2f.toByte(), 0x84.toByte(),
    0x53.toByte(), 0xd1.toByte(), 0x00.toByte(), 0xed.toByte(), 0x20.toByte(), 0xfc.toByte(), 0xb1.toByte(), 0x5b.toByte(),
    0x6a.toByte(), 0xcb.toByte(), 0xbe.toByte(), 0x39.toByte(), 0x4a.toByte(), 0x4c.toByte(), 0x58.toByte(), 0xcf.toByte(),
    0xd0.toByte(), 0xef.toByte(), 0xaa.toByte(), 0xfb.toByte(), 0x43.toByte(), 0x4d.toByte(), 0x33.toByte(), 0x85.toByte(),
    0x45.toByte(), 0xf9.toByte(), 0x02.toByte(), 0x7f.toByte(), 0x50.toByte(), 0x3c.toByte(), 0x9f.toByte(), 0xa8.toByte(),
    0x51.toByte(), 0xa3.toByte(), 0x40.toByte(), 0x8f.toByte(), 0x92.toByte(), 0x9d.toByte(), 0x38.toByte(), 0xf5.toByte(),
    0xbc.toByte(), 0xb6.toByte(), 0xda.toByte(), 0x21.toByte(), 0x10.toByte(), 0xff.toByte(), 0xf3.toByte(), 0xd2.toByte(),
    0xcd.toByte(), 0x0c.toByte(), 0x13.toByte(), 0xec.toByte(), 0x5f.toByte(), 0x97.toByte(), 0x44.toByte(), 0x17.toByte(),
    0xc4.toByte(), 0xa7.toByte(), 0x7e.toByte(), 0x3d.toByte(), 0x64.toByte(), 0x5d.toByte(), 0x19.toByte(), 0x73.toByte(),
    0x60.toByte(), 0x81.toByte(), 0x4f.toByte(), 0xdc.toByte(), 0x22.toByte(), 0x2a.toByte(), 0x90.toByte(), 0x88.toByte(),
    0x46.toByte(), 0xee.toByte(), 0xb8.toByte(), 0x14.toByte(), 0xde.toByte(), 0x5e.toByte(), 0x0b.toByte(), 0xdb.toByte(),
    0xe0.toByte(), 0x32.toByte(), 0x3a.toByte(), 0x0a.toByte(), 0x49.toByte(), 0x06.toByte(), 0x24.toByte(), 0x5c.toByte(),
    0xc2.toByte(), 0xd3.toByte(), 0xac.toByte(), 0x62.toByte(), 0x91.toByte(), 0x95.toByte(), 0xe4.toByte(), 0x79.toByte(),
    0xe7.toByte(), 0xc8.toByte(), 0x37.toByte(), 0x6d.toByte(), 0x8d.toByte(), 0xd5.toByte(), 0x4e.toByte(), 0xa9.toByte(),
    0x6c.toByte(), 0x56.toByte(), 0xf4.toByte(), 0xea.toByte(), 0x65.toByte(), 0x7a.toByte(), 0xae.toByte(), 0x08.toByte(),
    0xba.toByte(), 0x78.toByte(), 0x25.toByte(), 0x2e.toByte(), 0x1c.toByte(), 0xa6.toByte(), 0xb4.toByte(), 0xc6.toByte(),
    0xe8.toByte(), 0xdd.toByte(), 0x74.toByte(), 0x1f.toByte(), 0x4b.toByte(), 0xbd.toByte(), 0x8b.toByte(), 0x8a.toByte(),
    0x70.toByte(), 0x3e.toByte(), 0xb5.toByte(), 0x66.toByte(), 0x48.toByte(), 0x03.toByte(), 0xf6.toByte(), 0x0e.toByte(),
    0x61.toByte(), 0x35.toByte(), 0x57.toByte(), 0xb9.toByte(), 0x86.toByte(), 0xc1.toByte(), 0x1d.toByte(), 0x9e.toByte(),
    0xe1.toByte(), 0xf8.toByte(), 0x98.toByte(), 0x11.toByte(), 0x69.toByte(), 0xd9.toByte(), 0x8e.toByte(), 0x94.toByte(),
    0x9b.toByte(), 0x1e.toByte(), 0x87.toByte(), 0xe9.toByte(), 0xce.toByte(), 0x55.toByte(), 0x28.toByte(), 0xdf.toByte(),
    0x8c.toByte(), 0xa1.toByte(), 0x89.toByte(), 0x0d.toByte(), 0xbf.toByte(), 0xe6.toByte(), 0x42.toByte(), 0x68.toByte(),
    0x41.toByte(), 0x99.toByte(), 0x2d.toByte(), 0x0f.toByte(), 0xb0.toByte(), 0x54.toByte(), 0xbb.toByte(), 0x16.toByte()
)
val sq = byteArrayOf(
    0x25.toByte(), 0x24.toByte(), 0x73.toByte(), 0x67.toByte(), 0xd7.toByte(), 0xae.toByte(), 0x5c.toByte(), 0x30.toByte(),
    0xa4.toByte(), 0xee.toByte(), 0x6e.toByte(), 0xcb.toByte(), 0x7d.toByte(), 0xb5.toByte(), 0x82.toByte(), 0xdb.toByte(),
    0xe4.toByte(), 0x8e.toByte(), 0x48.toByte(), 0x49.toByte(), 0x4f.toByte(), 0x5d.toByte(), 0x6a.toByte(), 0x78.toByte(),
    0x70.toByte(), 0x88.toByte(), 0xe8.toByte(), 0x5f.toByte(), 0x5e.toByte(), 0x84.toByte(), 0x65.toByte(), 0xe2.toByte(),
    0xd8.toByte(), 0xe9.toByte(), 0xcc.toByte(), 0xed.toByte(), 0x40.toByte(), 0x2f.toByte(), 0x11.toByte(), 0x28.toByte(),
    0x57.toByte(), 0xd2.toByte(), 0xac.toByte(), 0xe3.toByte(), 0x4a.toByte(), 0x15.toByte(), 0x1b.toByte(), 0xb9.toByte(),
    0xb2.toByte(), 0x80.toByte(), 0x85.toByte(), 0xa6.toByte(), 0x2e.toByte(), 0x02.toByte(), 0x47.toByte(), 0x29.toByte(),
    0x07.toByte(), 0x4b.toByte(), 0x0e.toByte(), 0xc1.toByte(), 0x51.toByte(), 0xaa.toByte(), 0x89.toByte(), 0xd4.toByte(),
    0xca.toByte(), 0x01.toByte(), 0x46.toByte(), 0xb3.toByte(), 0xef.toByte(), 0xdd.toByte(), 0x44.toByte(), 0x7b.toByte(),
    0xc2.toByte(), 0x7f.toByte(), 0xbe.toByte(), 0xc3.toByte(), 0x9f.toByte(), 0x20.toByte(), 0x4c.toByte(), 0x64.toByte(),
    0x83.toByte(), 0xa2.toByte(), 0x68.toByte(), 0x42.toByte(), 0x13.toByte(), 0xb4.toByte(), 0x41.toByte(), 0xcd.toByte(),
    0xba.toByte(), 0xc6.toByte(), 0xbb.toByte(), 0x6d.toByte(), 0x4d.toByte(), 0x71.toByte(), 0x21.toByte(), 0xf4.toByte(),
    0x8d.toByte(), 0xb0.toByte(), 0xe5.toByte(), 0x93.toByte(), 0xfe.toByte(), 0x8f.toByte(), 0xe6.toByte(), 0xcf.toByte(),
    0x43.toByte(), 0x45.toByte(), 0x31.toByte(), 0x22.toByte(), 0x37.toByte(), 0x36.toByte(), 0x96.toByte(), 0xfa.toByte(),
    0xbc.toByte(), 0x0f.toByte(), 0x08.toByte(), 0x52.toByte(), 0x1d.toByte(), 0x55.toByte(), 0x1a.toByte(), 0xc5.toByte(),
    0x4e.toByte(), 0x23.toByte(), 0x69.toByte(), 0x7a.toByte(), 0x92.toByte(), 0xff.toByte(), 0x5b.toByte(), 0x5a.toByte(),
    0xeb.toByte(), 0x9a.toByte(), 0x1c.toByte(), 0xa9.toByte(), 0xd1.toByte(), 0x7e.toByte(), 0x0d.toByte(), 0xfc.toByte(),
    0x50.toByte(), 0x8a.toByte(), 0xb6.toByte(), 0x62.toByte(), 0xf5.toByte(), 0x0a.toByte(), 0xf8.toByte(), 0xdc.toByte(),
    0x03.toByte(), 0x3c.toByte(), 0x0c.toByte(), 0x39.toByte(), 0xf1.toByte(), 0xb8.toByte(), 0xf3.toByte(), 0x3d.toByte(),
    0xf2.toByte(), 0xd5.toByte(), 0x97.toByte(), 0x66.toByte(), 0x81.toByte(), 0x32.toByte(), 0xa0.toByte(), 0x00.toByte(),
    0x06.toByte(), 0xce.toByte(), 0xf6.toByte(), 0xea.toByte(), 0xb7.toByte(), 0x17.toByte(), 0xf7.toByte(), 0x8c.toByte(),
    0x79.toByte(), 0xd6.toByte(), 0xa7.toByte(), 0xbf.toByte(), 0x8b.toByte(), 0x3f.toByte(), 0x1f.toByte(), 0x53.toByte(),
    0x63.toByte(), 0x75.toByte(), 0x35.toByte(), 0x2c.toByte(), 0x60.toByte(), 0xfd.toByte(), 0x27.toByte(), 0xd3.toByte(),
    0x94.toByte(), 0xa5.toByte(), 0x7c.toByte(), 0xa1.toByte(), 0x05.toByte(), 0x58.toByte(), 0x2d.toByte(), 0xbd.toByte(),
    0xd9.toByte(), 0xc7.toByte(), 0xaf.toByte(), 0x6b.toByte(), 0x54.toByte(), 0x0b.toByte(), 0xe0.toByte(), 0x38.toByte(),
    0x04.toByte(), 0xc8.toByte(), 0x9d.toByte(), 0xe7.toByte(), 0x14.toByte(), 0xb1.toByte(), 0x87.toByte(), 0x9c.toByte(),
    0xdf.toByte(), 0x6f.toByte(), 0xf9.toByte(), 0xda.toByte(), 0x2a.toByte(), 0xc4.toByte(), 0x59.toByte(), 0x16.toByte(),
    0x74.toByte(), 0x91.toByte(), 0xab.toByte(), 0x26.toByte(), 0x61.toByte(), 0x76.toByte(), 0x34.toByte(), 0x2b.toByte(),
    0xad.toByte(), 0x99.toByte(), 0xfb.toByte(), 0x72.toByte(), 0xec.toByte(), 0x33.toByte(), 0x12.toByte(), 0xde.toByte(),
    0x98.toByte(), 0x3b.toByte(), 0xc0.toByte(), 0x9b.toByte(), 0x3e.toByte(), 0x18.toByte(), 0x10.toByte(), 0x3a.toByte(),
    0x56.toByte(), 0xe1.toByte(), 0x77.toByte(), 0xc9.toByte(), 0x1e.toByte(), 0x9e.toByte(), 0x95.toByte(), 0xa3.toByte(),
    0x90.toByte(), 0x19.toByte(), 0xa8.toByte(), 0x6c.toByte(), 0x09.toByte(), 0xd0.toByte(), 0xf0.toByte(), 0x86.toByte()
)
class Snow3g {
    private val lfsr = IntArray(16)
    private val fsm = IntArray(3)

    fun mulx(V: Byte, c: Byte): Byte {
        return if ((V and 0x80.toByte()) != 0.toByte()) {
            (V.toInt() shl 1 xor c.toInt()).toByte()
        } else {
            (V.toInt() shl 1).toByte()
        }
    }

    private fun mulxPow(V: Byte, i: Byte, c: Byte): Byte {
        return if (i == 0.toByte()) {
            V
        } else {
            mulx(mulxPow(V, (i - 1).toByte(), c), c)
        }
    }

    private fun s1(w: UInt): UInt {
        val w0 = (w shr 24 and 255u).toUByte().toInt()
        val w1 = (w shr 16 and 255u).toUByte().toInt()
        val w2 = (w shr 8 and 255u).toUByte().toInt()
        val w3 = w.toUByte().toInt()

        val r0 = (mulx(sr[w0], 0x1b) xor sr[w1] xor sr[w2] xor mulx(sr[w3], 0x1b) xor sr[w3]).toUInt()
        val r1 = (mulx(sr[w0], 0x1b) xor sr[w0] xor mulx(sr[w1], 0x1b) xor sr[w2] xor sr[w3]).toUInt()
        val r2 = (sr[w0] xor mulx(sr[w1], 0x1b) xor sr[w1] xor mulx(sr[w2], 0x1b) xor sr[w3]).toUInt()
        val r3 = (sr[w0] xor sr[w1] xor mulx(sr[w2], 0x1b) xor sr[w2] xor mulx(sr[w3], 0x1b)).toUInt()

        return (r0 shl 24) or (r1 shl 16) or (r2 shl 8) or r3
    }

    private fun s2(w: UInt): UInt {
        val w0 = (w shr 24 and 255u).toUByte().toInt()
        val w1 = (w shr 16 and 255u).toUByte().toInt()
        val w2 = (w shr 8 and 255u).toUByte().toInt()
        val w3 = w.toUByte().toInt()

        val r0 = (mulx(sq[w0], 0x69) xor sq[w1] xor sq[w2] xor mulx(sq[w3], 0x69) xor sq[w3]).toUInt()
        val r1 = (mulx(sq[w0], 0x69) xor sq[w0] xor mulx(sq[w1], 0x69) xor sq[w2] xor sq[w3]).toUInt()
        val r2 = (sq[w0] xor mulx(sq[w1], 0x69) xor sq[w1] xor mulx(sq[w2], 0x69) xor sq[w3]).toUInt()
        val r3 = (sq[w0] xor sq[w1] xor mulx(sq[w2], 0x69) xor sq[w2] xor mulx(sq[w3], 0x69)).toUInt()

        return (r0 shl 24) or (r1 shl 16) or (r2 shl 8) or r3
    }

    private fun mulAlpha(c: Byte): Int {
        val r0 = mulxPow(c, 23.toByte(), 0xa9.toByte())
        val r1 = mulxPow(c, 245.toByte(), 0xa9.toByte())
        val r2 = mulxPow(c, 48.toByte(), 0xa9.toByte())
        val r3 = mulxPow(c, 239.toByte(), 0xa9.toByte())
        return r0.toInt() shl 24 or (r1.toInt() shl 16) or (r2.toInt() shl 8) or r3.toInt()
    }
    private fun divAlpha(c: Byte): Int {
        val r0 = mulxPow(c, 16.toByte(), 0xa9.toByte())
        val r1 = mulxPow(c, 39.toByte(), 0xa9.toByte())
        val r2 = mulxPow(c, 6.toByte(), 0xa9.toByte())
        val r3 = mulxPow(c, 64.toByte(), 0xa9.toByte())
        return r0.toInt() shl 24 or (r1.toInt() shl 16) or (r2.toInt() shl 8) or r3.toInt()
    }
    private fun lfsrInitializationMode(F: Int) {
        val v = (lfsr[0] shl 8) xor mulAlpha((lfsr[0] shr 24 and 0xff).toByte()) xor lfsr[2] xor (lfsr[11] shr 8) xor divAlpha((lfsr[11] and 0xff).toByte()) xor F
        for (i in 0..14) {
            lfsr[i] = lfsr[i + 1]
        }
        lfsr[15] = v
    }
    private fun lfsrKeystreamMode() {
        val v = (lfsr[0] shl 8) xor mulAlpha((lfsr[0] shr 24 and 0xff).toByte()) xor lfsr[2] xor (lfsr[11] shr 8) xor divAlpha((lfsr[11] and 0xff).toByte())
        for (i in 0..14) {
            lfsr[i] = lfsr[i + 1]
        }
        lfsr[15] = v
    }

    private fun clockFsm(s15: Int, s5: Int): Int {
        val F = (s15 + fsm[0]) xor fsm[1]
        val r = fsm[1] + (fsm[2] xor s5)
        fsm[2] = s2(fsm[1].toUInt()).toInt()
        fsm[1] = s1(fsm[0].toUInt()).toInt()
        fsm[0] = r
        return F
    }

    private fun generateKeystream(n: Int, ks: IntArray) {
        clockFsm(lfsr[15], lfsr[5])
        lfsrKeystreamMode()
        for (i in 0 until n) {
            val F = clockFsm(lfsr[15], lfsr[5])
            ks[i] = F xor lfsr[0]
            lfsrKeystreamMode()
        }
    }
    fun getKeyStream(k: IntArray, iv: IntArray, n: Int): IntArray {
        for (i in 0..3) {
            lfsr[i] = k[i] xor 0xffffffff.toInt()
        }
        for (i in 4..7) {
            lfsr[i] = k[i - 4]
        }
        lfsr[8] = k[0] xor 0xffffffff.toInt()
        lfsr[9] = k[1] xor 0xffffffff.toInt() xor iv[3]
        lfsr[10] = k[2] xor 0xffffffff.toInt() xor iv[2]
        lfsr[11] = k[3] xor 0xffffffff.toInt()
        lfsr[12] = k[0] xor iv[1]
        lfsr[13] = k[1]
        lfsr[14] = k[2]
        lfsr[15] = k[3] xor iv[0]
        for (i in 0..2) {
            fsm[i] = 0
        }
        for (i in 0..31) {
            val F = clockFsm(lfsr[15], lfsr[5])
            lfsrInitializationMode(F)
        }
        val ks = IntArray(n)
        generateKeystream(n, ks)
        return ks
    }
}
fun getKeyStream(k: IntArray, iv: IntArray, n: Int): IntArray {
    val s = Snow3g()
    return s.getKeyStream(k, iv, n)
}


