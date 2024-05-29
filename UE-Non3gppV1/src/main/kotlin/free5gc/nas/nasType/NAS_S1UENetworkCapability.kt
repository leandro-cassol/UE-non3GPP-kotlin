package free5gc.nas.nasType

class S1UENetworkCapability {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiS1UENetworkCapability")
    fun getIei(): UByte = iei

    @JvmName("setIeiS1UENetworkCapability")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenS1UENetworkCapability")
    fun getLen(): UByte = len

    @JvmName("setLenS1UENetworkCapability")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getEEA0(): UByte = (buffer[0].toInt() and getBitMask(8, 7).toInt() shr 7).toUByte()

    fun setEEA0(eEA0: UByte) {
        buffer[0] = (buffer[0].toInt() and 127 or ((eEA0.toInt() and 1) shl 7)).toUByte()
    }


    /*


    func (a *S1UENetworkCapability) GetEEA1_128() (eEA1_128 uint8) {
	return a.Buffer[0] & GetBitMask(7, 6) >> (6)
}



func (a *S1UENetworkCapability) SetEEA1_128(eEA1_128 uint8) {
	a.Buffer[0] = (a.Buffer[0] & 191) + ((eEA1_128 & 1) << 6)
}



func (a *S1UENetworkCapability) GetEEA2_128() (eEA2_128 uint8) {
	return a.Buffer[0] & GetBitMask(6, 5) >> (5)
}



func (a *S1UENetworkCapability) SetEEA2_128(eEA2_128 uint8) {
	a.Buffer[0] = (a.Buffer[0] & 223) + ((eEA2_128 & 1) << 5)
}



func (a *S1UENetworkCapability) GetEEA3_128() (eEA3_128 uint8) {
	return a.Buffer[0] & GetBitMask(5, 4) >> (4)
}



func (a *S1UENetworkCapability) SetEEA3_128(eEA3_128 uint8) {
	a.Buffer[0] = (a.Buffer[0] & 239) + ((eEA3_128 & 1) << 4)
}



func (a *S1UENetworkCapability) GetEEA4() (eEA4 uint8) {
	return a.Buffer[0] & GetBitMask(4, 3) >> (3)
}



func (a *S1UENetworkCapability) SetEEA4(eEA4 uint8) {
	a.Buffer[0] = (a.Buffer[0] & 247) + ((eEA4 & 1) << 3)
}



func (a *S1UENetworkCapability) GetEEA5() (eEA5 uint8) {
	return a.Buffer[0] & GetBitMask(3, 2) >> (2)
}



func (a *S1UENetworkCapability) SetEEA5(eEA5 uint8) {
	a.Buffer[0] = (a.Buffer[0] & 251) + ((eEA5 & 1) << 2)
}



func (a *S1UENetworkCapability) GetEEA6() (eEA6 uint8) {
	return a.Buffer[0] & GetBitMask(2, 1) >> (1)
}



func (a *S1UENetworkCapability) SetEEA6(eEA6 uint8) {
	a.Buffer[0] = (a.Buffer[0] & 253) + ((eEA6 & 1) << 1)
}



func (a *S1UENetworkCapability) GetEEA7() (eEA7 uint8) {
	return a.Buffer[0] & GetBitMask(1, 0)
}



func (a *S1UENetworkCapability) SetEEA7(eEA7 uint8) {
	a.Buffer[0] = (a.Buffer[0] & 254) + (eEA7 & 1)
}



func (a *S1UENetworkCapability) GetEIA0() (eIA0 uint8) {
	return a.Buffer[1] & GetBitMask(8, 7) >> (7)
}



func (a *S1UENetworkCapability) SetEIA0(eIA0 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 127) + ((eIA0 & 1) << 7)
}



func (a *S1UENetworkCapability) GetEIA1_128() (eIA1_128 uint8) {
	return a.Buffer[1] & GetBitMask(7, 6) >> (6)
}



func (a *S1UENetworkCapability) SetEIA1_128(eIA1_128 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 191) + ((eIA1_128 & 1) << 6)
}



func (a *S1UENetworkCapability) GetEIA2_128() (eIA2_128 uint8) {
	return a.Buffer[1] & GetBitMask(6, 5) >> (5)
}



func (a *S1UENetworkCapability) SetEIA2_128(eIA2_128 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 223) + ((eIA2_128 & 1) << 5)
}



func (a *S1UENetworkCapability) GetEIA3_128() (eIA3_128 uint8) {
	return a.Buffer[1] & GetBitMask(5, 4) >> (4)
}



func (a *S1UENetworkCapability) SetEIA3_128(eIA3_128 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 239) + ((eIA3_128 & 1) << 4)
}



func (a *S1UENetworkCapability) GetEIA4() (eIA4 uint8) {
	return a.Buffer[1] & GetBitMask(4, 3) >> (3)
}



func (a *S1UENetworkCapability) SetEIA4(eIA4 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 247) + ((eIA4 & 1) << 3)
}



func (a *S1UENetworkCapability) GetEIA5() (eIA5 uint8) {
	return a.Buffer[1] & GetBitMask(3, 2) >> (2)
}



func (a *S1UENetworkCapability) SetEIA5(eIA5 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 251) + ((eIA5 & 1) << 2)
}



func (a *S1UENetworkCapability) GetEIA6() (eIA6 uint8) {
	return a.Buffer[1] & GetBitMask(2, 1) >> (1)
}



func (a *S1UENetworkCapability) SetEIA6(eIA6 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 253) + ((eIA6 & 1) << 1)
}



func (a *S1UENetworkCapability) GetEIA7() (eIA7 uint8) {
	return a.Buffer[1] & GetBitMask(1, 0)
}



func (a *S1UENetworkCapability) SetEIA7(eIA7 uint8) {
	a.Buffer[1] = (a.Buffer[1] & 254) + (eIA7 & 1)
}



func (a *S1UENetworkCapability) GetUEA0() (uEA0 uint8) {
	return a.Buffer[2] & GetBitMask(8, 7) >> (7)
}



func (a *S1UENetworkCapability) SetUEA0(uEA0 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 127) + ((uEA0 & 1) << 7)
}



func (a *S1UENetworkCapability) GetUEA1() (uEA1 uint8) {
	return a.Buffer[2] & GetBitMask(7, 6) >> (6)
}



func (a *S1UENetworkCapability) SetUEA1(uEA1 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 191) + ((uEA1 & 1) << 6)
}



func (a *S1UENetworkCapability) GetUEA2() (uEA2 uint8) {
	return a.Buffer[2] & GetBitMask(6, 5) >> (5)
}



func (a *S1UENetworkCapability) SetUEA2(uEA2 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 223) + ((uEA2 & 1) << 5)
}



func (a *S1UENetworkCapability) GetUEA3() (uEA3 uint8) {
	return a.Buffer[2] & GetBitMask(5, 4) >> (4)
}



func (a *S1UENetworkCapability) SetUEA3(uEA3 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 239) + ((uEA3 & 1) << 4)
}



func (a *S1UENetworkCapability) GetUEA4() (uEA4 uint8) {
	return a.Buffer[2] & GetBitMask(4, 3) >> (3)
}



func (a *S1UENetworkCapability) SetUEA4(uEA4 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 247) + ((uEA4 & 1) << 3)
}



func (a *S1UENetworkCapability) GetUEA5() (uEA5 uint8) {
	return a.Buffer[2] & GetBitMask(3, 2) >> (2)
}



func (a *S1UENetworkCapability) SetUEA5(uEA5 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 251) + ((uEA5 & 1) << 2)
}



func (a *S1UENetworkCapability) GetUEA6() (uEA6 uint8) {
	return a.Buffer[2] & GetBitMask(2, 1) >> (1)
}



func (a *S1UENetworkCapability) SetUEA6(uEA6 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 253) + ((uEA6 & 1) << 1)
}



func (a *S1UENetworkCapability) GetUEA7() (uEA7 uint8) {
	return a.Buffer[2] & GetBitMask(1, 0)
}



func (a *S1UENetworkCapability) SetUEA7(uEA7 uint8) {
	a.Buffer[2] = (a.Buffer[2] & 254) + (uEA7 & 1)
}



func (a *S1UENetworkCapability) GetUCS2() (uCS2 uint8) {
	return a.Buffer[3] & GetBitMask(8, 7) >> (7)
}



func (a *S1UENetworkCapability) SetUCS2(uCS2 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 127) + ((uCS2 & 1) << 7)
}



func (a *S1UENetworkCapability) GetUIA1() (uIA1 uint8) {
	return a.Buffer[3] & GetBitMask(7, 6) >> (6)
}



func (a *S1UENetworkCapability) SetUIA1(uIA1 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 191) + ((uIA1 & 1) << 6)
}



func (a *S1UENetworkCapability) GetUIA2() (uIA2 uint8) {
	return a.Buffer[3] & GetBitMask(6, 5) >> (5)
}



func (a *S1UENetworkCapability) SetUIA2(uIA2 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 223) + ((uIA2 & 1) << 5)
}



func (a *S1UENetworkCapability) GetUIA3() (uIA3 uint8) {
	return a.Buffer[3] & GetBitMask(5, 4) >> (4)
}



func (a *S1UENetworkCapability) SetUIA3(uIA3 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 239) + ((uIA3 & 1) << 4)
}



func (a *S1UENetworkCapability) GetUIA4() (uIA4 uint8) {
	return a.Buffer[3] & GetBitMask(4, 3) >> (3)
}



func (a *S1UENetworkCapability) SetUIA4(uIA4 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 247) + ((uIA4 & 1) << 3)
}



func (a *S1UENetworkCapability) GetUIA5() (uIA5 uint8) {
	return a.Buffer[3] & GetBitMask(3, 2) >> (2)
}



func (a *S1UENetworkCapability) SetUIA5(uIA5 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 251) + ((uIA5 & 1) << 2)
}



func (a *S1UENetworkCapability) GetUIA6() (uIA6 uint8) {
	return a.Buffer[3] & GetBitMask(2, 1) >> (1)
}



func (a *S1UENetworkCapability) SetUIA6(uIA6 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 253) + ((uIA6 & 1) << 1)
}



func (a *S1UENetworkCapability) GetUIA7() (uIA7 uint8) {
	return a.Buffer[3] & GetBitMask(1, 0)
}



func (a *S1UENetworkCapability) SetUIA7(uIA7 uint8) {
	a.Buffer[3] = (a.Buffer[3] & 254) + (uIA7 & 1)
}



func (a *S1UENetworkCapability) GetProSedd() (proSedd uint8) {
	return a.Buffer[4] & GetBitMask(8, 7) >> (7)
}



func (a *S1UENetworkCapability) SetProSedd(proSedd uint8) {
	a.Buffer[4] = (a.Buffer[4] & 127) + ((proSedd & 1) << 7)
}



func (a *S1UENetworkCapability) GetProSe() (proSe uint8) {
	return a.Buffer[4] & GetBitMask(7, 6) >> (6)
}



func (a *S1UENetworkCapability) SetProSe(proSe uint8) {
	a.Buffer[4] = (a.Buffer[4] & 191) + ((proSe & 1) << 6)
}



func (a *S1UENetworkCapability) GetH245ASH() (h245ASH uint8) {
	return a.Buffer[4] & GetBitMask(6, 5) >> (5)
}



func (a *S1UENetworkCapability) SetH245ASH(h245ASH uint8) {
	a.Buffer[4] = (a.Buffer[4] & 223) + ((h245ASH & 1) << 5)
}



func (a *S1UENetworkCapability) GetACCCSFB() (aCCCSFB uint8) {
	return a.Buffer[4] & GetBitMask(5, 4) >> (4)
}



func (a *S1UENetworkCapability) SetACCCSFB(aCCCSFB uint8) {
	a.Buffer[4] = (a.Buffer[4] & 239) + ((aCCCSFB & 1) << 4)
}



func (a *S1UENetworkCapability) GetLPP() (lPP uint8) {
	return a.Buffer[4] & GetBitMask(4, 3) >> (3)
}



func (a *S1UENetworkCapability) SetLPP(lPP uint8) {
	a.Buffer[4] = (a.Buffer[4] & 247) + ((lPP & 1) << 3)
}



func (a *S1UENetworkCapability) GetLCS() (lCS uint8) {
	return a.Buffer[4] & GetBitMask(3, 2) >> (2)
}



func (a *S1UENetworkCapability) SetLCS(lCS uint8) {
	a.Buffer[4] = (a.Buffer[4] & 251) + ((lCS & 1) << 2)
}



func (a *S1UENetworkCapability) GetxSRVCC() (xSRVCC uint8) {
	return a.Buffer[4] & GetBitMask(2, 1) >> (1)
}



func (a *S1UENetworkCapability) SetxSRVCC(xSRVCC uint8) {
	a.Buffer[4] = (a.Buffer[4] & 253) + ((xSRVCC & 1) << 1)
}



func (a *S1UENetworkCapability) GetNF() (nF uint8) {
	return a.Buffer[4] & GetBitMask(1, 0)
}



func (a *S1UENetworkCapability) SetNF(nF uint8) {
	a.Buffer[4] = (a.Buffer[4] & 254) + (nF & 1)
}



func (a *S1UENetworkCapability) GetEPCO() (ePCO uint8) {
	return a.Buffer[5] & GetBitMask(8, 7) >> (7)
}



func (a *S1UENetworkCapability) SetEPCO(ePCO uint8) {
	a.Buffer[5] = (a.Buffer[5] & 127) + ((ePCO & 1) << 7)
}



func (a *S1UENetworkCapability) GetHCCPCIOT() (hCCPCIOT uint8) {
	return a.Buffer[5] & GetBitMask(7, 6) >> (6)
}



func (a *S1UENetworkCapability) SetHCCPCIOT(hCCPCIOT uint8) {
	a.Buffer[5] = (a.Buffer[5] & 191) + ((hCCPCIOT & 1) << 6)
}



func (a *S1UENetworkCapability) GetERwoPDN() (eRwoPDN uint8) {
	return a.Buffer[5] & GetBitMask(6, 5) >> (5)
}



func (a *S1UENetworkCapability) SetERwoPDN(eRwoPDN uint8) {
	a.Buffer[5] = (a.Buffer[5] & 223) + ((eRwoPDN & 1) << 5)
}



func (a *S1UENetworkCapability) GetS1UData() (s1UData uint8) {
	return a.Buffer[5] & GetBitMask(5, 4) >> (4)
}



func (a *S1UENetworkCapability) SetS1UData(s1UData uint8) {
	a.Buffer[5] = (a.Buffer[5] & 239) + ((s1UData & 1) << 4)
}



func (a *S1UENetworkCapability) GetUPCIot() (uPCIot uint8) {
	return a.Buffer[5] & GetBitMask(4, 3) >> (3)
}



func (a *S1UENetworkCapability) SetUPCIot(uPCIot uint8) {
	a.Buffer[5] = (a.Buffer[5] & 247) + ((uPCIot & 1) << 3)
}



func (a *S1UENetworkCapability) GetCPCIot() (cPCIot uint8) {
	return a.Buffer[5] & GetBitMask(3, 2) >> (2)
}



func (a *S1UENetworkCapability) SetCPCIot(cPCIot uint8) {
	a.Buffer[5] = (a.Buffer[5] & 251) + ((cPCIot & 1) << 2)
}



func (a *S1UENetworkCapability) GetProserelay() (proserelay uint8) {
	return a.Buffer[5] & GetBitMask(2, 1) >> (1)
}



func (a *S1UENetworkCapability) SetProserelay(proserelay uint8) {
	a.Buffer[5] = (a.Buffer[5] & 253) + ((proserelay & 1) << 1)
}



func (a *S1UENetworkCapability) GetProSedc() (proSedc uint8) {
	return a.Buffer[5] & GetBitMask(1, 0)
}



func (a *S1UENetworkCapability) SetProSedc(proSedc uint8) {
	a.Buffer[5] = (a.Buffer[5] & 254) + (proSedc & 1)
}



func (a *S1UENetworkCapability) GetBearer15() (bearer15 uint8) {
	return a.Buffer[6] & GetBitMask(8, 7) >> (7)
}



func (a *S1UENetworkCapability) SetBearer15(bearer15 uint8) {
	a.Buffer[6] = (a.Buffer[6] & 127) + ((bearer15 & 1) << 7)
}



func (a *S1UENetworkCapability) GetSGC() (sGC uint8) {
	return a.Buffer[6] & GetBitMask(7, 6) >> (6)
}



func (a *S1UENetworkCapability) SetSGC(sGC uint8) {
	a.Buffer[6] = (a.Buffer[6] & 191) + ((sGC & 1) << 6)
}



func (a *S1UENetworkCapability) GetN1mode() (n1mode uint8) {
	return a.Buffer[6] & GetBitMask(6, 5) >> (5)
}



func (a *S1UENetworkCapability) SetN1mode(n1mode uint8) {
	a.Buffer[6] = (a.Buffer[6] & 223) + ((n1mode & 1) << 5)
}



func (a *S1UENetworkCapability) GetDCNR() (dCNR uint8) {
	return a.Buffer[6] & GetBitMask(5, 4) >> (4)
}



func (a *S1UENetworkCapability) SetDCNR(dCNR uint8) {
	a.Buffer[6] = (a.Buffer[6] & 239) + ((dCNR & 1) << 4)
}



func (a *S1UENetworkCapability) GetCPbackoff() (cPbackoff uint8) {
	return a.Buffer[6] & GetBitMask(4, 3) >> (3)
}



func (a *S1UENetworkCapability) SetCPbackoff(cPbackoff uint8) {
	a.Buffer[6] = (a.Buffer[6] & 247) + ((cPbackoff & 1) << 3)
}



func (a *S1UENetworkCapability) GetRestrictEC() (restrictEC uint8) {
	return a.Buffer[6] & GetBitMask(3, 2) >> (2)
}



func (a *S1UENetworkCapability) SetRestrictEC(restrictEC uint8) {
	a.Buffer[6] = (a.Buffer[6] & 251) + ((restrictEC & 1) << 2)
}



func (a *S1UENetworkCapability) GetV2XPC5() (v2XPC5 uint8) {
	return a.Buffer[6] & GetBitMask(2, 1) >> (1)
}



func (a *S1UENetworkCapability) SetV2XPC5(v2XPC5 uint8) {
	a.Buffer[6] = (a.Buffer[6] & 253) + ((v2XPC5 & 1) << 1)
}



func (a *S1UENetworkCapability) GetMulitpeDRB() (mulitpeDRB uint8) {
	return a.Buffer[6] & GetBitMask(1, 0)
}



func (a *S1UENetworkCapability) SetMulitpeDRB(mulitpeDRB uint8) {
	a.Buffer[6] = (a.Buffer[6] & 254) + (mulitpeDRB & 1)
}



func (a *S1UENetworkCapability) GetSpare() (spare []uint8) {
	spare = make([]uint8, len(a.Buffer)-7)
	copy(spare, a.Buffer[7:])
	return spare
}



func (a *S1UENetworkCapability) SetSpare(spare []uint8) {
	copy(a.Buffer[7:], spare)
}




     */



    companion object {
        fun newS1UENetworkCapability(iei: UByte): S1UENetworkCapability {
            val s1UENetworkCapability = S1UENetworkCapability()
            s1UENetworkCapability.setIei(iei)
            return s1UENetworkCapability
        }

        fun getBitMask(pos: Int, len: Int): UByte {
            return ((1 shl len) - 1 shl pos).toUByte()
        }
    }
}
