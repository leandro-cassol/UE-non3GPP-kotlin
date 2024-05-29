package free5gc.nas.nasType

class UniversalTimeAndLocalTimeZone() {
    var iei: UByte = 0u
    var octet = UByteArray(7)

    @JvmName("getIeiUniversalTimeAndLocalTimeZone")
    fun getIei(): UByte = iei

    @JvmName("setIeiUniversalTimeAndLocalTimeZone")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getYear(): UByte = octet[0]

    fun setYear(year: UByte) {
        octet[0] = year
    }

    fun getMonth(): UByte = octet[1]

    fun setMonth(month: UByte) {
        octet[1] = month
    }

    fun getDay(): UByte = octet[2]

    fun setDay(day: UByte) {
        octet[2] = day
    }

    fun getHour(): UByte = octet[3]

    fun setHour(hour: UByte) {
        octet[3] = hour
    }

    fun getMinute(): UByte = octet[4]

    fun setMinute(minute: UByte) {
        octet[4] = minute
    }

    fun getSecond(): UByte = octet[5]

    fun setSecond(second: UByte) {
        octet[5] = second
    }

    fun getTimeZone(): UByte = octet[6]

    fun setTimeZone(timeZone: UByte) {
        octet[6] = timeZone
    }

    companion object {
        fun newUniversalTimeAndLocalTimeZone(iei: UByte): UniversalTimeAndLocalTimeZone {
            val universalTimeAndLocalTimeZone = UniversalTimeAndLocalTimeZone()
            universalTimeAndLocalTimeZone.setIei(iei)
            return universalTimeAndLocalTimeZone
        }
    }
}