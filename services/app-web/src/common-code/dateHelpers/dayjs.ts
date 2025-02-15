import dayjs from 'dayjs'
import advancedFormat from 'dayjs/plugin/advancedFormat'
import isLeapYear from 'dayjs/plugin/isLeapYear'
import timezone from 'dayjs/plugin/timezone'
import utc from 'dayjs/plugin/utc'
import duration from 'dayjs/plugin/duration'

dayjs.extend(utc)
dayjs.extend(advancedFormat)
dayjs.extend(timezone)
dayjs.extend(isLeapYear)
dayjs.extend(duration)

export { dayjs }
