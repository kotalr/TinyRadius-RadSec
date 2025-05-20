package org.tinyradius.util;

import java.util.Calendar;
import java.text.SimpleDateFormat;

public class DateTimeUtil {

    private static ThreadLocal<SimpleDateFormat> FORMAT_YYYY_MM_DDHHMMSS = new ThreadLocal<SimpleDateFormat>() {
        @Override
        protected SimpleDateFormat initialValue() {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        }
    };

    public static String getDateTimeString() {
        return FORMAT_YYYY_MM_DDHHMMSS.get().format(new java.util.Date());
    }

    public static String getPreviousDateTimeBySecondString(int second) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, -second);

        return FORMAT_YYYY_MM_DDHHMMSS.get().format(calendar.getTime());
    }

}
