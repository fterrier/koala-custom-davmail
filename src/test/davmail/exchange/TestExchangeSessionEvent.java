/*
 * DavMail POP/IMAP/SMTP/CalDav/LDAP Exchange Gateway
 * Copyright (C) 2010  Mickael Guessant
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package davmail.exchange;

import davmail.BundleMessage;
import junit.framework.TestCase;

import java.io.IOException;
import java.io.StringReader;

/**
 * Test ExchangeSession event conversion.
 */
@SuppressWarnings({"UseOfSystemOutOrSystemErr"})
public class TestExchangeSessionEvent extends TestCase {
    static String email = "user@company.com";
    static VObject vTimeZone;

    static {
        try {
            vTimeZone = new VObject(new ICSBufferedReader(new StringReader("BEGIN:VTIMEZONE\n" +
                    "TZID:(GMT+01.00) Paris/Madrid/Brussels/Copenhagen\n" +
                    "X-MICROSOFT-CDO-TZID:3\n" +
                    "BEGIN:STANDARD\n" +
                    "DTSTART:16010101T030000\n" +
                    "TZOFFSETFROM:+0200\n" +
                    "TZOFFSETTO:+0100\n" +
                    "RRULE:FREQ=YEARLY;WKST=MO;INTERVAL=1;BYMONTH=10;BYDAY=-1SU\n" +
                    "END:STANDARD\n" +
                    "BEGIN:DAYLIGHT\n" +
                    "DTSTART:16010101T020000\n" +
                    "TZOFFSETFROM:+0100\n" +
                    "TZOFFSETTO:+0200\n" +
                    "RRULE:FREQ=YEARLY;WKST=MO;INTERVAL=1;BYMONTH=3;BYDAY=-1SU\n" +
                    "END:DAYLIGHT\n" +
                    "END:VTIMEZONE")));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    protected String fixICS(String icsBody, boolean fromServer) throws IOException {
        VCalendar vCalendar = new VCalendar(icsBody, email, vTimeZone);
        vCalendar.fixVCalendar(fromServer);
        return vCalendar.toString();
    }

    public void testNoClass() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        String toClient = fixICS(itemBody, true);
        System.out.println(toServer);
        System.out.println(toClient);
        assertTrue(toServer.indexOf("CLASS") < 0);
        assertTrue(toClient.indexOf("CLASS") < 0);
        assertTrue(toClient.indexOf("X-CALENDARSERVER-ACCESS") < 0);
    }

    public void testPublicClass() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "CLASS:PUBLIC\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        String toClient = fixICS(itemBody, true);
        System.out.println(toServer);
        System.out.println(toClient);
        assertTrue(toServer.indexOf("CLASS:PUBLIC") >= 0);
        assertTrue(toClient.indexOf("CLASS:PUBLIC") >= 0);
        assertTrue(toClient.indexOf("X-CALENDARSERVER-ACCESS:PUBLIC") >= 0);
    }

    public void testPrivateClass() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "CLASS:PRIVATE\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        String toClient = fixICS(itemBody, true);
        System.out.println(toServer);
        System.out.println(toClient);
        assertTrue(toServer.indexOf("CLASS:PRIVATE") >= 0);
        assertTrue(toClient.indexOf("CLASS:PRIVATE") >= 0);
        assertTrue(toClient.indexOf("X-CALENDARSERVER-ACCESS:CONFIDENTIAL") >= 0);
    }

    public void testConfidentialClass() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "CLASS:CONFIDENTIAL\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        String toClient = fixICS(itemBody, true);
        System.out.println(toServer);
        System.out.println(toClient);
        assertTrue(toServer.indexOf("CLASS:CONFIDENTIAL") >= 0);
        assertTrue(toClient.indexOf("CLASS:CONFIDENTIAL") >= 0);
        assertTrue(toClient.indexOf("X-CALENDARSERVER-ACCESS:PRIVATE") >= 0);
    }

    public void testCalendarServerAccessPrivate() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "PRODID:-//Apple Inc.//iCal 4.0.3//EN\n" +
                "BEGIN:VEVENT\n" +
                "X-CALENDARSERVER-ACCESS:PRIVATE\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        assertTrue(toServer.indexOf("CLASS:CONFIDENTIAL") >= 0);
    }

    public void testCalendarServerAccessConfidential() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "PRODID:-//Apple Inc.//iCal 4.0.3//EN\n" +
                "BEGIN:VEVENT\n" +
                "X-CALENDARSERVER-ACCESS:CONFIDENTIAL\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        assertTrue(toServer.indexOf("CLASS:PRIVATE") >= 0);
    }

    public void testCalendarServerAccessPublic() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "PRODID:-//Apple Inc.//iCal 4.0.3//EN\n" +
                "BEGIN:VEVENT\n" +
                "X-CALENDARSERVER-ACCESS:PUBLIC\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        assertTrue(toServer.indexOf("CLASS:PUBLIC") >= 0);
    }

    public void testCalendarServerAccessNone() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "PRODID:-//Apple Inc.//iCal 4.0.3//EN\n" +
                "BEGIN:VEVENT\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        assertFalse(toServer.contains("CLASS"));
    }

    public void testNoOrganizer() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        assertTrue(toServer.contains("ORGANIZER"));
    }


    public void testValarm() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "BEGIN:VALARM\n" +
                "TRIGGER:-PT15M\n" +
                "ATTACH;VALUE=URI:Basso\n" +
                "ACTION:AUDIO\n" +
                "END:VALARM\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        assertTrue(toServer.contains("ACTION:DISPLAY"));
    }

    public void testReceiveAllDay() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                vTimeZone +
                "BEGIN:VEVENT\n" +
                "DTSTART;TZID=\"(GMT+01.00) Paris/Madrid/Brussels/Copenhagen\":20100615T000000\n" +
                "DTEND;TZID=\"(GMT+01.00) Paris/Madrid/Brussels/Copenhagen\":20100616T000000\n" +
                "X-MICROSOFT-CDO-ALLDAYEVENT:TRUE\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toClient = fixICS(itemBody, true);
        System.out.println(toClient);
        // OWA created allday events have the X-MICROSOFT-CDO-ALLDAYEVENT set to true and always 000000 in event time
        // just remove the TZID, add VALUE=DATE param and set a date only value 
        assertTrue(toClient.contains("DTSTART;VALUE=DATE:20100615"));
        assertTrue(toClient.contains("DTEND;VALUE=DATE:20100616"));
    }

    public void testSendAllDay() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "DTSTART;VALUE=DATE:20100615\n" +
                "DTEND;VALUE=DATE:20100616\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        // Client created allday event have no timezone and no time information in date values
        // first set the X-MICROSOFT-CDO-ALLDAYEVENT flag for OWA
        assertTrue(toServer.contains("X-MICROSOFT-CDO-ALLDAYEVENT:TRUE"));
        // then patch TZID for Outlook (need to retrieve OWA TZID
        assertTrue(toServer.contains("BEGIN:VTIMEZONE"));
        assertTrue(toServer.contains("TZID:" + vTimeZone.getPropertyValue("TZID")));
        assertTrue(toServer.contains("DTSTART;TZID=\"" + vTimeZone.getPropertyValue("TZID") + "\":20100615T000000"));
        assertTrue(toServer.contains("DTEND;TZID=\"" + vTimeZone.getPropertyValue("TZID") + "\":20100616T000000"));
    }

    public void testRsvp() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "ATTENDEE;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:" + email + "\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toClient = fixICS(itemBody, true);
        System.out.println(toClient);
        assertTrue(toClient.contains("ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:" + email));
    }

    public void testExdate() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "EXDATE;TZID=\"Europe/Paris\":20100809T150000,20100823T150000\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toClient = fixICS(itemBody, true);
        System.out.println(toClient);
        assertTrue(toClient.contains("EXDATE;TZID=\"Europe/Paris\":20100823T150000"));

    }

    public void testEmptyLine() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toClient = fixICS(itemBody, true);
        System.out.println(toClient);
    }

    public void testAttendeeStatus() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "ATTENDEE;PARTSTAT=ACCEPTED;RSVP=FALSE:MAILTO:" + email + "\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        VCalendar vCalendar = new VCalendar(itemBody, email, vTimeZone);
        vCalendar.fixVCalendar(false);
        String status = vCalendar.getAttendeeStatus();
        assertEquals("ACCEPTED", status);
        System.out.println("'" + BundleMessage.format(status) + "'");
    }

    public void testMissingTzid() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "BEGIN:VEVENT\n" +
                "DTSTART:20100101T000000\n" +
                "DTEND:20100102T000000\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, false);
        System.out.println(toServer);
        assertTrue(toServer.contains("DTSTART;TZID="));
        assertTrue(toServer.contains("DTEND;TZID="));
    }

    public void testBroken() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "PRODID:-//Mozilla.org/NONSGML Mozilla Calendar V1.1//EN\n" +
                "VERSION:2.0\n" +
                "BEGIN:VEVENT\n" +
                "CREATED:20100916T115132Z\n" +
                "LAST-MODIFIED:20100916T115138Z\n" +
                "DTSTAMP:20100916T115138Z\n" +
                "UID:d72ff8cc-f3ee-4fbc-b44d-1aaf78d92847\n" +
                "SUMMARY:New Event\n" +
                "DTSTART;VALUE=DATE:20100929\n" +
                "DTEND;VALUE=DATE:20100930\n" +
                "TRANSP:TRANSPARENT\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, true);
        System.out.println(toServer);
    }

    public void testFloatingTimezone() throws IOException {
        String itemBody = "BEGIN:VCALENDAR\n" +
                "PRODID:Microsoft CDO for Microsoft Exchange\n" +
                "VERSION:2.0\n" +
                "BEGIN:VTIMEZONE\n" +
                "TZID:Pacific Time (US & Canada)\\; Tijuana\n" +
                "BEGIN:STANDARD\n" +
                "DTSTART:16010101T030000\n" +
                "TZOFFSETFROM:-0700\n" +
                "TZOFFSETTO:-0800\n" +
                "RRULE:FREQ=YEARLY;WKST=MO;INTERVAL=1;BYMONTH=11;BYDAY=1SU\n" +
                "END:STANDARD\n" +
                "BEGIN:DAYLIGHT\n" +
                "DTSTART:16010101T010000\n" +
                "TZOFFSETFROM:-0800\n" +
                "TZOFFSETTO:-0700\n" +
                "RRULE:FREQ=YEARLY;WKST=MO;INTERVAL=1;BYMONTH=3;BYDAY=2SU\n" +
                "END:DAYLIGHT\n" +
                "END:VTIMEZONE" +
                "BEGIN:VEVENT\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toServer = fixICS(itemBody, true);
        System.out.println(toServer);
    }

    public void testAnotherBroken() throws IOException {
        String icsBody = "BEGIN:VCALENDAR\n" +
                "METHOD:PUBLISH\n" +
                "PRODID:Microsoft Exchange Server 2010\n" +
                "VERSION:2.0\n" +
                "BEGIN:VTIMEZONE\n" +
                "TZID:GMT -0800 (Standard) / GMT -0700 (Daylight)\\n\n" +
                "BEGIN:STANDARD\n" +
                "DTSTART:16010101T020000\n" +
                "TZOFFSETFROM:-0700\n" +
                "TZOFFSETTO:-0800\n" +
                "RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=1SU;BYMONTH=11\n" +
                "END:STANDARD\n" +
                "BEGIN:DAYLIGHT\n" +
                "DTSTART:16010101T020000\n" +
                "TZOFFSETFROM:-0800\n" +
                "TZOFFSETTO:-0700\n" +
                "RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=2SU;BYMONTH=3\n" +
                "END:DAYLIGHT\n" +
                "END:VTIMEZONE\n" +
                "BEGIN:VEVENT\n" +
                "ORGANIZER;CN=John Doe:MAILTO:aTargetAddress@dummy.com\n" +
                "DESCRIPTION;LANGUAGE=en-US:Look over broken timezone.\\n\n" +
                "SUMMARY;LANGUAGE=en-US:meeting\n" +
                "DTSTART;TZID=GMT -0800 (Standard) / GMT -0700 (Daylight)\n" +
                ":20060210T130000\n" +
                "DTEND;TZID=GMT -0800 (Standard) / GMT -0700 (Daylight)\n" +
                ":20060210T143000\n" +
                "UID:040000008200E00074C5B7101A82E00800000000D01FF309972CC601000000000000000\n" +
                " 010000000B389A3C5092D7640A06D2EF5A2125577\n" +
                "CLASS:PUBLIC\n" +
                "PRIORITY:5\n" +
                "DTSTAMP:20060208T180425Z\n" +
                "TRANSP:OPAQUE\n" +
                "STATUS:CONFIRMED\n" +
                "SEQUENCE:0\n" +
                "LOCATION;LANGUAGE=en-US:not sure\n" +
                "X-MICROSOFT-CDO-APPT-SEQUENCE:0\n" +
                "X-MICROSOFT-CDO-OWNERAPPTID:1602758614\n" +
                "X-MICROSOFT-CDO-BUSYSTATUS:BUSY\n" +
                "X-MICROSOFT-CDO-INTENDEDSTATUS:BUSY\n" +
                "X-MICROSOFT-CDO-ALLDAYEVENT:FALSE\n" +
                "X-MICROSOFT-CDO-IMPORTANCE:1\n" +
                "X-MICROSOFT-CDO-INSTTYPE:0\n" +
                "X-MICROSOFT-DISALLOW-COUNTER:FALSE\n" +
                "END:VEVENT\n" +
                "END:VCALENDAR";
        String toClient = fixICS(icsBody, true);
        System.out.println(toClient);

    }
}
