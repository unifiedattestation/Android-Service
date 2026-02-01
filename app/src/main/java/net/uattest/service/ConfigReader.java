package net.uattest.service;

import android.content.Context;
import android.content.res.XmlResourceParser;
import android.util.Xml;

import org.xmlpull.v1.XmlPullParser;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class ConfigReader {
    private static final String CONFIG_PATH = "/product/etc/unifiedattestation.xml";

    public static List<String> loadDefaultUrls(Context context) {
        List<String> urls = new ArrayList<>();
        InputStream input = null;
        try {
            File file = new File(CONFIG_PATH);
            if (file.exists()) {
                input = new FileInputStream(file);
                parseXml(input, urls);
                return urls;
            }
        } catch (Exception ignored) {
        }

        return urls;
    }

    private static void parseXml(InputStream input, List<String> urls) throws Exception {
        XmlPullParser parser = Xml.newPullParser();
        parser.setInput(input, "utf-8");
        parseXml(parser, urls);
    }

    private static void parseXml(XmlPullParser parser, List<String> urls) throws Exception {
        int event = parser.getEventType();
        while (event != XmlPullParser.END_DOCUMENT) {
            if (event == XmlPullParser.START_TAG && "backend".equals(parser.getName())) {
                String url = parser.getAttributeValue(null, "url");
                if (url != null && !url.isEmpty()) {
                    urls.add(url);
                }
            }
            event = parser.next();
        }
    }
}
