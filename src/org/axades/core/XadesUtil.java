package org.axades.core;


import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import org.kxml2.io.KXmlSerializer;
import org.kxml2.kdom.Document;
import org.kxml2.kdom.Element;
import org.kxml2.kdom.Node;

import android.util.Log;

public class XadesUtil {
	public static void XMLOutput(Document doc, String path, boolean enveloping, boolean simplets) {
		
		KXmlSerializer serializer = new KXmlSerializer();
		
		if (!enveloping){
			 Element root = doc.getRootElement();
			 Element sig = root.getElement("", "ds:Signature");
			 Document ketto = new Document();
			 ketto.addChild(Node.ELEMENT, sig);
			 
			doc=ketto;
		}
		try {
			String tsoption = "notscert";
			if (!simplets){tsoption="";}
			File f = new File(path+DateUtils.nowshort()+"_"+tsoption+".xml/");
			f.createNewFile();
			FileOutputStream fas = new FileOutputStream(f);
			
			serializer.setOutput(fas, "UTF-8");
			Log.v("Xades","done");
			//tv.setText("Hello, Android4"+fas.toString());
		
		} catch (FileNotFoundException e1) {
			
			e1.printStackTrace();
		}
		 catch (IOException e) {
			
			e.printStackTrace();
		}
		 
		 
		try {
			doc.write(serializer);
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
	}
	
	public static void set_xmlns(Element el, String xmlns_Enveloping){
        el.setAttribute(null,"xmlns","http://uri.etsi.org/01903/v1.3.2#");
        el.setAttribute(null,"xmlns:ds","http://www.w3.org/2000/09/xmldsig#");
        if (xmlns_Enveloping.length()>0){
        	el.setAttribute(null,"xmlns:"+ xmlns_Enveloping ,"http://www.szabo-aron.hu/uri/XAdES-PHP/v/20091201");
        }
	}
	public static class DateUtils {
		  public static final String DATE_FORMAT_NOW = "yyyy-MM-dd HH:mm:ss";

		  public static String now() {
		    Calendar cal = Calendar.getInstance();
		    SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
		    return sdf.format(cal.getTime());

		  }
		  public static String nowxmldt(){
			  String dt = now();
			  dt=dt.replace(' ', 'T');
			  return dt+'Z';
		  }
		  public static final String DATE_FORMAT_SHORT = "MM-dd_HH-mm";

		  public static String nowshort() {
		    Calendar cal = Calendar.getInstance();
		    SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_SHORT);
		    return sdf.format(cal.getTime());

		  }
	}
	 /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes, int length)
    {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }

        return new String(chars);
    }

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes)
    {
        return toString(bytes, bytes.length);
    }
    
    
    
    public static String toHex(byte[] data, int length)
    {
        StringBuffer    buf = new StringBuffer();
        String digits = "0123456789abcdef";
        for (int i = 0; i != length; i++)
        {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }
    
    
   
    
   public static byte[] hexToByteArray(String input){

	   char[] charstring = input.toCharArray();
	   byte[] out = new byte[input.length()/2];
	   for (int i=0;i<charstring.length;i+=2){

    	   int c1 = hexCharToInt(charstring[i]);
    	   int c2 = hexCharToInt(charstring[i+1]);
    	   int c3 = c1<<4;
    	   out[i/2]=(byte) (c2|c3);
    	   
       }
	   return out;
   }
 

public static int hexCharToInt(int c){
   if (c>90){
	   c=c-87;
   }
   else{
	   c=c-48;
   }
   return c;
}
}
