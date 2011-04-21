package org.axades.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import android.util.Log;



public class TSHexRequest{
    /** Called when the activity is first created. */
	/** 
	 * tsaUrl - TimeStampAuthority URL
	 * data - bytearray containing to-be-hashed data
	 */
	public static String xades_hex_ts_req(String tsaUrl, byte[] data){
        try{
        
    	MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(data);
		byte[] digest = messageDigest.digest();

		
	    OutputStream out = null;
   

        
//        String hexdatahead = "30290201013021300906052b0e03021a05000414";
//        String hexdatadigest = XadesUtil.toHex(digest);
//        String hexdatatail = "0101ff";
//        
//        String requesthex = hexdatahead + hexdatadigest + hexdatatail;
       
        String hexdatahead = "302e020101301f300706052b0e03021a0414";
        String hexdatadigest = XadesUtil.toHex(digest);
        String hexnoncehead = "0205"; //0 a vegen a padding
        String hexnonce = XadesUtil.toHex(new BigInteger("123554746825").toByteArray());
        String hexdatatail = "0101ff";
        
        String requesthex = hexdatahead+hexdatadigest+hexnoncehead+hexnonce+hexdatatail;
        
        
        byte[] request = XadesUtil.hexToByteArray(requesthex);
        
        URL url = new URL(tsaUrl); 
        HttpURLConnection con = (HttpURLConnection) url.openConnection(); 

        con.setDoOutput(true); 
        con.setDoInput(true); 
        con.setRequestMethod("POST"); 
        con.setRequestProperty("Content-type", "application/timestamp-query"); 

        con.setRequestProperty("Content-length", String.valueOf(request.length)); 
        out = con.getOutputStream(); 
        out.write(request); 
        out.flush(); 

        if (con.getResponseCode() != HttpURLConnection.HTTP_OK) { 
            throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage()); 
        } 
        Log.v("Xades","code:" + con.getResponseCode()); 

        InputStream in = con.getInputStream(); 
        Log.v("Xades","resMessage:" + con.getResponseMessage()); 
        
        
        TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
        //System.out.println(XadesUtil.toString(org.bouncycastle.util.encoders.Base64.encode(resp.getEncoded())));
        //Same without first 12 characters
        String token_nostatus_b64 = XadesUtil.toString(org.bouncycastle.util.encoders.Base64.encode(resp.getEncoded())).substring(12);
        
        return token_nostatus_b64;
        } catch (Exception e) { e.printStackTrace(); }
		return "";
    }
}