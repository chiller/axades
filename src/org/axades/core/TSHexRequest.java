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
import org.bouncycastle.util.encoders.Base64;

import android.util.Log;


/*
 * Timestamp keres manualisan osszerakva hex stringekbol
 */
public class TSHexRequest{
	public static String xades_hex_ts_req(String tsaUrl, byte[] data){
        try{
        
        	MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        	messageDigest.update(data);
        	byte[] digest = messageDigest.digest();		
        	
        	//A szakdolgozat 3.1.2. fejezete ismerteti a karakterek jelenteset
        	String hexdatahead = "302e020101301f300706052b0e03021a0414";
        	String hexdatadigest = XadesUtil.toHex(digest);
        	String hexnoncehead = "0205"; //0 a vegen a padding
        	String hexnonce = XadesUtil.toHex(new BigInteger("123554746825").toByteArray());
        	String hexdatatail = "0101ff";
        	String requesthex = hexdatahead + hexdatadigest + hexnoncehead + hexnonce + hexdatatail;
        
        
        	byte[] request = XadesUtil.hexToByteArray(requesthex);
        
        	//Http kapcsolat felepitese
        	OutputStream out = null;
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
        	//Az elso 12 karakter a status uzenet ami nem resze a tokennek
        	String token_nostatus_b64 = XadesUtil.toString(Base64.encode(resp.getEncoded())).substring(12);
        
        return token_nostatus_b64;
        } catch (Exception e) { e.printStackTrace(); }
		return "";
    }
}