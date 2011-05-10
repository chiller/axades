package org.axades.service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.axades.core.XadesT;
import org.bouncycastle.tsp.TSPException;

import android.app.IntentService;
import android.content.Intent;
import android.util.Log;

public class XadesService extends IntentService {

	  //A szülőnek át kell adni a dolgozó szál nevét
	  public XadesService() {
	      super("XadesService");
	  }

	  /*Az IntentService ezt hívja meg a dolgozó szálból azzal az Intent objektummal,
	   *  ami elindította, majd visszatérés után leállítja a Service-t.
	   */
	  protected void onHandleIntent(Intent intent) {
	      Log.v("Xades","Called XadesService");
	      //A broadcast cím kiolvasása
	      String broadcastid = intent.getStringExtra("broadcastid");
	      String p12path = intent.getStringExtra("p12path");
	      String p12pass = intent.getStringExtra("p12pass");
	      String signdata = intent.getStringExtra("signdata");
	      
	      //###########
	      //Crypto Core 
	       
	      try{	      
	    	  call_signer(signdata, p12path, p12pass);
	      }
	      catch (Exception e){
	    	  e.printStackTrace();
	      }
	      
	      //###########
	      //A broadcast uzenet létrehozása
	      Intent broadcast = new Intent();
	      broadcast.putExtra("result", "Success");
	      broadcast.setAction(broadcastid);
	      sendBroadcast(broadcast);
	      
	      return;  
	  }
	  
	  private void call_signer(String signdatapath, String p12path, String p12pass) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, InvalidKeyException, UnrecoverableKeyException, SignatureException, TSPException
	  {
		  XadesT signer = new XadesT(signdatapath, p12path, p12pass);
		  signer.initKeystore();
		  signer.sign();
		
	  }
	}