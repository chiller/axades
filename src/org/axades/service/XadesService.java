package org.axades.service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
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
	      //###########
	      //Crypto Core
	      
	      call_signer();
	      
	      //###########
	      //A broadcast uzenet létrehozása
	      Intent broadcast = new Intent();
	      broadcast.putExtra("result", "Success");
	      broadcast.setAction(broadcastid);
	      sendBroadcast(broadcast);
	      
	      return;  
	  }
	  
	  private void call_signer()
	  {
		  XadesT signer = new XadesT();
		  try {
			signer.initKeystore();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		  try {
			signer.sign();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TSPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	  }
	}