package org.axades.service;

import android.app.IntentService;
import android.content.Intent;
import android.util.Log;

public class XadesService extends IntentService {

	  /** 
	   * A constructor is required, and must call the super IntentService(String)
	   * constructor with a name for the worker thread.
	   */
	  public XadesService() {
	      super("XadesService");
	  }

	  /**
	   * The IntentService calls this method from the default worker thread with
	   * the intent that started the service. When this method returns, IntentService
	   * stops the service, as appropriate.
	   */
	  protected void onHandleIntent(Intent intent) {
	      Log.v("xades","Called XadesService");
	      
	      String broadcastid = intent.getStringExtra("broadcastid");
	      broadcastid = "alma";
	      //###########
	      //Crypto Core
	      //###########
	      Intent broadcast = new Intent();
	      broadcast.putExtra("result", "Success");
	      broadcast.setAction(broadcastid);
	      sendBroadcast(broadcast);
	      
	  }
	}