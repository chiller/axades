package org.axades.service;

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
	      //###########
	      //A broadcast uzenet létrehozása
	      Intent broadcast = new Intent();
	      broadcast.putExtra("result", "Success");
	      broadcast.setAction(broadcastid);
	      sendBroadcast(broadcast);
	      
	      return;  
	  }
	}