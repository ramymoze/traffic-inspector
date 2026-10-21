package com.trafficinspector.tunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * Starts the tunnel when the phone boots.
 *
 * Only when the user asked for it, and only when there is a server and a key
 * to connect to.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) {
            return
        }
        val prefs = context.getSharedPreferences(TunnelService.PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(TunnelService.PREF_START_ON_BOOT, false)) {
            return
        }
        val server = prefs.getString(TunnelService.PREF_SERVER, "") ?: ""
        val key = prefs.getString(TunnelService.PREF_KEY, "") ?: ""
        if (server.isEmpty() || key.isEmpty()) {
            Log.d(TunnelService.TAG, "no server to connect to, the tunnel stays off")
            return
        }
        val serviceIntent = Intent(context, TunnelService::class.java).apply {
            action = TunnelService.ACTION_START
            putExtra(TunnelService.EXTRA_SERVER, server)
            putExtra(TunnelService.EXTRA_PORT, prefs.getInt(TunnelService.PREF_PORT, 5555))
            putExtra(TunnelService.EXTRA_KEY, key)
            putExtra(
                TunnelService.EXTRA_DEVICE,
                prefs.getString(TunnelService.PREF_DEVICE, "") ?: TunnelService.defaultDevice()
            )
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            Log.d(TunnelService.TAG, "the tunnel was started after the restart")
        } catch (exc: Exception) {
            Log.d(TunnelService.TAG, "the tunnel could not be started: ${exc.message}")
        }
    }
}
