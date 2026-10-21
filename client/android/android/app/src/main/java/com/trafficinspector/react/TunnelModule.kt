package com.trafficinspector.react

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import com.trafficinspector.tunnel.TunnelService

/**
 * The bridge between the user interface and the tunnel.
 *
 * The user interface may die at any time, the tunnel must not.  Everything
 * here is a thin layer: the service does the work, this module only starts
 * it and reports what it says.
 */
class TunnelModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext), TunnelService.Listener {

    companion object {
        const val NAME = "Tunnel"
        const val EVENT_STATE = "tunnelState"
        const val REQUEST_CODE = 4242
    }

    private var pendingPermission: Promise? = null

    private val prefs by lazy {
        reactApplicationContext.getSharedPreferences(TunnelService.PREFS, Context.MODE_PRIVATE)
    }

    init {
        TunnelService.listeners.add(this)
    }

    override fun getName(): String = NAME

    override fun invalidate() {
        TunnelService.listeners.remove(this)
        super.invalidate()
    }

    /**
     * Ask the system for the permission to run a VPN.
     *
     * Resolves with true when the permission is already there, false when
     * the user still has to confirm it.
     */
    @ReactMethod
    fun prepare(promise: Promise) {
        val activity = currentActivity
        if (activity == null) {
            promise.reject("no_activity", "the screen is not there any more")
            return
        }
        val intent = VpnService.prepare(activity)
        if (intent == null) {
            promise.resolve(true)
            return
        }
        pendingPermission = promise
        try {
            activity.startActivityForResult(intent, REQUEST_CODE)
        } catch (exc: Exception) {
            pendingPermission = null
            promise.reject("no_permission", exc.message)
        }
    }

    /** The result of the permission dialog. */
    fun onPermissionResult(resultCode: Int) {
        val promise = pendingPermission ?: return
        pendingPermission = null
        promise.resolve(resultCode == android.app.Activity.RESULT_OK)
    }

    @ReactMethod
    fun start(server: String, port: Int, keyHex: String, device: String, promise: Promise) {
        val activity = currentActivity
        if (activity == null) {
            promise.reject("no_activity", "the screen is not there any more")
            return
        }
        val intent = VpnService.prepare(activity)
        if (intent != null) {
            promise.reject("no_permission", "the permission for the tunnel is missing")
            return
        }
        try {
            val serviceIntent = Intent(activity, TunnelService::class.java).apply {
                action = TunnelService.ACTION_START
                putExtra(TunnelService.EXTRA_SERVER, server)
                putExtra(TunnelService.EXTRA_PORT, port)
                putExtra(TunnelService.EXTRA_KEY, keyHex)
                putExtra(TunnelService.EXTRA_DEVICE, device)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                activity.startForegroundService(serviceIntent)
            } else {
                activity.startService(serviceIntent)
            }
            promise.resolve(true)
        } catch (exc: Exception) {
            promise.reject("cannot_start", exc.message)
        }
    }

    @ReactMethod
    fun stop(promise: Promise) {
        val activity = currentActivity
        val context = reactApplicationContext
        try {
            val intent = Intent(context, TunnelService::class.java).apply {
                action = TunnelService.ACTION_STOP
            }
            if (activity != null) {
                activity.startService(intent)
            } else {
                context.startService(intent)
            }
            promise.resolve(true)
        } catch (exc: Exception) {
            promise.reject("cannot_stop", exc.message)
        }
    }

    /** What the tunnel is doing right now. */
    @ReactMethod
    fun status(promise: Promise) {
        val result = Arguments.createMap()
        result.putString("state", TunnelService.state)
        result.putString("message", TunnelService.message)
        result.putString("device", TunnelService.device)
        promise.resolve(result)
    }

    /** A name for this device, so the report can tell the devices apart. */
    @ReactMethod
    fun defaultDevice(promise: Promise) {
        promise.resolve(TunnelService.defaultDevice())
    }

    /** The settings of the tunnel, they should survive a restart. */
    @ReactMethod
    fun getConfig(promise: Promise) {
        val result = Arguments.createMap()
        result.putString("server", prefs.getString(TunnelService.PREF_SERVER, "") ?: "")
        result.putInt("port", prefs.getInt(TunnelService.PREF_PORT, 5555))
        result.putString("key", prefs.getString(TunnelService.PREF_KEY, "") ?: "")
        result.putString("device", prefs.getString(TunnelService.PREF_DEVICE, "") ?: "")
        result.putBoolean(
            "startOnBoot",
            prefs.getBoolean(TunnelService.PREF_START_ON_BOOT, false)
        )
        promise.resolve(result)
    }

    @ReactMethod
    fun setConfig(server: String, port: Int, key: String, device: String, promise: Promise) {
        prefs.edit()
            .putString(TunnelService.PREF_SERVER, server)
            .putInt(TunnelService.PREF_PORT, port)
            .putString(TunnelService.PREF_KEY, key)
            .putString(TunnelService.PREF_DEVICE, device)
            .apply()
        promise.resolve(true)
    }

    /** Should the tunnel come up by itself after a restart of the phone? */
    @ReactMethod
    fun setStartOnBoot(enabled: Boolean, promise: Promise) {
        prefs.edit().putBoolean(TunnelService.PREF_START_ON_BOOT, enabled).apply()
        promise.resolve(true)
    }

    /**
     * The report of the traffic the server has seen.
     *
     * The file with the traffic is on the server, so the phone asks for the
     * report and the server sends it back.
     */
    @ReactMethod
    fun getReport(promise: Promise) {
        if (TunnelService.state != "connected") {
            promise.reject("no_tunnel", "the tunnel is not up, there is no report yet")
            return
        }
        val before = TunnelService.reportVersion
        try {
            val intent = Intent(reactApplicationContext, TunnelService::class.java).apply {
                action = TunnelService.ACTION_REPORT
            }
            reactApplicationContext.startService(intent)
        } catch (exc: Exception) {
            promise.reject("cannot_ask", exc.message)
            return
        }
        // the answer comes in pieces, the thread waits for the last one
        Thread({
            val deadline = System.currentTimeMillis() + 30000
            while (System.currentTimeMillis() < deadline) {
                if (TunnelService.reportVersion != before) {
                    promise.resolve(TunnelService.report)
                    return@Thread
                }
                try {
                    Thread.sleep(150)
                } catch (ignored: InterruptedException) {
                    promise.reject("interrupted", "the wait was stopped")
                    return@Thread
                }
            }
            promise.reject("no_report", "the server did not send the report in time")
        }, "report-waiter").start()
    }

    @ReactMethod
    fun addListener(eventName: String) {
        // the events are sent from the service, nothing to do here
    }

    @ReactMethod
    fun removeListeners(count: Int) {
        // the events are sent from the service, nothing to do here
    }

    // -- the events --------------------------------------------------------
    override fun onStateChanged(state: String, message: String) {
        val payload: WritableMap = Arguments.createMap()
        payload.putString("state", state)
        payload.putString("message", message)
        send(EVENT_STATE, payload)
    }

    private fun send(event: String, payload: Any) {
        val context = reactApplicationContext
        if (!context.hasActiveReactInstance()) return
        val map = toWritable(payload) ?: return
        context
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(event, map)
    }

    /** Turn what the service reports into something the javascript understands. */
    private fun toWritable(payload: Any): WritableMap? {
        if (payload is WritableMap) return payload
        if (payload !is Map<*, *>) return null
        val writable = Arguments.createMap()
        for ((key, value) in payload) {
            val name = key as? String ?: continue
            when (value) {
                is String -> writable.putString(name, value)
                is Int -> writable.putInt(name, value)
                is Double -> writable.putDouble(name, value)
                is Boolean -> writable.putBoolean(name, value)
                else -> writable.putString(name, value.toString())
            }
        }
        return writable
    }
}
