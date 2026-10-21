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
        const val EVENT_FLOW = "tunnelFlow"
        const val REQUEST_CODE = 4242
    }

    private var pendingPermission: Promise? = null

    private val prefs by lazy {
        reactApplicationContext.getSharedPreferences("TunnelConfig", Context.MODE_PRIVATE)
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
        val flows = Arguments.createArray()
        TunnelService.flows.forEach { flows.pushMap(Arguments.makeNativeMap(it.toMap())) }
        result.putArray("flows", flows)
        promise.resolve(result)
    }

    /** The settings of the tunnel, they should survive a restart. */
    @ReactMethod
    fun getConfig(promise: Promise) {
        val result = Arguments.createMap()
        result.putString("server", prefs.getString("server", "") ?: "")
        result.putInt("port", prefs.getInt("port", 5555))
        result.putString("key", prefs.getString("key", "") ?: "")
        result.putString("device", prefs.getString("device", "") ?: "")
        promise.resolve(result)
    }

    @ReactMethod
    fun setConfig(server: String, port: Int, key: String, device: String, promise: Promise) {
        prefs.edit()
            .putString("server", server)
            .putInt("port", port)
            .putString("key", key)
            .putString("device", device)
            .apply()
        promise.resolve(true)
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

    override fun onFlow(flow: TunnelService.FlowInfo) {
        send(EVENT_FLOW, flow.toMap())
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
