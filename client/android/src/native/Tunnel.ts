import {
  NativeEventEmitter,
  NativeModules,
  EmitterSubscription,
} from 'react-native';

const { Tunnel: NativeTunnel } = NativeModules;

export type TunnelState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'error'
  | 'stopped';

export interface TunnelConfig {
  server: string;
  port: number;
  keyHex: string;
  device: string;
}

/** What the app remembers between two starts. */
export interface SavedConfig {
  server: string;
  port: number;
  key: string;
  device: string;
  startOnBoot: boolean;
}

export interface TunnelStatus {
  state: TunnelState;
  message: string;
  device: string;
}

const emitter = new NativeEventEmitter(NativeTunnel);

export const Tunnel = {
  /**
   * Ask for the permission to run a VPN.
   *
   * Resolves with true when the permission is already there, false when the
   * user still has to confirm it in the dialog of the system.
   */
  prepare(): Promise<boolean> {
    return NativeTunnel.prepare();
  },

  start(config: TunnelConfig): Promise<boolean> {
    return NativeTunnel.start(
      config.server,
      config.port,
      config.keyHex,
      config.device,
    );
  },

  stop(): Promise<boolean> {
    return NativeTunnel.stop();
  },

  status(): Promise<TunnelStatus> {
    return NativeTunnel.status();
  },

  /** The settings of the tunnel, they survive a restart of the app. */
  getConfig(): Promise<SavedConfig> {
    return NativeTunnel.getConfig();
  },

  setConfig(config: SavedConfig): Promise<boolean> {
    return NativeTunnel.setConfig(
      config.server,
      config.port,
      config.key,
      config.device,
    );
  },

  /** Should the tunnel come up by itself after a restart of the phone? */
  setStartOnBoot(enabled: boolean): Promise<boolean> {
    return NativeTunnel.setStartOnBoot(enabled);
  },

  /** A name for this device, so the report can tell the devices apart. */
  defaultDevice(): Promise<string> {
    return NativeTunnel.defaultDevice();
  },

  onStateChanged(
    callback: (state: TunnelState, message: string) => void,
  ): EmitterSubscription {
    return emitter.addListener('tunnelState', (event: any) =>
      callback(event.state, event.message),
    );
  },
};
