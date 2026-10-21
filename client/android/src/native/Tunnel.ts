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

export interface FlowInfo {
  flowId: number;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  proto: string;
  service: string;
  bytesUp: number;
  bytesDown: number;
  state: string;
  at: string;
}

export interface TunnelStatus {
  state: TunnelState;
  message: string;
  device: string;
  flows: FlowInfo[];
}

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

  onStateChanged(
    callback: (state: TunnelState, message: string) => void,
  ): EmitterSubscription {
    return emitter.addListener('tunnelState', (event: any) =>
      callback(event.state, event.message),
    );
  },

  onFlow(callback: (flow: FlowInfo) => void): EmitterSubscription {
    return emitter.addListener('tunnelFlow', (event: any) => callback(event));
  },
};
