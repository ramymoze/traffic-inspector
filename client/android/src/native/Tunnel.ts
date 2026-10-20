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
