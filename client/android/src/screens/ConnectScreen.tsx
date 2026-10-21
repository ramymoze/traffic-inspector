import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActivityIndicator,
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { theme } from '../theme';
import { FlowInfo, Tunnel, TunnelState } from '../native/Tunnel';

function human(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

const STATE_COLORS: Record<TunnelState, string> = {
  idle: theme.textFaint,
  connecting: theme.warn,
  connected: theme.ok,
  error: theme.error,
  stopped: theme.textFaint,
};

const STATE_TEXT: Record<TunnelState, string> = {
  idle: 'not connected',
  connecting: 'connecting',
  connected: 'connected',
  error: 'error',
  stopped: 'stopped',
};

function Field(props: {
  label: string;
  value: string;
  onChangeText: (text: string) => void;
  placeholder?: string;
  secure?: boolean;
  keyboardType?: 'default' | 'numeric';
  hint?: string;
}) {
  const [hidden, setHidden] = useState(Boolean(props.secure));
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{props.label}</Text>
      <View style={styles.inputRow}>
        <TextInput
          style={styles.input}
          value={props.value}
          onChangeText={props.onChangeText}
          placeholder={props.placeholder}
          placeholderTextColor={theme.textFaint}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType={props.keyboardType ?? 'default'}
          secureTextEntry={Boolean(props.secure) && hidden}
        />
        {props.secure ? (
          <Pressable onPress={() => setHidden(!hidden)} style={styles.reveal}>
            <Text style={styles.revealText}>{hidden ? 'show' : 'hide'}</Text>
          </Pressable>
        ) : null}
      </View>
      {props.hint ? <Text style={styles.hint}>{props.hint}</Text> : null}
    </View>
  );
}

function FlowRow(props: { flow: FlowInfo }) {
  const { flow } = props;
  const color = flow.proto === 'UDP' ? theme.udp : theme.tcp;
  return (
    <View style={styles.flow}>
      <View style={styles.flowTop}>
        <Text style={[styles.proto, { color }]}>{flow.proto}</Text>
        <Text style={styles.destination} numberOfLines={1}>
          {flow.dstIp}:{flow.dstPort}
        </Text>
        <Text style={styles.service}>{flow.service}</Text>
        <Text style={styles.time}>{flow.at}</Text>
      </View>
      <View style={styles.flowBottom}>
        <Text style={styles.source} numberOfLines={1}>
          from {flow.srcIp}:{flow.srcPort}
        </Text>
        <Text style={styles.bytes}>
          ↑ {human(flow.bytesUp)}  ↓ {human(flow.bytesDown)}
        </Text>
      </View>
    </View>
  );
}

export default function ConnectScreen() {
  const [server, setServer] = useState('');
  const [port, setPort] = useState('5555');
  const [key, setKey] = useState('');
  const [device, setDevice] = useState('phone-android');
  const [state, setState] = useState<TunnelState>('idle');
  const [message, setMessage] = useState('');
  const [flows, setFlows] = useState<FlowInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const keyInput = useRef<TextInput>(null);

  useEffect(() => {
    const stateSub = Tunnel.onStateChanged((newState, newMessage) => {
      setState(newState);
      setMessage(newMessage);
    });
    const flowSub = Tunnel.onFlow(flow => {
      setFlows(current => [flow, ...current].slice(0, 100));
    });
    Tunnel.status()
      .then(status => {
        setState(status.state);
        setMessage(status.message);
        setFlows(status.flows ?? []);
      })
      .catch(() => undefined);
    Tunnel.getConfig()
      .then(config => {
        if (config?.server) {
          setServer(config.server);
        }
        if (config?.port) {
          setPort(String(config.port));
        }
        if (config?.key) {
          setKey(config.key);
        }
        if (config?.device) {
          setDevice(config.device);
        }
      })
      .catch(() => undefined);
    return () => {
      stateSub.remove();
      flowSub.remove();
    };
  }, []);

  // remember the settings, so the key does not have to be typed again
  useEffect(() => {
    const timer = setTimeout(() => {
      Tunnel.setConfig({
        server,
        port: parseInt(port, 10) || 5555,
        key,
        device,
      }).catch(() => undefined);
    }, 500);
    return () => clearTimeout(timer);
  }, [server, port, key, device]);

  const connected = state === 'connected' || state === 'connecting';

  const onConnect = useCallback(async () => {
    setBusy(true);
    try {
      const ready = await Tunnel.prepare();
      if (!ready) {
        setState('idle');
        setMessage('the permission was not given');
        setBusy(false);
        return;
      }
      await Tunnel.start({
        server: server.trim(),
        port: parseInt(port, 10) || 5555,
        keyHex: key.trim(),
        device: device.trim() || 'android',
      });
    } catch (error: any) {
      setState('error');
      setMessage(String(error?.message ?? error));
    } finally {
      setBusy(false);
    }
  }, [server, port, key, device]);

  const onDisconnect = useCallback(async () => {
    setBusy(true);
    try {
      await Tunnel.stop();
    } catch (error: any) {
      setMessage(String(error?.message ?? error));
    } finally {
      setBusy(false);
    }
  }, []);

  const header = useMemo(
    () => (
      <View>
        <View style={styles.hero}>
          <Text style={styles.title}>Traffic Inspector</Text>
          <Text style={styles.subtitle}>
            the traffic of this device goes through your server
          </Text>
        </View>

        <View style={styles.card}>
          <View style={styles.statusRow}>
            <View
              style={[
                styles.dot,
                { backgroundColor: STATE_COLORS[state] ?? theme.textFaint },
              ]}
            />
            <Text style={styles.statusText}>{STATE_TEXT[state] ?? state}</Text>
            <View style={styles.spacer} />
            {state === 'connecting' ? (
              <ActivityIndicator size="small" color={theme.warn} />
            ) : null}
          </View>
          {message ? <Text style={styles.message}>{message}</Text> : null}

          <Field
            label="server"
            value={server}
            onChangeText={setServer}
            placeholder="the address of your server"
          />
          <View style={styles.row}>
            <View style={styles.rowItem}>
              <Field
                label="port"
                value={port}
                onChangeText={setPort}
                keyboardType="numeric"
                placeholder="5555"
              />
            </View>
            <View style={styles.rowItem}>
              <Field
                label="name of the device"
                value={device}
                onChangeText={setDevice}
                placeholder="phone-android"
              />
            </View>
          </View>
          <Field
            label="master key"
            value={key}
            onChangeText={setKey}
            placeholder="the shared secret of the server"
            secure
            hint="the same key the server has, 64 characters"
          />

          <Pressable
            style={[
              styles.button,
              connected ? styles.buttonOff : styles.buttonOn,
              busy ? styles.buttonBusy : null,
            ]}
            onPress={connected ? onDisconnect : onConnect}
            disabled={busy}>
            <Text style={styles.buttonText}>
              {connected ? 'stop the tunnel' : 'start the tunnel'}
            </Text>
          </Pressable>
        </View>

        <Text style={styles.sectionTitle}>
          the traffic right now{flows.length ? ` (${flows.length})` : ''}
        </Text>
      </View>
    ),
    [state, message, server, port, key, device, busy, connected, flows.length],
  );

  return (
    <KeyboardAvoidingView
      style={styles.screen}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <StatusBar barStyle="light-content" backgroundColor={theme.background} />
      <FlatList
        data={flows}
        keyExtractor={item => `${item.flowId}-${item.at}-${item.dstIp}`}
        renderItem={({ item }) => <FlowRow flow={item} />}
        ListHeaderComponent={header}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyText}>
              nothing yet — the flows of the device show up here
            </Text>
          </View>
        }
        contentContainerStyle={styles.content}
      />
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: theme.background,
  },
  content: {
    padding: 20,
    paddingBottom: 48,
  },
  hero: {
    marginBottom: 22,
    marginTop: 12,
  },
  title: {
    color: theme.text,
    fontSize: 30,
    fontWeight: '700',
    letterSpacing: -0.5,
  },
  subtitle: {
    color: theme.textDim,
    fontSize: 14,
    marginTop: 6,
  },
  card: {
    backgroundColor: theme.surface,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: theme.border,
    padding: 18,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
  },
  dot: {
    width: 9,
    height: 9,
    borderRadius: 5,
    marginRight: 9,
  },
  statusText: {
    color: theme.text,
    fontSize: 15,
    fontWeight: '600',
  },
  spacer: {
    flex: 1,
  },
  message: {
    color: theme.textDim,
    fontSize: 13,
    marginBottom: 14,
  },
  field: {
    marginTop: 12,
  },
  label: {
    color: theme.textFaint,
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: 1,
    marginBottom: 6,
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  input: {
    flex: 1,
    backgroundColor: theme.surfaceHigh,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: theme.border,
    color: theme.text,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 15,
    fontFamily: theme.mono,
  },
  reveal: {
    paddingHorizontal: 12,
    paddingVertical: 10,
  },
  revealText: {
    color: theme.accent,
    fontSize: 13,
  },
  hint: {
    color: theme.textFaint,
    fontSize: 11,
    marginTop: 5,
  },
  row: {
    flexDirection: 'row',
    marginTop: 4,
  },
  rowItem: {
    flex: 1,
    marginRight: 10,
  },
  button: {
    marginTop: 20,
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  buttonOn: {
    backgroundColor: theme.accent,
  },
  buttonOff: {
    backgroundColor: theme.surfaceHigh,
    borderWidth: 1,
    borderColor: theme.error,
  },
  buttonBusy: {
    opacity: 0.6,
  },
  buttonText: {
    color: theme.background,
    fontSize: 15,
    fontWeight: '700',
  },
  sectionTitle: {
    color: theme.textDim,
    fontSize: 13,
    textTransform: 'uppercase',
    letterSpacing: 1,
    marginTop: 26,
    marginBottom: 10,
  },
  flow: {
    backgroundColor: theme.surface,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: theme.border,
    padding: 12,
    marginBottom: 8,
  },
  flowTop: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  proto: {
    fontSize: 11,
    fontWeight: '700',
    width: 34,
  },
  destination: {
    color: theme.text,
    fontSize: 14,
    fontFamily: theme.mono,
    flex: 1,
  },
  service: {
    color: theme.textDim,
    fontSize: 12,
    marginRight: 10,
  },
  time: {
    color: theme.textFaint,
    fontSize: 12,
    fontFamily: theme.mono,
  },
  flowBottom: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 6,
  },
  source: {
    color: theme.textFaint,
    fontSize: 11,
    fontFamily: theme.mono,
    flex: 1,
  },
  bytes: {
    color: theme.textDim,
    fontSize: 11,
    fontFamily: theme.mono,
  },
  empty: {
    padding: 24,
    borderRadius: 12,
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: theme.border,
  },
  emptyText: {
    color: theme.textFaint,
    fontSize: 13,
    textAlign: 'center',
  },
});
