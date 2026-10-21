import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { theme } from '../theme';
import { Tunnel, TunnelState } from '../native/Tunnel';

type Palette = {
  dot: string;
  card: string;
  border: string;
};

const PALETTE: Record<TunnelState, Palette> = {
  idle: {
    dot: theme.textFaint,
    card: theme.surface,
    border: theme.border,
  },
  connecting: {
    dot: theme.warn,
    card: theme.warnSoft,
    border: '#4A3D1A',
  },
  connected: {
    dot: theme.ok,
    card: theme.okSoft,
    border: '#1E4632',
  },
  error: {
    dot: theme.error,
    card: theme.errorSoft,
    border: '#4A2424',
  },
  stopped: {
    dot: theme.textFaint,
    card: theme.surface,
    border: theme.border,
  },
};

const STATE_TEXT: Record<TunnelState, string> = {
  idle: 'not connected',
  connecting: 'connecting',
  connected: 'connected',
  error: 'not connected',
  stopped: 'not connected',
};

function Field(props: {
  label: string;
  value: string;
  onChangeText: (text: string) => void;
  placeholder?: string;
  secret?: boolean;
  keyboardType?: 'default' | 'numeric';
  hint?: string;
  editable?: boolean;
}) {
  const [hidden, setHidden] = useState(Boolean(props.secret));
  const [focused, setFocused] = useState(false);

  return (
    <View style={styles.field}>
      <Text style={styles.label}>{props.label}</Text>
      <View
        style={[
          styles.inputRow,
          focused ? styles.inputRowFocused : null,
          props.editable === false ? styles.inputRowLocked : null,
        ]}>
        <TextInput
          style={styles.input}
          value={props.value}
          onChangeText={props.onChangeText}
          placeholder={props.placeholder}
          placeholderTextColor={theme.textFaint}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType={props.keyboardType ?? 'default'}
          secureTextEntry={Boolean(props.secret) && hidden}
          editable={props.editable !== false}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
        />
        {props.secret ? (
          <Pressable
            onPress={() => setHidden(!hidden)}
            style={styles.reveal}
            hitSlop={{ top: 12, bottom: 12 }}>
            <Text style={styles.revealText}>{hidden ? 'show' : 'hide'}</Text>
          </Pressable>
        ) : null}
      </View>
      {props.hint ? <Text style={styles.hint}>{props.hint}</Text> : null}
    </View>
  );
}

export default function ConnectScreen() {
  const [server, setServer] = useState('');
  const [port, setPort] = useState('5555');
  const [key, setKey] = useState('');
  const [device, setDevice] = useState('');
  const [state, setState] = useState<TunnelState>('idle');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    const subscription = Tunnel.onStateChanged((newState, newMessage) => {
      setState(newState);
      setMessage(newMessage);
    });
    Tunnel.status()
      .then(status => {
        setState(status.state);
        setMessage(status.message);
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
        } else if (!started.current) {
          Tunnel.defaultDevice().then(name => setDevice(name));
        }
      })
      .catch(() => undefined);
    return () => subscription.remove();
  }, []);

  // remember the settings, so the key does not have to be typed again
  useEffect(() => {
    const timer = setTimeout(() => {
      Tunnel.setConfig({
        server: server.trim(),
        port: parseInt(port, 10) || 5555,
        key: key.trim(),
        device: device.trim(),
      }).catch(() => undefined);
    }, 400);
    return () => clearTimeout(timer);
  }, [server, port, key, device]);

  const connected = state === 'connected';
  const working = state === 'connecting';
  const palette = PALETTE[state] ?? PALETTE.idle;

  const onConnect = useCallback(async () => {
    setBusy(true);
    setMessage('');
    try {
      const ready = await Tunnel.prepare();
      if (!ready) {
        setMessage('the permission was not given');
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

  const canStart = server.trim().length > 0 && key.trim().length > 0;

  return (
    <KeyboardAvoidingView
      style={styles.screen}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <StatusBar barStyle="light-content" backgroundColor={theme.background} />
      <ScrollView
        contentContainerStyle={styles.content}
        keyboardShouldPersistTaps="handled">
        <View style={styles.hero}>
          <Text style={styles.title}>Traffic Inspector</Text>
          <Text style={styles.subtitle}>
            put the traffic of this phone through your own server
          </Text>
        </View>

        <View
          style={[
            styles.statusCard,
            { backgroundColor: palette.card, borderColor: palette.border },
          ]}>
          <View style={styles.statusRow}>
            <View style={[styles.dot, { backgroundColor: palette.dot }]} />
            <Text style={styles.statusText}>{STATE_TEXT[state] ?? state}</Text>
            {working ? (
              <ActivityIndicator
                size="small"
                color={palette.dot}
                style={styles.statusSpinner}
              />
            ) : null}
          </View>
          {message ? (
            <Text style={styles.statusMessage} numberOfLines={3}>
              {message}
            </Text>
          ) : null}
        </View>

        <View style={styles.card}>
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
                placeholder="phone"
              />
            </View>
          </View>
          <Field
            label="master key"
            value={key}
            onChangeText={setKey}
            placeholder="the shared secret"
            secret
            hint="the same key the server has, it is in the .env file of the server"
          />
        </View>

        <Pressable
          style={[
            styles.button,
            connected ? styles.buttonStop : styles.buttonStart,
            !connected && !canStart ? styles.buttonDisabled : null,
          ]}
          onPress={connected ? onDisconnect : onConnect}
          disabled={busy || (!connected && !canStart)}>
          <Text
            style={[
              styles.buttonText,
              connected ? styles.buttonTextStop : styles.buttonTextStart,
            ]}>
            {connected
              ? 'stop the tunnel'
              : working
              ? 'connecting ...'
              : 'start the tunnel'}
          </Text>
        </Pressable>

        <Text style={styles.footer}>
          Everything this phone sends goes through your server.  The server
          writes it into a file you can read at any time.
        </Text>
      </ScrollView>
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
    marginTop: 14,
    marginBottom: 22,
  },
  title: {
    color: theme.text,
    fontSize: 28,
    fontWeight: '700',
    letterSpacing: -0.5,
  },
  subtitle: {
    color: theme.textDim,
    fontSize: 14,
    marginTop: 6,
    lineHeight: 20,
  },
  statusCard: {
    borderRadius: theme.radius,
    borderWidth: 1,
    paddingHorizontal: 16,
    paddingVertical: 14,
    marginBottom: 14,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  dot: {
    width: 9,
    height: 9,
    borderRadius: 5,
    marginRight: 10,
  },
  statusText: {
    color: theme.text,
    fontSize: 15,
    fontWeight: '600',
  },
  statusSpinner: {
    marginLeft: 10,
  },
  statusMessage: {
    color: theme.textDim,
    fontSize: 12.5,
    marginTop: 8,
    lineHeight: 18,
  },
  card: {
    backgroundColor: theme.surface,
    borderRadius: theme.radius,
    borderWidth: 1,
    borderColor: theme.border,
    padding: 16,
    paddingBottom: 10,
  },
  field: {
    marginBottom: 14,
  },
  label: {
    color: theme.textFaint,
    fontSize: 10.5,
    textTransform: 'uppercase',
    letterSpacing: 1.1,
    marginBottom: 7,
    fontWeight: '600',
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: theme.surfaceHigh,
    borderRadius: theme.radiusSmall,
    borderWidth: 1,
    borderColor: theme.border,
  },
  inputRowFocused: {
    borderColor: theme.borderFocus,
  },
  inputRowLocked: {
    opacity: 0.5,
  },
  input: {
    flex: 1,
    color: theme.text,
    paddingHorizontal: 13,
    paddingVertical: 12,
    fontSize: 15,
    fontFamily: theme.mono,
  },
  reveal: {
    paddingHorizontal: 13,
    paddingVertical: 12,
  },
  revealText: {
    color: theme.accent,
    fontSize: 13,
    fontWeight: '600',
  },
  hint: {
    color: theme.textFaint,
    fontSize: 11.5,
    marginTop: 6,
    lineHeight: 16,
  },
  row: {
    flexDirection: 'row',
    marginBottom: 0,
  },
  rowItem: {
    flex: 1,
    marginRight: 12,
  },
  button: {
    marginTop: 18,
    borderRadius: theme.radiusSmall,
    paddingVertical: 16,
    alignItems: 'center',
  },
  buttonStart: {
    backgroundColor: theme.accent,
  },
  buttonStop: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: theme.error,
  },
  buttonDisabled: {
    opacity: 0.4,
  },
  buttonText: {
    fontSize: 15.5,
    fontWeight: '700',
    letterSpacing: 0.2,
  },
  buttonTextStart: {
    color: theme.background,
  },
  buttonTextStop: {
    color: theme.error,
  },
  footer: {
    color: theme.textFaint,
    fontSize: 12,
    lineHeight: 18,
    textAlign: 'center',
    marginTop: 22,
  },
});
