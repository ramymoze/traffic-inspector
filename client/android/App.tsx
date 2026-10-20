/**
 * The traffic inspector.
 *
 * The screen is the whole user interface: the settings of the tunnel and
 * the list of the flows the device is making right now.
 */

import React from 'react';
import { SafeAreaView, StatusBar, StyleSheet } from 'react-native';
import ConnectScreen from './src/screens/ConnectScreen';
import { theme } from './src/theme';

export default function App() {
  return (
    <SafeAreaView style={styles.safe}>
      <StatusBar barStyle="light-content" backgroundColor={theme.background} />
      <ConnectScreen />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: theme.background,
  },
});
