/**
 * The native module of the tunnel does not exist in a test.
 *
 * The screen only asks it for the settings, the state and the report, so
 * a mock that answers is enough to see that the screen renders.
 */

jest.mock('./src/native/Tunnel', () => ({
  Tunnel: {
    prepare: jest.fn().mockResolvedValue(true),
    start: jest.fn().mockResolvedValue(true),
    stop: jest.fn().mockResolvedValue(true),
    status: jest.fn().mockResolvedValue({
      state: 'idle',
      message: '',
      device: 'phone',
    }),
    getConfig: jest.fn().mockResolvedValue({
      server: '',
      port: 5555,
      key: '',
      device: 'phone',
      startOnBoot: false,
    }),
    setConfig: jest.fn().mockResolvedValue(true),
    setStartOnBoot: jest.fn().mockResolvedValue(true),
    defaultDevice: jest.fn().mockResolvedValue('phone'),
    getReport: jest.fn().mockResolvedValue('NOTHING TO WORRY ABOUT'),
    onStateChanged: jest.fn().mockReturnValue({ remove: jest.fn() }),
  },
}));
