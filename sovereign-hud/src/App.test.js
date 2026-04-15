import { render, screen } from '@testing-library/react';
import App from './App';

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  global.fetch = jest.fn();
});

test('renders the login overlay when no auth token is present', async () => {
  render(<App />);
  expect(screen.getByText(/initializing hud/i)).toBeInTheDocument();
  expect(await screen.findByText(/sovereign identity gate/i)).toBeInTheDocument();
  expect(screen.getByText(/status: auth check required/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /run auth check/i })).toBeInTheDocument();
});

test('renders the authenticated HUD when a valid token is present', async () => {
  sessionStorage.setItem('shadow.access_token', 'shadow-test-token');
  global.fetch.mockResolvedValue({
    ok: true,
    json: async () => ({ channels: { slack: true } }),
  });

  render(<App />);

  expect(await screen.findByText(/authenticated: operator lvl 3/i)).toBeInTheDocument();
  expect(screen.getByText(/arp detector/i)).toBeInTheDocument();
  expect(screen.getByText(/collector and websocket bridge operational/i)).toBeInTheDocument();
});
