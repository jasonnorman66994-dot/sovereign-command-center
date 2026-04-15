const fs = require('fs');
const path = require('path');

function loadDashboardHarness() {
    const html_path = path.resolve(__dirname, '..', '..', 'dashboard', 'index.html');
    const html = fs.readFileSync(html_path, 'utf8');
    const script_match = html.match(/<script>([\s\S]*)<\/script>\s*<\/body>/i);

    if(!script_match)
    {
        throw new Error('Dashboard script block not found');
    }

    window.__SHADOW_DASHBOARD_TEST__ = true;
    document.open();
    document.write(html.replace(/<script>[\s\S]*<\/script>\s*<\/body>/i, '</body>'));
    document.close();
    window.eval(script_match[1]);

    return window.__shadowDashboardTestHooks;
}

describe('dashboard index regression harness', () => {
    let hooks;

    beforeAll(() => {
        global.WebSocket = class FakeWebSocket {
            constructor(url) {
                this.url = url;
                this.readyState = 1;
            }

            close() {
                this.readyState = 3;
            }
        };

        hooks = loadDashboardHarness();
    });

    beforeEach(() => {
        jest.restoreAllMocks();
        global.fetch = jest.fn();
        sessionStorage.clear();
        localStorage.clear();

        document.getElementById('console').innerHTML = '';
        document.getElementById('business-filter').innerHTML = '<option value="all">All Targets</option>';
        document.getElementById('business-filter').disabled = false;
        document.getElementById('auth-status').textContent = '';
        document.getElementById('auth-status').className = 'status-line';
        document.getElementById('business-status').textContent = '';
        document.getElementById('business-status').className = 'status-line';
        document.getElementById('telemetry-status').textContent = 'Telemetry pipeline: waiting for data...';
        document.getElementById('telemetry-status').className = 'status-line';
        document.getElementById('system-check-banner').textContent = 'reset';

        hooks.setAuthConfig({ auth_mode: 'legacy', oidc_enabled: false });
        hooks.setAccessToken('');
        hooks.setTelemetryAdvance(0, null);
        hooks.resetRealtimeState('Telemetry pipeline: waiting for data...');
    });

    test('clears the session and disables protected controls after a target auth failure', async () => {
        hooks.setAuthConfig({
            auth_mode: 'oidc',
            oidc_enabled: true,
            authorize_url: 'http://localhost:8080/auth',
        });
        hooks.setAccessToken('shadow-test-token');

        global.fetch.mockResolvedValue({
            ok: false,
            status: 401,
            json: async () => ({ detail: 'unauthorized' }),
        });

        await hooks.loadBusinessTargets();

        expect(hooks.getAccessToken()).toBe('');
        expect(document.getElementById('auth-status')).toHaveTextContent('Business targets require login.');
        expect(document.getElementById('telemetry-status')).toHaveTextContent('Telemetry pipeline: login required');
        expect(document.getElementById('business-status')).toHaveTextContent('Business targets unavailable until you log in.');
        expect(document.getElementById('oidc-login-btn')).not.toBeDisabled();
        expect(document.getElementById('logout-btn')).toBeDisabled();
        expect(document.getElementById('business-filter')).toBeDisabled();
    });

    test('classifies telemetry as stale when frames stop advancing beyond the freshness threshold', () => {
        const now = 1_700_000_000_000;
        jest.spyOn(Date, 'now').mockReturnValue(now);

        hooks.setTelemetryAdvance(now - 120_000, 'evt-17');

        const summary = hooks.summarizeTelemetryHealth({
            ws_telemetry_last_event_id: 'evt-17',
            ws_telemetry_frames_sent: 14,
            ws_telemetry_errors: 0,
        }, 42);

        expect(summary.level).toBe('warn');
        expect(summary.freshness).toBe('stale(120s)');
        expect(summary.lastId).toBe('evt-17');
        expect(summary.total).toBe(42);
    });

    test('renders the auth-required banner when health endpoints return 401', async () => {
        hooks.setAccessToken('shadow-test-token');
        global.fetch
            .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({}) })
            .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({}) });

        await hooks.runSystemCheck();

        expect(document.getElementById('system-check-banner')).toHaveTextContent('AUTH REQUIRED: OIDC SESSION EXPIRED OR MISSING');
    });

    test('supports pausing, stepping, and resuming scenario replay', () => {
        jest.useFakeTimers();

        try {
            hooks.renderScenarioReplayConsole('SCENARIO_13_ZERO_DAY_EXPLOIT');

            jest.advanceTimersByTime(0);
            expect(document.getElementById('console').childElementCount).toBe(1);
            expect(hooks.getReplayState()).toMatchObject({
                scenario: 'SCENARIO_13_ZERO_DAY_EXPLOIT',
                nextIndex: 1,
                paused: false,
                completed: false,
            });

            hooks.toggleScenarioReplayPause();
            jest.advanceTimersByTime(1000);
            expect(document.getElementById('console').childElementCount).toBe(1);
            expect(hooks.getReplayState().paused).toBe(true);

            hooks.stepScenarioReplay();
            expect(document.getElementById('console').childElementCount).toBe(2);
            expect(hooks.getReplayState()).toMatchObject({
                nextIndex: 2,
                paused: true,
                completed: false,
            });

            hooks.toggleScenarioReplayPause();
            jest.advanceTimersByTime(420);
            expect(document.getElementById('console').childElementCount).toBe(3);
            expect(hooks.getReplayState().paused).toBe(false);
        } finally {
            jest.runOnlyPendingTimers();
            jest.useRealTimers();
        }
    });

    test('renders Scenario 16 replay status as terminal identity-collapse messaging', () => {
        jest.useFakeTimers();

        try {
            document.getElementById('scenario-detail').innerHTML = '<div id="scenario-replay-status" class="copy-status"></div>';
            hooks.renderScenarioReplayConsole('SCENARIO_16_OIDC_SIGNING_KEY_THEFT');

            expect(hooks.getReplayStatusText()).toContain('Identity extinction replay 0/13');

            jest.advanceTimersByTime(0);
            expect(hooks.getReplayStatusText()).toContain('Identity extinction replay 1/13');

            hooks.toggleScenarioReplayPause();
            expect(hooks.getReplayStatusText()).toContain('Forged trust remains the active failure mode');
        } finally {
            jest.runOnlyPendingTimers();
            jest.useRealTimers();
        }
    });
});