"""Shared engine control state for kill-switch and manual resume."""

import threading

# Thread-safe event controlling whether outbound pulse activity is allowed.
pulse_active = threading.Event()
pulse_active.set()


def is_pulse_active() -> bool:
    return pulse_active.is_set()


def halt_pulse_engine() -> None:
    pulse_active.clear()


def resume_pulse_engine() -> None:
    pulse_active.set()
