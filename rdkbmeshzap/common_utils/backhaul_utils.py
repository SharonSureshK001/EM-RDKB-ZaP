# If not stated otherwise in this file or this component LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import math
import os
import re
import shlex
import time

import pytest
from scapy.all import Ether
from scapy.all import rdpcap

from rdkbmeshzap.common_utils import report_logger


def _env(name, default):
    """Return an environment override or the default."""
    return os.environ.get(name, default)


def _env_float(name, default):
    """Return a positive finite float from the environment or the default."""
    value = float(os.environ.get(name, default))
    assert math.isfinite(value) and value > 0, f"Invalid {name}: {value}"
    return value


# Environment-specific values can be overridden with EM_* variables.
BACKHAUL_AKM_PARAMETER = _env(
    "EM_BACKHAUL_AKM_PARAMETER",
    "Device.WiFi.DataElements.Network.Device.1.Radio.1.BSS.1.BackhaulAKMsAllowed",
)

AGENT = _env("EM_AGENT", "extender1")
CONTROLLER = _env("EM_CONTROLLER", "controller")

DOWN_WAIT_SECONDS = _env_float("EM_DOWN_WAIT_SECONDS", 10)
RECONNECT_TIMEOUT_SECONDS = _env_float("EM_RECONNECT_TIMEOUT", 120)
RECONNECT_POLL_SECONDS = _env_float("EM_RECONNECT_POLL", 5)

EAPOL_CAPTURE_FILTER = "ether proto 0x888e"
ETHERTYPE_EAPOL = 0x888E
EAPOL_TYPE_KEY = 3


def get_backhaul_interface(initialize, agent=AGENT):
    """
    Resolve backhaul interface from runtime database.
    EM_BACKHAUL_IFACE may be used as an explicit override.
    """
    override = os.getenv("EM_BACKHAUL_IFACE")

    if override:
        return override.strip()

    iface = initialize.read_from_database(
        agent,
        "backhaul_interface"
    )

    assert iface and str(iface).strip(), (
        f"{agent}: backhaul_interface not available"
    )

    return str(iface).strip()


def get_expected_ssid(initialize):
    """Return the controller's configured backhaul SSID."""

    expected_ssid = initialize.read_from_database(
        CONTROLLER,
        "mesh_backhaul_ssid"
    )

    assert isinstance(expected_ssid, str) and expected_ssid.strip(), (
        "controller.mesh_backhaul_ssid must be configured"
    )

    return expected_ssid.strip()


def get_agent_ip(initialize):
    """Return the agent's bridge IP."""

    agent_ip = initialize.read_from_database(
        AGENT,
        "bridge_ip"
    )

    assert isinstance(agent_ip, str) and agent_ip.strip(), (
        f"{AGENT}.bridge_ip must be configured"
    )

    return agent_ip.strip()


def verify_backhaul_association(initialize, agent):
    """Verify association to the expected backhaul SSID."""

    backhaul_iface = get_backhaul_interface(
        initialize,
        agent
    )

    expected_ssid = get_expected_ssid(initialize)

    assert initialize.get_wireless_backhaul_connection_status(
        agent,
        backhaul_iface,
    ), (
        f"{agent}: Agent is not connected on "
        f"{backhaul_iface}"
    )

    _, ssid = initialize.get_backhaul_link_details(
        agent,
        backhaul_iface,
    )

    assert ssid is not None, (
        f"{agent}: SSID not found in link output"
    )

    assert ssid == expected_ssid, (
        f"{agent}: Agent is not connected to expected "
        f"SSID {expected_ssid!r}; got {ssid!r}"
    )

    return initialize.get_iw_dev_link_info(
        agent,
        backhaul_iface,
    )


def verify_link_metrics(output):
    """Verify signal strength, frequency and transmit bitrate."""

    signal = re.search(
        r"^\s*signal:\s*(-?\d+(?:\.\d+)?)\s+dBm\b",
        output,
        re.MULTILINE,
    )

    frequency = re.search(
        r"^\s*freq:\s*(\d+(?:\.\d+)?)",
        output,
        re.MULTILINE,
    )

    tx_bitrate = re.search(
        r"^\s*tx bitrate:\s*(\d+(?:\.\d+)?)",
        output,
        re.MULTILINE,
    )

    assert signal, (
        f"Signal strength information missing:\n{output}"
    )

    assert frequency and float(frequency.group(1)) > 0, (
        f"Frequency information missing:\n{output}"
    )

    assert tx_bitrate and float(tx_bitrate.group(1)) > 0, (
        f"Transmit bitrate information missing:\n{output}"
    )


def verify_controller_connectivity(initialize, agent):
    """Verify controller reachability."""

    controller_ip = initialize.read_from_database(
        CONTROLLER,
        "bridge_ip"
    )

    assert isinstance(controller_ip, str) and controller_ip.strip(), (
        "controller.bridge_ip must be configured"
    )

    ping_output = initialize.execute_command(
        agent,
        f"ping -c 4 -W 2 {shlex.quote(controller_ip.strip())}"
    )

    assert (
        "0% packet loss" in ping_output
        or "4 packets transmitted, 4 received" in ping_output
        or "4 received" in ping_output
    ), f"Controller-Agent connectivity failed:\n{ping_output}"


def wait_for_reconnect(
    initialize,
    expected_ssid,
    agent=AGENT
):
    """Wait for successful backhaul reconnection."""

    backhaul_iface = get_backhaul_interface(
        initialize,
        agent
    )

    deadline = time.monotonic() + RECONNECT_TIMEOUT_SECONDS
    last_state = "no link information"

    while time.monotonic() < deadline:

        try:
            bssid, ssid = initialize.get_backhaul_link_details(
                agent,
                backhaul_iface,
            )

        except Exception as exc:

            last_state = (
                f"command temporarily unavailable: {exc}"
            )

            report_logger.print_info(
                f"{agent}: {last_state}"
            )

        else:

            last_state = (
                f"bssid={bssid}, ssid={ssid}"
            )

            if bssid and ssid == expected_ssid:
                return bssid, ssid

        time.sleep(RECONNECT_POLL_SECONDS)

    pytest.fail(
        f"{agent}: Backhaul did not reconnect within "
        f"{RECONNECT_TIMEOUT_SECONDS:g} seconds.\n\n"
        f"Last link state: {last_state}"
    )


def count_eapol_key_frames(pcap_path):
    """Count EAPOL-Key frames."""

    count = 0

    for pkt in rdpcap(pcap_path):

        if not pkt.haslayer(Ether):
            continue

        if pkt[Ether].type != ETHERTYPE_EAPOL:
            continue

        payload = bytes(pkt[Ether].payload)

        if len(payload) >= 2 and payload[1] == EAPOL_TYPE_KEY:
            count += 1

    return count


def verify_eapol_handshake(pcap_path):
    """
    Verify EAPOL authentication activity following reassociation.
    """

    frame_count = count_eapol_key_frames(
        pcap_path
    )

    report_logger.print_info(
        f"Captured EAPOL-Key frames in "
        f"{pcap_path}: {frame_count}"
    )

    assert frame_count >= 2, (
        "Expected a complete EAPOL authentication "
        f"exchange after reassociation. "
        f"Found {frame_count} frame(s)."
    )

    return frame_count

