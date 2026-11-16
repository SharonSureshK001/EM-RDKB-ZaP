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


import re
import time

import pytest

from rdkbmeshzap.common_utils import report_logger

AGENT = "extender1"
CONTROLLER = "controller"

BACKHAUL_IFACE = "wifi1.3"
LINK_CMD = f"iw dev {BACKHAUL_IFACE} link"

PCAP_PATH = "/tmp/backhaul_reassoc.pcap"

DOWN_WAIT_SECONDS = 10
RECONNECT_TIMEOUT_SECONDS = 120
RECONNECT_POLL_SECONDS = 5

MAC_RE = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"


def _run(initialize, device, command, check=True):
    """
    Execute a command on a device.

    Returns:
        (stdout, rc)
    """
    stdout, stderr, rc = initialize.execute_command(
        device,
        command,
        return_stderr=True,
        return_rc=True,
    )

    output = str(stdout or "")

    if check:
        assert rc == 0, (
            f"{device}: command failed\n"
            f"Command : {command}\n"
            f"RC      : {rc}\n"
            f"STDOUT  : {output}\n"
            f"STDERR  : {stderr}"
        )

    report_logger.print_info(output)

    return output, rc


def _try_run(initialize, device, command):
    """
    Execute a command that may temporarily fail
    while backhaul connectivity is unavailable.
    """
    try:
        return _run(
            initialize,
            device,
            command,
            check=False,
        )
    except Exception as exc:
        report_logger.print_info(
            f"{device}: command temporarily unavailable: {exc}"
        )
        return None, None


def _parse_link(output):
    """
    Parse output from:
        iw dev <iface> link

    Returns:
        (bssid, ssid)
    """
    if not output:
        return None, None

    connected = re.search(
        rf"^\s*Connected to ({MAC_RE})\b",
        output,
        re.MULTILINE,
    )

    ssid = re.search(
        r"^\s*SSID:\s*(.*?)\s*$",
        output,
        re.MULTILINE,
    )

    return (
        connected.group(1).lower() if connected else None,
        ssid.group(1).strip() if ssid else None,
    )


def _get_expected_ssid(initialize):
    expected_ssid = initialize.read_from_database(
        CONTROLLER,
        "mesh_backhaul_ssid",
    )

    assert isinstance(expected_ssid, str) and expected_ssid.strip(), (
        "controller.mesh_backhaul_ssid must be configured"
    )

    return expected_ssid.strip()


def _get_agent_ip(initialize):
    agent_ip = initialize.read_from_database(
        AGENT,
        "bridge_ip",
    )

    assert isinstance(agent_ip, str) and agent_ip.strip(), (
        f"{AGENT}.bridge_ip must be configured"
    )

    return agent_ip.strip()


def _wait_for_reconnect(initialize, expected_ssid):
    """
    Wait until Agent reconnects to expected
    backhaul SSID.
    """
    deadline = time.monotonic() + RECONNECT_TIMEOUT_SECONDS

    last_output = ""

    while time.monotonic() < deadline:

        output, rc = _try_run(
            initialize,
            AGENT,
            LINK_CMD,
        )

        if output is not None and rc == 0:

            last_output = output

            bssid, ssid = _parse_link(output)

            if bssid and ssid == expected_ssid:
                return bssid, output

        time.sleep(RECONNECT_POLL_SECONDS)

    pytest.fail(
        f"{AGENT}: Backhaul did not reconnect within "
        f"{RECONNECT_TIMEOUT_SECONDS} seconds.\n\n"
        f"Last link output:\n{last_output}"
    )

def _verify_eapol_handshake(dump_output):
    """
    Verify EAPOL traffic was captured after
    reassociation.
    """
    eapol_frames = [
        line
        for line in dump_output.splitlines()
        if re.search(r"EAPOL", line, re.IGNORECASE)
    ]

    report_logger.print_info(
        "Captured EAPOL Frames:\n" +
        "\n".join(eapol_frames)
    )

    assert len(eapol_frames) >= 2, (
        f"Expected EAPOL activity after reassociation. "
        f"Found {len(eapol_frames)} frame(s).\n\n"
        f"{dump_output}"
    )

    return len(eapol_frames)


# PUBLIC_INTERFACE
def test_em_backhaul_reassociation(initialize):
    """
    Objective:
    Verify Agent backhaul reassociation after
    a controlled interface restart.

    Validation:
      - Existing association present
      - Interface restart occurs
      - Agent reassociates successfully
      - New EAPOL exchange observed
      - Controller regains connectivity
    """

    report_logger.print_test(
        "EM_Backhaul_Reassociation"
    )

    expected_ssid = _get_expected_ssid(
        initialize
    )

    agent_ip = _get_agent_ip(
        initialize
    )

    capture_pid = None

    try:

        # --------------------------------------------------
        # STEP 1
        # --------------------------------------------------
        report_logger.print_step(
            "STEP 1: Verify current backhaul association"
        )

        pre_output, _ = _run(
            initialize,
            AGENT,
            LINK_CMD,
        )

        pre_bssid, pre_ssid = _parse_link(
            pre_output
        )

        assert pre_bssid, (
            f"{AGENT}: Backhaul is not connected.\n"
            f"{pre_output}"
        )

        assert pre_ssid == expected_ssid, (
            f"{AGENT}: Connected SSID "
            f"{pre_ssid!r}, expected "
            f"{expected_ssid!r}"
        )

        report_logger.print_success(
            f"PASS: Connected to "
            f"BSSID {pre_bssid}, "
            f"SSID {pre_ssid}"
        )

        # --------------------------------------------------
        # STEP 2
        # --------------------------------------------------
        report_logger.print_step(
            "STEP 2: Start EAPOL packet capture"
        )

        _run(
            initialize,
            AGENT,
            f"rm -f {PCAP_PATH}"
        )

        start_output, _ = _run(
            initialize,
            AGENT,
            f"nohup tcpdump "
            f"-i {BACKHAUL_IFACE} "
            f"-w {PCAP_PATH} "
            f"ether proto 0x888e "
            f"> /dev/null 2>&1 & echo $!"
        )

        pid_match = re.search(
            r"^\s*(\d+)\s*$",
            start_output,
            re.MULTILINE,
        )

        assert pid_match, (
            f"Failed to obtain tcpdump PID:\n"
            f"{start_output}"
        )

        capture_pid = pid_match.group(1)

        time.sleep(2)

        _, rc = _run(
            initialize,
            AGENT,
            f"kill -0 {capture_pid}",
            check=False,
        )

        assert rc == 0, (
            f"{AGENT}: tcpdump did not start"
        )

        _run(
            initialize,
            AGENT,
            f"ls -l {PCAP_PATH}"
        )

        report_logger.print_success(
            f"PASS: Packet capture started "
            f"(PID {capture_pid})"
        )

        # --------------------------------------------------
        # STEP 3
        # --------------------------------------------------
        report_logger.print_step(
            "STEP 3: Restart backhaul interface"
        )

        restart_cmd = (
            f"setsid nohup sh -c "
            f"'ifconfig {BACKHAUL_IFACE} down; "
            f"sleep {DOWN_WAIT_SECONDS}; "
            f"ifconfig {BACKHAUL_IFACE} up' "
            f"> /dev/null 2>&1 "
            f"< /dev/null &"
        )

        _try_run(
            initialize,
            AGENT,
            restart_cmd,
        )

        time.sleep(DOWN_WAIT_SECONDS)

        report_logger.print_success(
            "PASS: Backhaul restart initiated"
        )

        # --------------------------------------------------
        # STEP 4
        # --------------------------------------------------
        report_logger.print_step(
            "STEP 4: Verify backhaul reconnection"
        )

        post_bssid, post_output = (
            _wait_for_reconnect(
                initialize,
                expected_ssid,
            )
        )

        report_logger.print_success(
            f"PASS: Reconnected to "
            f"BSSID {post_bssid}"
        )

        # --------------------------------------------------
        # STEP 5
        # --------------------------------------------------
        report_logger.print_step(
            "STEP 5: Verify EAPOL authentication sequence"
        )

        _try_run(
            initialize,
            AGENT,
            f"kill {capture_pid}"
        )

        time.sleep(2)

        capture_pid = None

        dump_output, _ = _run(
            initialize,
            AGENT,
            f"tcpdump -r {PCAP_PATH} -n"
        )

        frame_count = _verify_eapol_handshake(
            dump_output
        )

        report_logger.print_success(
            f"PASS: Captured "
            f"{frame_count} EAPOL frame(s)"
        )

        # --------------------------------------------------
        # STEP 6
        # --------------------------------------------------
        report_logger.print_step(
            "STEP 6: Verify connectivity restoration"
        )

        post_bssid_check, post_ssid = (
            _parse_link(post_output)
        )

        assert post_bssid_check == post_bssid

        assert post_ssid == expected_ssid, (
            f"Unexpected SSID after "
            f"reassociation: {post_ssid}"
        )

        report_logger.print_info(
            f"Pre-reassociation BSSID : "
            f"{pre_bssid}"
        )

        report_logger.print_info(
            f"Post-reassociation BSSID: "
            f"{post_bssid}"
        )


        ping_output, ping_rc = _run(
            initialize,
            CONTROLLER,
            f"ping -c 5 {agent_ip}",
            check=False,
        )

        assert ping_rc == 0, (
            f"Ping command failed:\n{ping_output}"
        )

        replies = re.findall(
            r"\d+\s+bytes\s+from",
            ping_output,
            re.IGNORECASE,
        )

        assert len(replies) >= 3, (
            f"Connectivity not restored after reassociation. "
            f"Received only {len(replies)} successful ping replies.\n"
            f"{ping_output}"
        )

        report_logger.print_success(
            f"PASS: Controller successfully reached Agent "
            f"({agent_ip}) with {len(replies)} successful ping replies"
        )

    finally:

        if capture_pid:

            _try_run(
                initialize,
                AGENT,
                f"kill {capture_pid}"
            )