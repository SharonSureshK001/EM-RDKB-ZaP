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
from contextlib import suppress

from rdkbmeshzap.common_utils import device_utils, report_logger
from rdkbmeshzap.common_utils.backhaul_utils import (
    AGENT,
    CONTROLLER,
    DOWN_WAIT_SECONDS,
    EAPOL_CAPTURE_FILTER,
    get_agent_ip,
    get_backhaul_interface,
    get_expected_ssid,
    verify_eapol_handshake,
    wait_for_reconnect,
)


# PUBLIC_INTERFACE
def test_em_backhaul_reassociation(initialize):
    """
    Objective:
    Verify Agent backhaul reassociation after
    a controlled interface restart.

    Validation:
      - Existing association present
      - Interface restart occurs
      - Link disconnect is observed
      - Agent reassociates successfully
      - New EAPOL exchange observed
      - Controller regains connectivity
    """

    capture_running = False

    capture_name = device_utils.create_capture_name(
        "backhaul_reassoc",
        AGENT,
    )

    report_logger.print_test(
        "Entering test_em_backhaul_reassociation"
    )

    try:

        expected_ssid = get_expected_ssid(
            initialize
        )

        agent_ip = get_agent_ip(
            initialize
        )

        backhaul_iface = get_backhaul_interface(
            initialize,
            AGENT,
        )

        report_logger.print_step(
            "STEP 1: Verify current backhaul association"
        )

        pre_bssid, pre_ssid = (
            initialize.get_backhaul_link_details(
                AGENT,
                backhaul_iface,
            )
        )

        assert pre_bssid, (
            f"{AGENT}: Backhaul is not connected "
            f"on {backhaul_iface}."
        )

        assert pre_ssid == expected_ssid, (
            f"{AGENT}: Connected SSID "
            f"{pre_ssid!r}, expected "
            f"{expected_ssid!r}"
        )

        report_logger.print_success(
            f"PASS: Connected to BSSID "
            f"{pre_bssid}, SSID {pre_ssid}"
        )

        report_logger.print_step(
            "STEP 2: Start EAPOL packet capture"
        )

        initialize.start_frame_capture(
            AGENT,
            backhaul_iface,
            EAPOL_CAPTURE_FILTER,
            capture_name,
        )

        capture_running = True

        time.sleep(2)

        report_logger.print_success(
            f"PASS: Packet capture started "
            f"({capture_name})"
        )

        report_logger.print_step(
            "STEP 3: Restart backhaul interface"
        )

        restart_cmd = (
            f"setsid nohup sh -c "
            f"'ifconfig {backhaul_iface} down; "
            f"sleep {DOWN_WAIT_SECONDS:g}; "
            f"ifconfig {backhaul_iface} up' "
            f"> /dev/null 2>&1 < /dev/null &"
        )

        try:
            initialize.execute_command(
                AGENT,
                restart_cmd,
            )

        except Exception as exc:

            report_logger.print_info(
                f"Expected interruption during "
                f"restart: {exc}"
            )

        report_logger.print_step(
            "STEP 3A: Verify disconnect occurred"
        )
        disconnect_seen = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:

            try:

                connected = (
                    initialize.get_wireless_backhaul_connection_status(
                        AGENT,
                        backhaul_iface,
                    )
                )

            except Exception:
                connected = False

            if not connected:
                disconnect_seen = True
                break

            time.sleep(2)

        assert disconnect_seen, (
            f"{AGENT}: Backhaul interface never "
            f"entered disconnected state"
        )

        report_logger.print_success(
            "PASS: Disconnect observed"
        )

        report_logger.print_step(
            "STEP 4: Verify backhaul reconnection"
        )

        post_bssid, post_ssid = wait_for_reconnect(
            initialize,
            expected_ssid,
            AGENT,
        )

        report_logger.print_success(
            f"PASS: Reconnected to BSSID "
            f"{post_bssid}, SSID {post_ssid}"
        )

        report_logger.print_step(
            "STEP 5: Verify EAPOL authentication sequence"
        )

        local_pcap = (
            device_utils.stop_and_collect_capture(
                initialize,
                AGENT,
                capture_name,
            )
        )

        capture_running = False
        frame_count = verify_eapol_handshake(
            local_pcap
        )

        report_logger.print_success(
            f"PASS: Captured "
            f"{frame_count} EAPOL-Key frame(s)"
        )

        report_logger.print_step(
            "STEP 6: Verify connectivity restoration"
        )

        report_logger.print_info(
            f"Pre-reassociation BSSID : "
            f"{pre_bssid}"
        )

        report_logger.print_info(
            f"Post-reassociation BSSID: "
            f"{post_bssid}"
        )

        ping_output, ping_rc = (
            initialize.execute_command(
                CONTROLLER,
                f"ping -c 5 {agent_ip}",
                return_rc=True,
            )
        )

        assert ping_rc == 0, (
            f"Ping command failed:\n"
            f"{ping_output}"
        )

        replies = re.findall(
            r"\d+\s+bytes\s+from",
            ping_output,
            re.IGNORECASE,
        )

        assert len(replies) >= 3, (
            f"Connectivity not restored after "
            f"reassociation. Received only "
            f"{len(replies)} successful ping "
            f"replies.\n{ping_output}"
        )

        report_logger.print_success(
            f"PASS: Controller successfully reached "
            f"Agent ({agent_ip}) with "
            f"{len(replies)} successful ping replies"
        )

    finally:

        if capture_running:
            with suppress(Exception):
                device_utils.stop_and_collect_capture(
                    initialize,
                    AGENT,
                    capture_name,
                )

        report_logger.print_test(
            "Exiting test_em_backhaul_reassociation"
        )