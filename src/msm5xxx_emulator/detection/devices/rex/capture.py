"""REX timer and controller evidence collected during firmware planning."""
from __future__ import annotations

from .rules import (REX_TICK_SIGNATURE, find_rex_5ms_irq_arm, find_rex_5ms_irq_route, find_rex_5ms_sleep_timer, find_rex_idle_address,
    find_rex_legacy_row0_profile, find_rex_static_c40_controller_observation, find_rex_static_controller_callback_candidate,
    find_rex_static_overlay_controller_callback_candidate, find_uis_idle_pair)

def capture_static(layout):
    rex_static_controller_candidate = (find_rex_static_controller_callback_candidate(layout.primary_image, ram_base=layout.ram_base, ram_size=layout.ram_size,))
    rex_static_c40_controller_observation = (find_rex_static_c40_controller_observation(layout.primary_image))
    if rex_static_controller_candidate is not None:
        if rex_static_controller_candidate["accepted"]:
            if (rex_static_controller_candidate.get("controller_class") in { "legacy-msm5000-620-two-bank-w1c-8call-v1",
                "legacy-msm5000-620-two-bank-w1c-group10-v1", "legacy-msm5000-620-two-bank-w1c-group12-v1", }):
                layout.detection_notes.append("static MSM5000 0x620 two-bank clear/write controller " "class detected; 5-unit service cadence is a temporary "
                    "evidence-gated physical-tick approximation")
            elif (rex_static_controller_candidate.get("signature") == "static-msm5000-620-controller-callback-v1"):
                layout.detection_notes.append("static MSM5000 0x620 two-bank delta-5 controller " "candidate detected; native pending cadence and idle "
                    "remain unproven")
            elif (rex_static_controller_candidate.get("signature") == "static-fb0-controller-callback-v1"):
                layout.detection_notes.append("static FB0 index-0x1B delta-5 controller candidate " "detected; explicit experimental activation required, "
                    "physical timer cadence remains approximated")
            else:
                layout.detection_notes.append("static C80 index-0x1E delta-5 controller candidate " "detected; native pending, IRQ, and idle remain unproven")
        else:
            layout.detection_notes.append(
                "static REX controller candidate rejected: "
                f"{rex_static_controller_candidate['reject_reason']}"
            )
    if rex_static_c40_controller_observation is not None:
        if rex_static_c40_controller_observation["accepted"]:
            layout.detection_notes.append("static C40 selector-0 delta-5 controller observation " "detected; native pending, cadence, repeat IRQ, and idle "
                "remain unproven")
        else:
            layout.detection_notes.append(
                "static C40 controller observation rejected: "
                f"{rex_static_c40_controller_observation['reject_reason']}"
            )
    return rex_static_controller_candidate, rex_static_c40_controller_observation

def capture_tick(layout, direct_signature, auto_relative):
    rex_tick_address = direct_signature("rex_tick_address", REX_TICK_SIGNATURE)
    rex_idle_address = find_rex_idle_address(layout.primary_image)
    rex_irq_route = None
    rex_irq_arm_address = None
    rex_tick_ms = 1000
    if rex_idle_address is not None:
        auto_relative.add("rex_idle_address")
    rex_5ms_pair = (find_rex_5ms_sleep_timer(layout.primary_image) if rex_idle_address is None and rex_tick_address is None else None)
    if rex_5ms_pair is not None:
        rex_idle_address, rex_tick_address, rex_tick_ms = rex_5ms_pair
    return (rex_tick_address, rex_idle_address, rex_5ms_pair, rex_irq_route, rex_irq_arm_address, rex_tick_ms,)

def capture_mapped(layout, runtime_position, mapped_runtime, mapped_file, rex_static_controller_candidate):
    uis_idle_entry_address = None
    uis_idle_body_address = None
    uis_idle_pair = find_uis_idle_pair(layout.primary_image, mapped_runtime, mapped_file)
    if uis_idle_pair is not None:
        uis_idle_entry_address = runtime_position("uis_idle_entry_address", uis_idle_pair[0])
        uis_idle_body_address = runtime_position("uis_idle_body_address", uis_idle_pair[1])
        if uis_idle_entry_address is not None and uis_idle_body_address is not None:
            layout.detection_notes.append("firmware UI-idle entry/body call shape detected; observation only")
        else:
            uis_idle_entry_address = None
            uis_idle_body_address = None
    if rex_static_controller_candidate is None:
        rex_static_controller_candidate = (find_rex_static_overlay_controller_callback_candidate(layout.primary_image, mapped_runtime, mapped_file, ram_base=layout.ram_base,
            ram_size=layout.ram_size,))
        if rex_static_controller_candidate is not None:
            if rex_static_controller_candidate["accepted"]:
                layout.detection_notes.append("static C80 index-0x2B copied-handler delta-5 controller " "candidate detected; first-bank TIME_TICK only")
            else:
                layout.detection_notes.append(
                    "static C80 copied-handler controller candidate rejected: "
                    f"{rex_static_controller_candidate['reject_reason']}"
                )
    return (uis_idle_entry_address, uis_idle_body_address, rex_static_controller_candidate,)

def capture_delivery(layout, rex_5ms_pair, rex_idle_address, rex_tick_address, rex_irq_route, rex_irq_arm_address, rex_tick_ms, rex_basic_irq_profile, overlays,
    mapped_runtime):
    if rex_5ms_pair is not None:
        idle_position, tick_position, rex_tick_ms = rex_5ms_pair
        rex_idle_address = mapped_runtime(idle_position)
        rex_tick_address = mapped_runtime(tick_position)
        rex_irq_route = find_rex_5ms_irq_route(layout.primary_image, tick_position, mapped_runtime, candidate_only_mapper=True,)
        layout.detection_notes.append("REX sleep loop and periodic wrapper prove 5 ms timer-list advance")
        if rex_irq_route is not None:
            rex_irq_arm_address = find_rex_5ms_irq_arm(layout.primary_image, tick_position)
            layout.detection_notes.append("REX IRQ wrapper/controller route proves firmware 5 ms delivery")
    if (layout.requested_load_address == 0 and rex_irq_route is None and rex_idle_address is None and rex_tick_address is None):
        rex_basic_irq_profile, _row0_reason = find_rex_legacy_row0_profile(layout.primary_image, layout.ram_base, layout.ram_size, overlays)
        if rex_basic_irq_profile is not None:
            rex_tick_address = mapped_runtime(rex_basic_irq_profile["callback_file_offset"])
            rex_irq_route = tuple(rex_basic_irq_profile["route"])
            rex_irq_arm_address = rex_basic_irq_profile["arm_address"]
            rex_tick_ms = 5
            layout.detection_notes.append("source-linked row0 IRQ: 5 logical units/1000 carry; "
                "virtual 5ms policy, physical oscillator unverified; no idle hook")
        elif _row0_reason not in (None, "row0-callback-none"):
            layout.detection_notes.append(
                f"row0 IRQ not applied: {_row0_reason}; native fallback"
            )
    return (rex_basic_irq_profile, rex_idle_address, rex_tick_address, rex_irq_route, rex_irq_arm_address, rex_tick_ms,)
