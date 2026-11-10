"""Audio source and memory admission for native property projection."""
from __future__ import annotations
from . import transport_projection as projection
from .rules import find_ma5_readback_candidate
from .ma5_gpio_irq import find_ma5_gpio_irq_candidate

def indexed_ram_profile(audio, config):
    audio_family = audio.get('family') if audio is not None else None
    audio_grammar = audio.get('grammar') if audio is not None else None
    return (audio_family == "ma3" and audio_grammar == "ma3-indexed-v1" and getattr(config, "chipset", None) == "MSM5100" and getattr(config, "flash_size", None)
        == 0x01000000 and getattr(config, "ram_base", None) == 0x01000000 and getattr(config, "ram_size", None) == 0x00800000)

def ma2_eligible(audio, config):
    audio_family = audio.get('family') if audio is not None else None
    audio_grammar = audio.get('grammar') if audio is not None else None
    return audio is not None and audio.get('static_status') == 'accepted' and (audio_family == 'ma2') and (audio_grammar == 'ma2-command-v1') and (config.ma2_silent_boot_address
        is not None or audio.get('base') == 42467328)

def register_transport_eligible(audio, config, ma3_indexed_ram_profile, upper_nor_present):
    audio_family = audio.get('family') if audio is not None else None
    audio_grammar = audio.get('grammar') if audio is not None else None
    return audio is not None and audio.get('static_status') == 'accepted' and ((audio_family, audio_grammar) in {('ma5', 'indexed-rw-v1'), ('ma3',
        'ma3-readback-v1'), ('ma3', 'ma3-readback-fifo-v1'), ('ma3', 'ma3-kp-readback-fifo-v1'), ('ma3', 'ma3-indexed-v1'), ('opaque', 'command-status-data-v1')}) and (audio_grammar
        != 'ma3-indexed-v1' or ma3_indexed_ram_profile) and (not upper_nor_present)

def automatic_irq(detector_image):
    candidate = find_ma5_readback_candidate(detector_image)
    ma5_auto_irq = (candidate.get("structural_evidence", {}).get("transport_class") == "local-counter-direction-timing-v1")
    if (candidate.get("structural_evidence", {}).get("transport_class") == "local-counter-literal-data-v1"):
        route = find_ma5_gpio_irq_candidate(detector_image, candidate)
        ma5_auto_irq = (route.get("status") == "candidate" and route.get("gpio", {}).get("pin") == 5 and route.get("installation", {}).get("profile") ==
            "conditional-install-direct-or-task-v1")
    if (candidate.get("structural_evidence", {}).get("transport_class") == "alternate-direct-reset-readback-v1"):
        route = find_ma5_gpio_irq_candidate(detector_image, candidate)
        ma5_auto_irq = (route.get("status") == "candidate" and route.get("installation", {}).get("profile") == "direct-install-no-flag-v1")
    return ma5_auto_irq

def boot_transport_selection(detector_image, audio, config, *, ma3_indexed_ram_profile, upper_nor_present, experimental_audio_refill):
    """Select boot-audio properties while leaving stream setup to transport."""
    audio_family = audio.get('family') if audio is not None else None
    audio_grammar = audio.get('grammar') if audio is not None else None
    if ma2_eligible(audio, config):
        sites = projection.qemu_audio_sites(audio)
        properties, notes = [], []
        if sites is not None:
            properties.extend((
                f"audio-aperture={int(audio['base']):x}:"
                f"{int(audio['data_offset']):x}:{audio_family}",
                f"audio-sites={sites}",
            ))
            if (experimental_audio_refill or (audio.get('irq_controller_candidate') or {}).get('profile') == 'byte-count-halfword-mask-v1'):
                irq_property, irq_reject = projection.qemu_audio_irq_property(audio, config)
                if irq_property is not None:
                    properties.append(irq_property)
                notes.append(
                    'QEMU audio refill provisional: half-full/empty occupancy approximation; live route gate'
                    if irq_property else
                    f'QEMU audio refill rejected: {irq_reject}; native fallback retained')
        return {'branch': 'ma2', 'properties': tuple(properties), 'notes': tuple(notes), 'stream': sites is not None, 'ma3_native': False}
    if register_transport_eligible(audio, config, ma3_indexed_ram_profile, upper_nor_present):
        sites = projection.qemu_audio_sites(audio)
        properties, notes = [], []
        if sites is not None:
            properties.extend((
                f"audio-aperture={int(audio['base']):x}:"
                f"{int(audio['data_offset']):x}:{audio_family}",
                f"audio-sites={sites}",
            ))
            notes.append("QEMU MA5 indexed write-only boot aperture enabled; " "reads remain fail-closed" if audio_family == 'ma5' else
                "QEMU MA3 register transport enabled with linked " "readback and MMIO accessors" if audio_family == 'ma3' else
                "QEMU command/status/data boot aperture enabled with " "inactive zero readback")
            if audio_family == 'ma3':
                irq_property, irq_reject = projection.qemu_ma3_gpio_irq_property(detector_image, config, audio)
                if irq_property is not None:
                    properties.append(irq_property)
                    notes.append("QEMU MA3 GPIO23 route enabled with linked parent, " "dispatcher, and reset-copy evidence; native RAM gates remain active")
                else:
                    notes.append(
                        f"QEMU MA3 GPIO IRQ route rejected: {irq_reject}; audio transport retained")
        return {'branch': 'register', 'properties': tuple(properties), 'notes': tuple(notes), 'stream': sites is not None and audio_family == 'ma3',
            'ma3_native': sites is not None and audio_family == 'ma3'}
    if (audio is not None and audio_grammar == 'repeated-bit-sequence-v1' and not upper_nor_present):
        packet_property, packet_reject = projection.qemu_audio_packet_property(detector_image, config, audio)
        if packet_property is not None:
            notes = ("QEMU temporary sequence receiver: actual reset/release required; " "raw register/RAM consumption only, no renderer or FIFO timing",)
            properties = (packet_property,)
        else:
            notes = (
                f"QEMU sequence receiver rejected: {packet_reject}; native fallback retained",)
            properties = ()
        return {'branch': 'sequence', 'properties': properties, 'notes': notes, 'stream': False, 'ma3_native': False}
    return {'branch': None, 'properties': (), 'notes': (), 'stream': False, 'ma3_native': False}
