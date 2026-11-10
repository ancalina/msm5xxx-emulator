"""Pure firmware detection helpers."""
import msm5xxx_emulator.detection.plan as boot_plan

from .arm import (arm_b_target, arm_b_word_target, arm_vector_score, thumb_bl_target, thumb_literal_value)
from msm5xxx_emulator.detection.registry import device_domain
find_audio_transport = device_domain('audio.rules').find_audio_transport
find_tone_generator = device_domain('audio.tone').find_tone_generator
tone_admission = device_domain('audio.tone').tone_admission
chipset_confidence = device_domain('identity.chipset').chipset_confidence
detect_chipset = device_domain('identity.chipset').detect_chipset
detect = boot_plan.detect
MODEL_RE = device_domain('identity.model').MODEL_RE
canonical_model = device_domain('identity.model').canonical_model
detect_model = device_domain('identity.model').detect_model
embedded_model_scores = device_domain('identity.model').embedded_model_scores
verified_embedded_model = device_domain('identity.model').verified_embedded_model
__all__ = ("MODEL_RE", "arm_b_target", "arm_b_word_target", "arm_vector_score", "canonical_model", "chipset_confidence", "detect", "detect_chipset",
    "detect_model", "embedded_model_scores", "find_audio_transport", "find_tone_generator", "thumb_bl_target", "thumb_literal_value", "tone_admission",
    "verified_embedded_model",)
