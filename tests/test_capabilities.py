"""Synthetic tests for static evidence and resource planning."""
from dataclasses import FrozenInstanceError
import unittest

from msm5xxx_emulator.detection.capabilities import (
    Capability, CapabilityPredicate, CapabilityRegistry, Decision,
    Evidence, MachinePlan, ResourceClaim, build_machine_plan, resolve_proposals,
)


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.evidence = Evidence("mmio-read", {"base": 0x3000700, "width": 4}, (12,))

    def accepted(self, name="uart", properties=(), claims=()):
        return Decision("accepted", Capability(name, ("mmio-read",),
                        (self.evidence,), properties, claims))

    def plan_claims(self, *claims):
        return build_machine_plan(self.accepted(str(index), claims=(claim,))
                                  for index, claim in enumerate(claims))

    def test_missing_required_evidence_is_explicit(self):
        registry = CapabilityRegistry()
        registry.register(CapabilityPredicate("uart", ("mmio-read",), lambda _: None))
        result = registry.resolve(()).decisions[0]
        self.assertEqual((result.status, result.missing_evidence),
                         ("missing", ("mmio-read",)))

    def test_differing_evidence_is_ambiguous(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            Capability("uart", ("mmio-read",), (
                self.evidence, Evidence("mmio-read", {"base": 0x3000800}, (20,)),
            ))

    def test_overlapping_address_claims_conflict(self):
        result = self.plan_claims(
            ResourceClaim("address", "uart", 0x3000700, 0x3000704),
            ResourceClaim("address", "timer", 0x3000702, 0x3000708))
        self.assertEqual(result.status, "conflict")
        self.assertIn("overlaps", result.reason)

    def test_disjoint_gpio_bits_can_coexist(self):
        self.assertEqual(self.plan_claims(
            ResourceClaim("gpio", "gpio-a", 0x3000700, 0x3000704, mask=0x03),
            ResourceClaim("gpio", "gpio-a", 0x3000700, 0x3000704, mask=0x0C)).status,
            "accepted")

    def test_overlapping_gpio_bits_conflict(self):
        self.assertEqual(self.plan_claims(
            ResourceClaim("gpio", "gpio-a", 0x3000700, 0x3000704, mask=0x03),
            ResourceClaim("gpio", "gpio-a", 0x3000700, 0x3000704, mask=0x06)).status,
            "conflict")

    def test_gpio_and_address_claims_conflict_on_same_register(self):
        self.assertEqual(self.plan_claims(
            ResourceClaim("address", "gpio-register", 0x3000700, 0x3000704),
            ResourceClaim("gpio", "gpio-a", 0x3000700, 0x3000704, mask=1)).status,
            "conflict")

    def test_gpio_alias_widths_compare_physical_pin_bits(self):
        word = ResourceClaim("gpio", "port", 0x3000720, 0x3000724, mask=1 << 21)
        same_pin = ResourceClaim("gpio", "port-byte", 0x3000722, 0x3000723, mask=1 << 5)
        other_pin = ResourceClaim("gpio", "port-byte", 0x3000722, 0x3000723, mask=1 << 4)
        for first, second in ((word, same_pin), (same_pin, word)):
            self.assertEqual(self.plan_claims(first, second).status, "conflict")
        for first, second in ((word, other_pin), (other_pin, word)):
            self.assertEqual(self.plan_claims(first, second).status, "accepted")

    def test_disjoint_gpio_pins_remain_composable_across_analysis_phases(self):
        self.assertEqual(self.plan_claims(
            ResourceClaim("gpio", "port", 0x3000720, 0x3000724,
                          mask=1 << 21, phase="reset"),
            ResourceClaim("gpio", "port-byte", 0x3000722, 0x3000723,
                          mask=1 << 4, phase="runtime")).status, "accepted")

    def test_gpio_refinement_can_cover_a_byte_alias_with_a_word_claim(self):
        weak = Capability("byte", ("mmio-read",), (self.evidence,), claims=(
            ResourceClaim("gpio", "port", 0x3000722, 0x3000723, mask=1 << 5),),
            alternative_group="port")
        strong = Capability("word", ("mmio-read",), (self.evidence,), claims=(
            ResourceClaim("gpio", "port", 0x3000720, 0x3000724, mask=1 << 21),),
            alternative_group="port", priority=1, refines=("byte",))
        result = resolve_proposals((Decision("accepted", capability=weak),
                                    Decision("accepted", capability=strong)))
        self.assertEqual(result.plan.capabilities, (strong,))

    def test_physical_claims_conflict_across_phases(self):
        self.assertEqual(self.plan_claims(
            ResourceClaim("address", "uart", 0x100, 0x110, phase="runtime"),
            ResourceClaim("address", "timer", 0x100, 0x110, phase="boot")).status,
            "conflict")

    def test_claims_in_different_address_spaces_can_coexist(self):
        self.assertEqual(self.plan_claims(
            ResourceClaim("address", "uart", 0x100, 0x110),
            ResourceClaim("address", "uart", 0x100, 0x110,
                          address_space="virtual", phase="boot")).status, "accepted")

    def test_shared_address_resource_requires_matching_contract(self):
        first = ResourceClaim("address", "uart", 0x100, 0x108,
                              shared_resource="console", semantics="read-only-status")
        compatible = ResourceClaim("address", "uart-alias", 0x104, 0x10C,
                                   shared_resource="console", semantics="read-only-status")
        incompatible = ResourceClaim("address", "uart", 0x104, 0x10C,
                                     shared_resource="console", semantics="write-output")
        self.assertEqual(self.plan_claims(first, compatible).status, "accepted")
        self.assertEqual(self.plan_claims(first, incompatible).status, "conflict")

    def test_different_property_assignments_conflict(self):
        result = build_machine_plan((
            self.accepted("uart", (("uart_base", 0x3000700),)),
            self.accepted("other-uart", (("uart_base", 0x3000800),))))
        self.assertEqual(result.status, "conflict")
        self.assertIn("property", result.reason)

    def test_plan_and_evidence_are_immutable(self):
        result = build_machine_plan((self.accepted(),))
        self.assertIsInstance(result.plan, MachinePlan)
        self.assertIsInstance(result.plan.capabilities[0], Capability)
        with self.assertRaises(FrozenInstanceError):
            result.plan.properties = ()
        with self.assertRaises(TypeError):
            result.plan.evidence[0].value[0] = 99

    def test_captured_parameters_are_immutable_and_survive_registry_resolution(self):
        original = {'size': 0x2000, 'regions': [[2, 0x1000]]}
        registry = CapabilityRegistry()
        registry.register(CapabilityPredicate('nor', ('mmio-read',), lambda facts:
            Capability('nor', ('mmio-read',), (self.evidence,),
                       parameters=(('geometry', original),))))
        first = registry.resolve((self.evidence,)).plan.capabilities[0]
        original['regions'][0][0] = 3
        self.assertEqual(dict(first.parameters)['geometry'],
                         (('regions', ((2, 0x1000),)), ('size', 0x2000)))
        self.assertEqual(first.properties, ())

    def test_bytearrays_are_copied_and_opaque_values_rejected(self):
        raw = bytearray(b"abcd")
        item = Evidence("literal", raw, (4,), "literal")
        raw[0] = 0
        self.assertEqual(item.value, b"abcd")
        with self.assertRaises(TypeError):
            Evidence("opaque", object(), (4,))

    def test_required_evidence_must_have_source_locations(self):
        with self.assertRaisesRegex(ValueError, "source locations"):
            Capability("uart", ("mmio-read",), (Evidence("mmio-read", 0x3000700),))

    def test_direct_machine_plan_cannot_bypass_claim_validation(self):
        first = self.accepted("uart", claims=(
            ResourceClaim("address", "uart", 0x3000700, 0x3000704),)).capability
        second = self.accepted("timer", claims=(
            ResourceClaim("address", "timer", 0x3000702, 0x3000708),)).capability
        with self.assertRaises(ValueError):
            MachinePlan((first, second), (), first.claims + second.claims, (self.evidence,))

    def test_empty_plan_is_a_valid_accepted_result(self):
        result = build_machine_plan(())
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.plan.capabilities, ())

    def test_registry_keeps_independent_ram_and_halt_observations(self):
        registry = CapabilityRegistry()
        registry.register(CapabilityPredicate(
            "ram", ("scatter-copy",), lambda facts: Capability(
                "ram-layout", ("scatter-copy",), (facts[0],), (("ram_base", 0x1000000),)
            )))
        registry.register(CapabilityPredicate(
            "halt", ("self-branch",), lambda facts: Capability(
                "halt-observation", ("self-branch",), (facts[1],)
            )))
        facts = (Evidence("scatter-copy", 0x1000, (4,), "data"),
                 Evidence("self-branch", 0x2000, (8,)))
        result = registry.resolve(facts)
        self.assertEqual([item.status for item in result.decisions], ["accepted", "accepted"])
        self.assertEqual({item.name for item in result.plan.capabilities},
                         {"ram-layout", "halt-observation"})

    def test_registry_composes_disjoint_gpio_bit_providers(self):
        registry = CapabilityRegistry()
        for name, mask in (("key-a", 1), ("key-b", 2)):
            evidence_name = f"{name}-code"
            registry.register(CapabilityPredicate(
                name, (evidence_name,), lambda facts, name=name, mask=mask,
                evidence_name=evidence_name: Capability(
                    name, (evidence_name,), (next(x for x in facts if x.name == evidence_name),),
                    claims=(ResourceClaim("gpio", "bank-a", 0x3000700, 0x3000704,
                                          mask=mask),)
                )))
        facts = (Evidence("key-a-code", 1, (2,)), Evidence("key-b-code", 2, (4,)))
        result = registry.resolve(facts)
        self.assertEqual([item.status for item in result.decisions], ["accepted", "accepted"])
        self.assertEqual(len(result.plan.claims), 2)

    def test_explicit_specific_rule_supersedes_fallback(self):
        facts = (Evidence("gpio-access", 0x3000700, (2,)),
                 Evidence("descriptor-owner", 0x3000704, (8,), "data"))
        fallback = Capability("gpio-fallback", ("gpio-access",), (facts[0],),
                              alternative_group="gpio", priority=0)
        specific = Capability("gpio-specific", ("gpio-access", "descriptor-owner"), facts,
                              alternative_group="gpio", priority=5)
        registry = CapabilityRegistry()
        registry.register(CapabilityPredicate("fallback", ("gpio-access",),
            lambda _: fallback, alternative_group="gpio", priority=0))
        registry.register(CapabilityPredicate("specific", ("gpio-access", "descriptor-owner"),
            lambda _: specific, alternative_group="gpio", priority=5,
            refines=("gpio-fallback",)))
        result = registry.resolve(facts)
        self.assertEqual([item.status for item in result.decisions], ["superseded", "accepted"])
        self.assertEqual([item.name for item in result.plan.capabilities], ["gpio-specific"])

    def test_equal_proofs_in_one_alternative_group_remain_ambiguous(self):
        facts = (self.evidence,)
        registry = CapabilityRegistry()
        for name in ("one", "two"):
            registry.register(CapabilityPredicate(name, ("mmio-read",),
                lambda fs, name=name: Capability(name, ("mmio-read",), fs),
                alternative_group="uart", priority=2))
        result = registry.resolve(facts)
        self.assertEqual([item.status for item in result.decisions],
                         ["ambiguous", "ambiguous"])
        self.assertEqual(result.plan.capabilities, ())

    def test_conflicting_optional_proposals_do_not_drop_independent_device(self):
        facts = tuple(Evidence(name, value, (index + 1,))
                      for index, (name, value) in enumerate((
                          ("a", 1), ("b", 2), ("c", 3))))
        registry = CapabilityRegistry()
        for name, evidence_name, start, end in (
                ("owner-a", "a", 0x100, 0x110),
                ("owner-b", "b", 0x108, 0x118),
                ("clock", "c", 0x200, 0x204)):
            registry.register(CapabilityPredicate(name, (evidence_name,),
                lambda fs, name=name, evidence_name=evidence_name, start=start, end=end:
                Capability(name, (evidence_name,),
                    (next(x for x in fs if x.name == evidence_name),),
                    claims=(ResourceClaim("address", name, start, end),))))
        result = registry.resolve(facts)
        self.assertEqual([item.status for item in result.decisions],
                         ["conflict", "conflict", "accepted"])
        self.assertEqual([item.name for item in result.plan.capabilities], ["clock"])

    def test_capability_cannot_claim_without_its_evidence(self):
        with self.assertRaises(ValueError):
            Capability("unsupported", ("scatter-copy",), (), claims=())

    def test_refinement_cannot_replace_contradictory_evidence(self):
        first = Capability('fallback', ('port',), (Evidence('port', 0x100, (4,)),),
                           alternative_group='bus')
        other = Capability('specific', ('port',), (Evidence('port', 0x200, (8,)),),
                           alternative_group='bus', priority=1, refines=('fallback',))
        result = resolve_proposals((Decision('accepted', first), Decision('accepted', other)))
        self.assertEqual([item.status for item in result.decisions], ['ambiguous', 'ambiguous'])
        self.assertEqual(result.plan.capabilities, ())

    def test_refinement_retains_properties_and_captured_parameter_keys(self):
        common = Evidence('port', 0x100, (4,))
        specific_evidence = Evidence('descriptor', 0x200, (8,), 'data')
        strong = Capability('specific', ('port', 'descriptor'),
                            (common, specific_evidence), alternative_group='bus',
                            priority=1, refines=('fallback',))

        for field in ('properties', 'parameters'):
            weak = Capability('fallback', ('port',), (common,),
                              alternative_group='bus', **{field: (('bus_base', 0x100),)})
            result = resolve_proposals((Decision('accepted', weak), Decision('accepted', strong)))
            self.assertEqual([item.status for item in result.decisions],
                             ['ambiguous', 'ambiguous'])
            self.assertEqual(result.plan.capabilities, ())

    def test_refinement_must_retain_weak_resource_claims(self):
        common = Evidence('port', 0x100, (4,))
        specific_evidence = Evidence('descriptor', 0x200, (8,), 'data')
        claim = ResourceClaim('address', 'external-bus', 0x100, 0x110)
        weak = Capability('fallback', ('port',), (common,), claims=(claim,),
                          alternative_group='bus')
        strong = Capability('specific', ('port', 'descriptor'),
                            (common, specific_evidence), alternative_group='bus',
                            priority=1, refines=('fallback',))

        result = resolve_proposals((Decision('accepted', weak), Decision('accepted', strong)))

        self.assertEqual([item.status for item in result.decisions],
                         ['ambiguous', 'ambiguous'])
        self.assertEqual(result.plan.claims, ())

    def test_refinement_can_replace_a_property_value_and_cover_claim(self):
        common = Evidence('port', 0x100, (4,))
        specific_evidence = Evidence('descriptor', 0x200, (8,), 'data')
        weak_claim = ResourceClaim('address', 'external-bus', 0x100, 0x110)
        strong_claim = ResourceClaim('address', 'external-bus', 0x100, 0x120)
        weak = Capability('fallback', ('port',), (common,),
                          properties=(('bus_base', 0x100),), claims=(weak_claim,),
                          alternative_group='bus')
        strong = Capability('specific', ('port', 'descriptor'),
                            (common, specific_evidence),
                            properties=(('bus_base', 0x200),), claims=(strong_claim,),
                            alternative_group='bus', priority=1,
                            refines=('fallback',))

        result = resolve_proposals((Decision('accepted', weak), Decision('accepted', strong)))

        self.assertEqual([item.status for item in result.decisions],
                         ['superseded', 'accepted'])
        self.assertEqual(result.plan.properties, (('bus_base', 0x200),))
        self.assertEqual(result.plan.claims, (strong_claim,))

    def test_frozen_set_survives_plan_projection(self):
        cap = Capability('device', ('port',), (Evidence('port', {1, 2}, (4,)),),
                         properties=(('values', {1, 2}),))
        result = build_machine_plan((Decision('accepted', cap),))
        self.assertEqual(result.plan.properties, (('values', frozenset({1, 2})),))

    def test_claims_are_bounded_by_address_space_and_register_width(self):
        with self.assertRaises(ValueError):
            ResourceClaim('gpio', 'bank', 0x100, 0x101, mask=0x100)
        with self.assertRaises(ValueError):
            ResourceClaim('address', 'window', 0, (1 << 32) + 1)

    def test_decision_status_is_constrained(self):
        with self.assertRaises(ValueError):
            Decision("selected")


if __name__ == "__main__":
    unittest.main()
