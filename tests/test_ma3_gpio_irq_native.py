"""Exercise the SC MA3 GPIO parent IRQ latch and W1C semantics in C."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class MA3GPIOIRQNativeTests(unittest.TestCase):
    def test_route_admission_latch_and_independent_acknowledgements(self):
        source_path = Path(__file__).resolve().parents[1] / "native/qemu/msm5xxx-poc.c"
        source = source_path.read_text(encoding="utf-8")

        def function(name):
            match = re.search(r"^static [^;\n]*\b" + name +
                              r"\([^;]*?\)\n\{", source, re.MULTILINE)
            self.assertIsNotNone(match, name)
            opening = source.index("{", match.start())
            depth, end = 1, opening + 1
            while depth:
                depth += (source[end] == "{") - (source[end] == "}")
                end += 1
            return source[match.start():end]

        helpers = "\n".join((
            function("msm5xxx_poc_ma3_gpio_irq_route_values_valid"),
            function("msm5xxx_poc_ma3_gpio_irq_rex_profile_valid"),
            function("msm5xxx_poc_ma3_gpio_irq_latch"),
            function("msm5xxx_poc_ma3_gpio_irq_w1c"),
        ))
        harness = r'''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
enum {
    MA3G_PIN, MA3G_PARENT_INDEX, MA3G_TABLE, MA3G_CALLBACKS,
    MA3G_PARENT_TABLE, MA3G_GPIO_DISPATCH, MA3G_PARENT_DISPATCH,
    MA3G_CALLBACK, MA3G_PARENT_MASK, MA3G_STATUS, MA3G_ENABLE,
    MA3G_COUNT
};
''' + helpers + r'''
int main(void) {
    uint32_t route[MA3G_COUNT] = {
        23, 29, 0x0100b914, 0x0129e278, 0x0100b584,
        0x00161f69, 0x00161bfc, 0x0009bb71, 0x2000,
        0x03000c84, 0x03000c98,
    };
    uint16_t gpio = 0, parent = 0, rex = 0;
    bool callback_seen = false;

    assert(msm5xxx_poc_ma3_gpio_irq_route_values_valid(route));
    route[MA3G_PARENT_MASK] = 0x1000;
    assert(!msm5xxx_poc_ma3_gpio_irq_route_values_valid(route));
    route[MA3G_PARENT_MASK] = 0x2000;

    /* SC uses the static C80 gate profile, with no copied-profile flag. */
    assert(msm5xxx_poc_ma3_gpio_irq_rex_profile_valid(
        true, false, 0x03000c80, 0x03000c94, 0x0200,
        0x01000000, 0x001d3954, 0x01293f0c, 0x00161bfc,
        0x188, 0x0100b8e0, 0x000b7898, 2));
    assert(!msm5xxx_poc_ma3_gpio_irq_rex_profile_valid(
        true, true, 0x03000c80, 0x03000c94, 0x0200,
        0x01000000, 0x001d3954, 0x01293f0c, 0x00161bfc,
        0x188, 0x0100b8e0, 0x000b7898, 2));
    assert(!msm5xxx_poc_ma3_gpio_irq_rex_profile_valid(
        true, false, 0x03000c80, 0x03000c94, 0x0200,
        0x01000000, 0x001d3954, 0x01293f0c, 0x00161bfc,
        0x188, 0x0100b8e0, 0x000b7898, 3));

    /* Unqualified and disabled sources cannot assert either interrupt. */
    assert(!msm5xxx_poc_ma3_gpio_irq_latch(true, false, &callback_seen,
                                            &gpio, &parent, &rex, 0x80));
    assert(!gpio && !parent && !rex && !callback_seen);
    assert(!msm5xxx_poc_ma3_gpio_irq_latch(true, true, &callback_seen,
                                            &gpio, &parent, &rex, 0));
    assert(!gpio && !parent && !rex && !callback_seen);

    /* A qualified edge with the line enabled raises GPIO and C80 masks. */
    assert(!msm5xxx_poc_ma3_gpio_irq_latch(false, true, &callback_seen,
                                            &gpio, &parent, &rex, 0x80));
    assert(!callback_seen);
    assert(msm5xxx_poc_ma3_gpio_irq_latch(true, true, &callback_seen,
                                           &gpio, &parent, &rex, 0x80));
    assert(gpio == 0x80 && parent == 0x2000 && rex == 0x2000);
    assert(!msm5xxx_poc_ma3_gpio_irq_latch(true, true, &callback_seen,
                                            &gpio, &parent, &rex, 0x80));

    /* GPIO C8C and parent C84 acknowledge separate latched status banks. */
    assert(msm5xxx_poc_ma3_gpio_irq_w1c(&gpio, 0x80));
    assert(gpio == 0x00 && parent == 0x2000 && rex == 0x2000);
    assert(msm5xxx_poc_ma3_gpio_irq_w1c(&rex, 0x2000));
    assert(msm5xxx_poc_ma3_gpio_irq_w1c(&parent, 0x2000));
    assert(!parent && !rex);
    assert(!msm5xxx_poc_ma3_gpio_irq_w1c(&gpio, 0x80));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            c_file = Path(temporary) / "ma3-gpio-irq.c"
            binary = Path(temporary) / "ma3-gpio-irq"
            c_file.write_text(harness, encoding="utf-8")
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-pedantic", "-o", str(binary), str(c_file)],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
