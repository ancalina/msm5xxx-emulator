"""Instantiate display consumers selected by a machine plan."""
from .b0_page import MonoPage, OffsetMonoPage, PairedPage
from .binary_window import BinaryWindow
from .packed_window2 import PackedWindow2
from .reverse565 import Reverse565
from .row565 import Row565
from .source_cursor import SourcePackedCursor
from .source_packed12 import SourcePacked12


def apply_source_plan(decoder, plan):
    choices = {}
    for capability in plan.capabilities:
        if capability.name == 'source-display-writer':
            choices = dict(capability.parameters)
    factories = {'paired': PairedPage, 'byte-paired': lambda: PairedPage(width=120, access_width=1),
                 'mono': MonoPage, 'offset-mono': OffsetMonoPage, 'row565': Row565,
                 'binary': BinaryWindow, 'reverse565': Reverse565, 'packed12': SourcePacked12}
    decoder._lcd_packed_window2 = PackedWindow2() if choices.get('packed2') else False
    decoder._lcd_source_packed_cursor = SourcePackedCursor() if choices.get('cursor') else False
    factory = factories.get(choices.get('page'))
    decoder._lcd_b0_source_page = factory() if factory else False
