"""Instantiate display consumers selected by a machine plan."""
from .b0_page import MonoPage, OffsetMonoPage, PairedPage
from .binary_window import BinaryWindow
from .packed_window2 import PackedWindow2
from .reverse565 import Reverse565
from .row565 import Row565
from .source_cursor import SourcePackedCursor
from .source_packed12 import SourcePacked12
from .window51 import Window51
from .dcs_window import DcsWindow
from .indexed28 import Indexed28
from .indexed44 import Indexed44
from .indexed1c import Indexed1C


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
    if choices.get('indexed44'):
        width, height, x, y, command, data = choices['indexed44']
        decoder._lcd_b0_source_page = Indexed44(width, height,
            x_origin=x, y_origin=y, command_port=command, data_port=data)
    elif choices.get('indexed1c'):
        width, height = choices['indexed1c']
        decoder._lcd_b0_source_page = Indexed1C(width, height)
    elif choices.get('indexed28'):
        values = choices['indexed28']
        dimensions, options = values[:2], values[2:]
        names = ('command_port', 'data_port', 'x_origin', 'y_origin', 'data_aperture')
        decoder._lcd_b0_source_page = Indexed28(*dimensions, **dict(zip(names, options)))
    elif choices.get('window51'):
        decoder._lcd_b0_source_page = Window51(*choices['window51'])
    elif choices.get('dcs_window'):
        decoder._lcd_b0_source_page = DcsWindow(*choices['dcs_window'])
