import re


def _channel_luminance(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def text_color_for_background_color(color):
    if not re.match(r'^[0-9a-fA-F]{3,6}$', color):
        return "000"
    if len(color) == 3:
        color = "".join(2 * c for c in color)
    try:
        r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
    except ValueError:
        return "000"
    luminance = (0.2126 * _channel_luminance(r)
                 + 0.7152 * _channel_luminance(g)
                 + 0.0722 * _channel_luminance(b))
    # WCAG: black text gives better contrast than white when luminance > ~0.179
    return "000" if luminance > 0.179 else "FFF"
