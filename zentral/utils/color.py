import re
import colorsys


def text_color_for_background_color(color):
    if not re.match(r'^[0-9a-fA-F]{3,6}$', color):
        return "000"
    if len(color) == 3:
        color = "".join(2 * c for c in color)
    try:
        hls = colorsys.rgb_to_hls(float(int(color[0:2], 16))/255.0,
                                  float(int(color[2:4], 16))/255.0,
                                  float(int(color[4:6], 16))/255.0,)
    except ValueError:
        return "000"
    else:
        if hls[1] > .7:
            return "000"
        else:
            return "FFF"
