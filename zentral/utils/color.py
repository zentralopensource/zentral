import colorsys


def text_color_for_background_color(color):
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
