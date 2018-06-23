COLORS = [
    '#3366CC', '#DC3912', '#FF9900', '#109618', '#990099', '#3B3EAC', '#0099C6',
    '#DD4477', '#66AA00', '#B82E2E', '#316395', '#994499', '#22AA99', '#AAAA11',
    '#6633CC', '#E67300', '#8B0707', '#329262', '#5574A6', '#3B3EAC'
 ]


COLOR_NUM = len(COLORS)


def make_background_color_cycle(values):
    return [COLORS[i % COLOR_NUM] for i in range(len(values))]


def make_background_color_mono(values):
    return [COLORS[0] for i in range(len(values))]


def make_dataset(values, cycle_colors=True, label=None):
    dataset = {
        "data": values
    }
    if label:
        dataset["label"] = label
    if cycle_colors:
        dataset["backgroundColor"] = make_background_color_cycle(values)
    else:
        dataset["backgroundColor"] = make_background_color_mono(values)
    return dataset
