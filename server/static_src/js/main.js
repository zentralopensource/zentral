// Import our custom CSS
import '../scss/styles.scss'

// Import all of Bootstrap's JS
// TODO: only the plugins we need!
import * as bootstrap from 'bootstrap'

// Enable bootstrap tooltip if the device doesn't have touch events.
if (!('ontouchstart' in window)) {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl, {
        trigger: 'hover'
    }))
}

// import Bar chart components of chart.js
// see https://www.chartjs.org/docs/latest/getting-started/integration.html#bundle-optimization
import { Chart, BarController, BarElement, LinearScale, CategoryScale, Title, Tooltip } from 'chart.js'
Chart.register(BarController, BarElement, LinearScale, CategoryScale, Title, Tooltip)
// TODO: find better solution!
window.Chart = Chart;


const popoverTriggerList = document.querySelectorAll('[data-toggle="popover"]')
const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl, {
    trigger: 'click'
}))


// charts

function get_data_and_make_chart(url, charts) {
    $.getJSON(url, function (data) {
        for (const [dataset, data_arr] of Object.entries(data.datasets)) {
            if (data.datasets.hasOwnProperty(dataset)) {
                var canvas = charts[data.app][dataset];
                var chart = new Chart(canvas, {
                    type: 'bar',
                    data: {
                        labels: data.labels,
                        datasets: [data_arr]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            x: { gridLines: { color: "darkgray", zeroLineColor: "darkgray" } },
                            y: { gridLines: { color: "darkgray", zeroLineColor: "darkgray" } }
                        },
                        plugins: {
                            title: {
                                display: true,
                                text: data_arr.label,
                            }
                        }
                    }
                });
            }
        }
    });
}

$(document).ready(function () {
    var charts = {};
    var urls = Array();
    $(".chart").each(function (index, canvas) {
        canvas = $(canvas);
        var app = canvas.data('app');
        var dataset = canvas.data('dataset');
        if (!charts.hasOwnProperty(app)) {
            charts[app] = {};
            urls.push('/app/' + app + '/hist_data/day/14/');
        }
        charts[app][dataset] = canvas;
    });
    for (var idx in urls) {
        if (urls.hasOwnProperty(idx)) {
            get_data_and_make_chart(urls[idx], charts);
        }
    }
});