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


// tasks
//
// A link with the task class posts to its href to launch a celery task, then polls
// the task result until it is ready. The messages are built with the task label. A
// task result with a file sends the browser to the download URL, without one the
// page is reloaded to display what the task changed. An export link carries the
// format in data-format, and its enclosing form is posted with it.

var TASK_POLLING_DELAY = 1000;
var TASK_RELOAD_DELAY = 1000;

function addMessage(message, tag) {
    var alert = document.createElement("div");
    alert.className = "alert alert-" + (tag === "error" ? "danger" : tag) + " alert-dismissible fade show";
    alert.setAttribute("role", "alert");
    alert.textContent = message;
    var closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.className = "btn-close";
    closeButton.setAttribute("data-bs-dismiss", "alert");
    closeButton.setAttribute("aria-label", "Close");
    alert.appendChild(closeButton);
    document.getElementById("messages").appendChild(alert);
    return alert;
}

function taskDone($link, startedMessage, message, tag) {
    if (startedMessage) {
        startedMessage.remove();
    }
    $link.removeClass("disabled");
    addMessage(message, tag);
}

function waitForTask(url, $link, startedMessage) {
    var label = $link.data("task-label");
    $.ajax({
        dataType: "json",
        url: url,
        success: function (data) {
            if (data.unready) {
                window.setTimeout(waitForTask, TASK_POLLING_DELAY, url, $link, startedMessage);
            } else if (data.status !== "SUCCESS") {
                taskDone($link, startedMessage, label + " failed.", "error");
            } else if ((data.result || {}).status === "SKIPPED") {
                taskDone($link, startedMessage, label + " skipped, already running.", "warning");
            } else if (data.download_url) {
                taskDone($link, startedMessage, label + " done.", "success");
                window.location = data.download_url;
            } else {
                if (startedMessage) {
                    startedMessage.remove();
                }
                addMessage(label + " done.", "success");
                // the link stays disabled, the message is displayed for a moment before the reload
                window.setTimeout(function () { window.location.reload(); }, TASK_RELOAD_DELAY);
            }
        },
        error: function () {
            taskDone($link, startedMessage, label + " status unknown.", "error");
        }
    });
}

function launchTask($link) {
    var label = $link.data("task-label");
    var options = {
        dataType: "json",
        url: $link.attr("href"),
        method: "post",
        success: function (data) {
            var startedMessage = addMessage(label + " started.", "info");
            window.setTimeout(waitForTask, 300, data.task_result_url, $link, startedMessage);
        },
        error: function () {
            taskDone($link, null, label + " could not be launched.", "error");
        }
    };
    var exportFormat = $link.data("format");
    if (exportFormat) {
        var postData = {"export_format": exportFormat};
        $.each($link.parents("form").serializeArray(), function (index, field) {
            if (field.value) {
                postData[field.name] = field.value;
            }
        });
        options.contentType = "application/json";
        options.data = JSON.stringify(postData);
    }
    $link.addClass("disabled");
    $.ajax(options);
}

$(document).ready(function () {
    // the pages that still wait for their tasks themselves bind the task class too,
    // the label is what tells them apart. To be dropped once they all use this code.
    $(".task[data-task-label]").click(function (event) {
        event.preventDefault();
        launchTask($(this));
    });
});