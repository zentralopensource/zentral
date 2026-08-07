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

const TASK_POLLING_DELAY = 1000
const TASK_RELOAD_DELAY = 1000

function csrfToken() {
    const cookie = document.cookie.split("; ").find(c => c.startsWith("csrftoken="))
    return cookie ? decodeURIComponent(cookie.slice("csrftoken=".length)) : ""
}

function getJSON(url, options) {
    return fetch(url, options).then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`)
        }
        return response.json()
    })
}

function addMessage(message, tag) {
    const alert = document.createElement("div")
    alert.className = `alert alert-${tag === "error" ? "danger" : tag} alert-dismissible fade show`
    alert.setAttribute("role", "alert")
    alert.textContent = message
    const closeButton = document.createElement("button")
    closeButton.type = "button"
    closeButton.className = "btn-close"
    closeButton.setAttribute("data-bs-dismiss", "alert")
    closeButton.setAttribute("aria-label", "Close")
    alert.appendChild(closeButton)
    document.getElementById("messages").appendChild(alert)
    return alert
}

function taskDone(link, startedMessage, message, tag) {
    if (startedMessage) {
        startedMessage.remove()
    }
    link.classList.remove("disabled")
    addMessage(message, tag)
}

function waitForTask(url, link, startedMessage) {
    const label = link.dataset.taskLabel
    getJSON(url).then(data => {
        if (data.unready) {
            window.setTimeout(waitForTask, TASK_POLLING_DELAY, url, link, startedMessage)
        } else if (data.status !== "SUCCESS") {
            taskDone(link, startedMessage, `${label} failed.`, "error")
        } else if ((data.result || {}).status === "SKIPPED") {
            taskDone(link, startedMessage, `${label} skipped, already running.`, "warning")
        } else if (data.download_url) {
            taskDone(link, startedMessage, `${label} done.`, "success")
            window.location = data.download_url
        } else {
            if (startedMessage) {
                startedMessage.remove()
            }
            addMessage(`${label} done.`, "success")
            // the link stays disabled, the message is displayed for a moment before the reload
            window.setTimeout(() => window.location.reload(), TASK_RELOAD_DELAY)
        }
    }).catch(() => taskDone(link, startedMessage, `${label} status unknown.`, "error"))
}

function launchTask(link) {
    const label = link.dataset.taskLabel
    const options = {method: "POST", headers: {"X-CSRFToken": csrfToken()}}
    const exportFormat = link.dataset.format
    if (exportFormat) {
        const postData = {"export_format": exportFormat}
        const form = link.closest("form")
        if (form) {
            new FormData(form).forEach((value, name) => {
                if (value) {
                    postData[name] = value
                }
            })
        }
        options.headers["Content-Type"] = "application/json"
        options.body = JSON.stringify(postData)
    }
    link.classList.add("disabled")
    getJSON(link.href, options).then(data => {
        const startedMessage = addMessage(`${label} started.`, "info")
        window.setTimeout(waitForTask, 300, data.task_result_url, link, startedMessage)
    }).catch(() => taskDone(link, null, `${label} could not be launched.`, "error"))
}

document.addEventListener("click", event => {
    const link = event.target.closest(".task")
    if (link) {
        event.preventDefault()
        launchTask(link)
    }
})
