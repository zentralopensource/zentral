// Import our custom CSS
import '../scss/styles.scss'

// Import all of Bootstrap's JS
// TODO: only the plugins we need!
import * as bootstrap from 'bootstrap'

// Enable bootstrap tooltip if the device doesn't have touch events.
if(!('ontouchstart' in window)) {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl, {
        trigger : 'hover'
    }))
}

// import Bar chart components of chart.js
// see https://www.chartjs.org/docs/latest/getting-started/integration.html#bundle-optimization
import { Chart, BarController, BarElement, LinearScale, CategoryScale } from 'chart.js'
Chart.register(BarController, BarElement, LinearScale, CategoryScale)
// TODO: find better solution!
window.Chart = Chart;


const popoverTriggerList = document.querySelectorAll('[data-toggle="popover"]')
const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl, {
    trigger : 'click'
}))
