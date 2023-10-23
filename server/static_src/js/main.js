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
