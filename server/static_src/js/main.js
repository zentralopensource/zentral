// Import our custom CSS
import '../scss/styles.scss'

// Import all of Bootstrap's JS
// TODO: only the plugins we need!
import * as bootstrap from 'bootstrap'

// Enable bootstrap tooltip

const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))
