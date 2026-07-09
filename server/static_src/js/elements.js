// Self-hosted @stoplight/elements assets, bundled through webpack instead of the
// unpkg CDN (blocked by Zentral's CSP). web-components.min.js registers the
// <elements-api> custom element used in elements.html. elements.scss is imported
// after Elements' own stylesheet so its theme-token overrides win.
import '@stoplight/elements/styles.min.css'
import '../scss/elements.scss'
import '@stoplight/elements/web-components.min.js'
