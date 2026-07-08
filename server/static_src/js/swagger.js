// Self-hosted Swagger UI assets, bundled through webpack instead of pulled from a
// CDN (blocked by Zentral's CSP) or the drf-spectacular-sidecar Python package.
// drf-spectacular's own init script (included inline in swagger_ui.html) drives
// the UI and expects SwaggerUIBundle as a global, so we expose it here.
import 'swagger-ui-dist/swagger-ui.css'
import '../scss/swagger.scss'
import SwaggerUIBundle from 'swagger-ui-dist/swagger-ui-bundle'

window.SwaggerUIBundle = SwaggerUIBundle
