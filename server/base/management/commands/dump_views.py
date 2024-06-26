import pprint
from django.conf import settings
from django.core.management.base import BaseCommand
from django.urls import URLPattern, URLResolver
import xlsxwriter


class Command(BaseCommand):
    help = "Dump all the configured Django views."
    csv_headers = [
        ("pattern", "Pattern"),
        ("module", "Module"),
        ("name", "View"),
        ("accounts_view", "Accounts view?"),
        ("admin_view", "Admin view?"),
        ("api_view", "API view?"),
        ("metrics_view", "Metrics view?"),
        ("public_view", "Public view?"),
        ("parents", "Parent view(s)"),
    ]

    def add_arguments(self, parser):
        parser.add_argument("--xlsx")

    def handle(self, *args, **options):
        urlconf = __import__(settings.ROOT_URLCONF, {}, {}, [''])
        workbook = worksheet = None
        row_idx = col_idx = 0
        outfile = options.get("xlsx")
        if outfile:
            workbook = xlsxwriter.Workbook(outfile)
            worksheet = workbook.add_worksheet("Zentral Django views")
            for _, name in self.csv_headers:
                worksheet.write(row_idx, col_idx, name)
                col_idx += 1
        for view_info in self.iter_view_info(urlconf.urlpatterns):
            row_idx += 1
            col_idx = 0
            if worksheet:
                view_info["parents"] = "\n".join(f"{m}.{n}" for m, n in view_info.pop("parents"))
                for key, _ in self.csv_headers:
                    worksheet.write(row_idx, col_idx, view_info[key])
                    col_idx += 1
            else:
                self.stdout.write(pprint.pformat(view_info))
        if workbook:
            workbook.close()

    def iter_views(self, urlpatterns, base='', namespace=None):
        for p in urlpatterns:
            pattern_desc = base + str(p.pattern)
            if isinstance(p, URLPattern):
                name = p.name
                if namespace:
                    name = f'{namespace}:{name}'
                yield p.callback, pattern_desc, name
            elif isinstance(p, URLResolver):
                if namespace and p.namespace:
                    _namespace = f'{namespace}:{p.namespace}'
                else:
                    _namespace = p.namespace or namespace
                yield from self.iter_views(p.url_patterns, pattern_desc, namespace=_namespace)
            elif hasattr(p, '_get_callback'):
                yield p._get_callback(), pattern_desc, p.name
            elif hasattr(p, 'url_patterns') or hasattr(p, '_get_url_patterns'):
                yield from self.iter_views(p.url_patterns, pattern_desc, namespace=namespace)

    def prepare_view_info(self, func, pattern, url_name):
        api_view = pattern.startswith("api/")
        public_view = pattern.startswith("public/")
        metrics_view = pattern.startswith("metrics/")
        accounts_view = pattern.startswith("accounts/")
        admin_view = not any([api_view, public_view, metrics_view, accounts_view])
        view_class = getattr(func, "view_class", None)
        parents = []
        if view_class:
            parents = [(cls.__module__, cls.__name__) for cls in view_class.__mro__ if cls not in (view_class, object)]
        view_obj = view_class or func
        view_module = view_obj.__module__
        view_name = view_obj.__name__
        return {
            "api_view": api_view,
            "public_view": public_view,
            "metrics_view": metrics_view,
            "accounts_view": accounts_view,
            "admin_view": admin_view,
            "module": view_module,
            "name": view_name,
            "parents": parents,
            "pattern": pattern
        }

    def iter_view_info(self, urlpatterns):
        for func, pattern, url_name in self.iter_views(urlpatterns):
            yield self.prepare_view_info(func, pattern, url_name)
