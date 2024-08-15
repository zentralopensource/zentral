from django_filters import rest_framework as filters
from rest_framework.generics import ListAPIView, RetrieveAPIView
from zentral.utils.drf import DefaultDjangoModelPermissions
from .models import Realm
from .serializers import RealmSerializer


class RealmList(ListAPIView):
    queryset = Realm.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = RealmSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class RealmDetail(RetrieveAPIView):
    queryset = Realm.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = RealmSerializer
