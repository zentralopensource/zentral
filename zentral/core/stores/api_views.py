from rest_framework.exceptions import ValidationError
from zentral.core.queues import queues
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from .models import Store
from .serializers import StoreSerializer
from .sync import signal_store_change


class StoreDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Store.objects.all()
    serializer_class = StoreSerializer

    def on_commit_callback_extra(self, instance):
        signal_store_change(instance)

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This store cannot be deleted")
        super().perform_destroy(instance)
        # perform the queue updates within the transaction
        # TODO revisit
        store = instance.get_backend(load=False)
        queues.mark_store_worker_queue_for_deletion(store)

    def perform_update(self, serializer):
        if not serializer.instance.can_be_updated():
            raise ValidationError("This store cannot be updated")
        super().perform_update(serializer)
        # perform the queue updates within the transaction
        # TODO revisit
        store = serializer.instance.get_backend(load=True)
        queues.setup_store_worker_queue(store)


class StoreList(ListCreateAPIViewWithAudit):
    queryset = Store.objects.all()
    serializer_class = StoreSerializer
    filterset_fields = ('name',)

    def on_commit_callback_extra(self, instance):
        signal_store_change(instance)

    def perform_create(self, serializer):
        super().perform_create(serializer)
        # perform the queue updates within the transaction
        # TODO revisit
        store = serializer.instance.get_backend(load=True)
        queues.setup_store_worker_queue(store)
