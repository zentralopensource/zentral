from django.db import models


class RepositoryBackend(models.TextChoices):
    AZURE = "AZURE", "Azure Blob Storage"
    S3 = "S3", "Amazon S3"
    VIRTUAL = "VIRTUAL", "Virtual"


def get_repository_backend(repository, load=False):
    backend = RepositoryBackend(repository.backend)
    if backend == RepositoryBackend.AZURE:
        from .azure import AzureRepository
        return AzureRepository(repository, load)
    elif backend == RepositoryBackend.S3:
        from .s3 import S3Repository
        return S3Repository(repository, load)
    elif backend == RepositoryBackend.VIRTUAL:
        from .virtual import VirtualRepository
        return VirtualRepository(repository, load)
    else:
        raise ValueError(f"Unknown repository backend: {backend}")


def load_repository_backend(repository):
    return get_repository_backend(repository, load=True)
