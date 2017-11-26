from collections import namedtuple


RelatedObjects = namedtuple('RelatedObjects',
                            ["name", "concrete", "to_name", "to_model", "objects"])


def find_all_related_objects(obj):
    for field in obj._meta.get_fields():
        if not field.is_relation:
            continue
        t = [field.name, field.concrete]
        # concrete or not
        if field.concrete:
            t.extend([None, field.related_model])
        else:
            t.extend([field.field.name, field.field.model])
        # get the related objects
        if field.many_to_one:
            related_obj = getattr(obj, field.name)
            if related_obj is not None:
                t.append([related_obj])
            else:
                continue
        elif field.one_to_one:
            try:
                t.append([getattr(obj, field.name)])
            except field.field.model.DoesNotExist:
                continue
        else:
            # many to many or one to many
            if field.concrete:
                qs = getattr(obj, field.name)
            else:
                qs = getattr(obj, field.get_accessor_name())
            if not qs.count():
                continue
            else:
                t.append(qs.all())
        yield RelatedObjects._make(t)
