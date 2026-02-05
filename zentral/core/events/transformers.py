import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union

from celpy import CELEvalError, Environment, celtypes, json_to_cel
from typing_extensions import override

logger = logging.getLogger("zentral.core.events.transformers")


class EventTransformer(ABC):

    @abstractmethod
    def transform(self, serialized_event: dict) -> Any:  # pragma: no cover
        ...


class EventTransformerError(Exception):
    pass


class CELEventTranformer(EventTransformer):
    def __init__(self, source):
        try:
            env = Environment()
            ast = env.compile(source)
            self.program = env.program(ast)
        except Exception:
            msg = "Could not load CEL source"
            logger.exception(msg)
            raise ValueError(msg)

    @override
    def transform(self, serialized_event: dict) -> Any:
        try:
            metadata = serialized_event.pop('_zentral')
        except Exception:
            msg = "No zentral event given"
            logger.exception(msg)
            raise EventTransformerError(msg)

        payload = serialized_event
        context = json_to_cel({
            "metadata": metadata,
            "payload": payload
        })
        try:
            return self.to_python(
                self.program.evaluate(context=context)
            )
        except EventTransformerError:
            raise
        except Exception:
            # should never happen
            msg = "Unknown evaluation error"
            logger.exception(msg)
            raise EventTransformerError(msg)

    @staticmethod
    def to_python(
        cel_object: celtypes.Value,
    ) -> Union[celtypes.Value, List[Any], Dict[Any, Any], bool]:
        """
        see:
        https://github.com/cloud-custodian/cel-python/blob/d304c0a3f0d38875dcc73ec265e2de01838ee61f/src/celpy/adapter.py#L79-L87
        """
        if isinstance(cel_object, celtypes.BoolType):
            return True if cel_object else False
        elif isinstance(cel_object, celtypes.ListType):
            return [CELEventTranformer.to_python(item) for item in cel_object]
        elif isinstance(cel_object, celtypes.MapType):
            return {
                CELEventTranformer.to_python(key): CELEventTranformer.to_python(value)
                for key, value in cel_object.items()
            }
        elif isinstance(cel_object, celtypes.DurationType):
            raise EventTransformerError("DurationType is not supported")
        elif isinstance(cel_object, celtypes.BytesType):
            raise EventTransformerError("BytesType is not supported")
        elif isinstance(cel_object, celtypes.TypeType):
            raise EventTransformerError("TypeType is not supported")
        elif isinstance(cel_object, CELEvalError):
            raise EventTransformerError("CEL evaluation error")
        else:
            # following Types are passed:
            # TimestampType (datetime.datetime)
            # DoubleType
            # IntType
            # NullType
            # StringType
            # UintType
            return cel_object
