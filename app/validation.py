from .models import FarmCVRequest


def validate_farm_payload(payload: FarmCVRequest) -> FarmCVRequest:
    # Pydantic performs structural validation; this service is deliberately side-effect free.
    return payload
