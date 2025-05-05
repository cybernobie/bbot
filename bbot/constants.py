SCAN_STATUSES = {
    "NOT_STARTED": 0,
    "STARTING": 1,
    "RUNNING": 2,
    "FINISHING": 3,
    "ABORTING": 5,
    "ABORTED": 6,
    "FAILED": 7,
    "FINISHED": 8,
}

SCAN_STATUS_CODES = {v: k for k, v in SCAN_STATUSES.items()}


def get_scan_status_code(status):
    """
    Convert a scan status string to a numeric status code
    """
    try:
        if isinstance(status, int):
            if not status in SCAN_STATUS_CODES:
                raise ValueError(f"Invalid scan status code: {status}")
            return status
        elif isinstance(status, str):
            return SCAN_STATUSES[status]
        else:
            raise ValueError(f"Invalid scan status: {status} (must be int or str)")
    except KeyError:
        raise ValueError(f"Invalid scan status: {status}")
