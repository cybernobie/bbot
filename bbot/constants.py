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


def is_valid_scan_status(status):
    """
    Check if a status is a valid scan status
    """
    return status in SCAN_STATUSES


def is_valid_scan_status_code(status):
    """
    Check if a status is a valid scan status code
    """
    return status in SCAN_STATUS_CODES


def get_scan_status_name(status):
    """
    Convert a numeric scan status code to a string status name
    """
    try:
        if isinstance(status, str):
            if not is_valid_scan_status(status):
                raise ValueError(f"Invalid scan status: {status}")
            return SCAN_STATUS_CODES[status]
        elif isinstance(status, int):
            return SCAN_STATUSES[status]
        else:
            raise ValueError(f"Invalid scan status: {status} (must be int or str)")
    except KeyError:
        raise ValueError(f"Invalid scan status: {status}")


def get_scan_status_code(status):
    """
    Convert a scan status string to a numeric status code
    """
    try:
        if isinstance(status, int):
            if not is_valid_scan_status_code(status):
                raise ValueError(f"Invalid scan status code: {status}")
            return status
        elif isinstance(status, str):
            return SCAN_STATUSES[status]
        else:
            raise ValueError(f"Invalid scan status: {status} (must be int or str)")
    except KeyError:
        raise ValueError(f"Invalid scan status: {status}")
