"""Validation of captured interrupt-controller parameters."""
def legacy_irq_route_metadata_valid(route: dict[str, object]) -> bool:
    """Validate the detector-closed interrupt controller grammar."""
    status = route.get("status")
    enable = route.get("enable")
    if not isinstance(status, int) or not isinstance(enable, int):
        return False
    controller_class = route.get("controller_class")
    if controller_class == "legacy-c80-two-bank-group10-v1":
        banks = (status, status + 4)
        clear_banks = banks
        writes = (enable, enable + 4)
        count, row_size, aperture = 2, 10, (status, enable + 6)
    elif controller_class == "legacy-c80-three-bank-group14-v1":
        banks = (status, status + 4, status + 0x30)
        clear_banks = (status, status + 4, enable + 0x38)
        writes = (enable, enable + 4, enable + 0x30)
        count, row_size, aperture = 3, 14, (status, enable + 0x3A)
    elif (controller_class == "legacy-msm5000-620-two-bank-read-consume-v1"):
        banks = (status, status + 4)
        count, row_size, aperture = 2, 12, (status, enable + 8)
        return (enable == status + 8 and route.get("status_banks") == banks and route.get("mask_set_banks") == banks and route.get("mask_output_banks") == (enable,
            enable + 4) and route.get("controller_aperture") == aperture and route.get("status_bank_count") == count and route.get("group_row_size") == row_size
            and route.get("pending_read_semantics") == "consume-on-read")
    else:
        return False
    return (route.get("status_banks") == banks and route.get("clear_banks") == clear_banks and route.get("controller_write_banks") == writes and route.get("controller_aperture")
        == aperture and route.get("status_bank_count") == count and route.get("group_row_size") == row_size)
