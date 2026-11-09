"""Native fixture instrumentation compatible with a bounded address space."""
try:
    import resource
except ImportError:
    resource = None


def native_sanitizers() -> str:
    # AddressSanitizer reserves a large virtual shadow even for tiny fixtures.
    # Keep the process limit; retain undefined-behavior and array-bound checks.
    if resource is not None:
        limit, _ = resource.getrlimit(resource.RLIMIT_AS)
        if limit != resource.RLIM_INFINITY:
            return '-fsanitize=undefined,bounds'
    return '-fsanitize=address,undefined'
