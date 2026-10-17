"""Panel release identity is independent of the loaded driver's IOCTL version."""
PANEL_VERSION = '3.2.3'
RELEASE_ID = 'SampleKernel1-2.6.0.2_KernelStudio-3.2.3_APCNormalize'
EXPECTED_DRIVER_VERSION = '2.6'
EXPECTED_DRIVER_BUILD = 20261017
DEFAULT_PORT = 8005

def release_info():
    return {'panel_version': PANEL_VERSION, 'release_id': RELEASE_ID,
            'expected_driver_version': EXPECTED_DRIVER_VERSION,
            'expected_driver_build': EXPECTED_DRIVER_BUILD, 'default_port': DEFAULT_PORT}
