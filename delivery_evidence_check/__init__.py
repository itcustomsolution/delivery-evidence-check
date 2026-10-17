"""Read-only integrity checks for explicitly listed local evidence files."""
from .core import EvidenceError, create_manifest, load_manifest, verify_manifest

__version__ = '0.2.0rc1'
__all__ = ['EvidenceError', 'create_manifest', 'load_manifest', 'verify_manifest']
