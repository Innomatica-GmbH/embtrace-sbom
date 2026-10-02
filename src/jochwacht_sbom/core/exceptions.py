"""Exception hierarchy for Jochwacht.

All Jochwacht exceptions inherit from JochwachtError so callers can catch
broadly or narrowly as needed.

``JochwachtError`` is kept as an alias at the bottom of this module: it was
importable from a published package for seven releases, and an ``except
JochwachtError`` in somebody's script should not start passing exceptions
through because we renamed a product.
"""


class JochwachtError(Exception):
    """Base exception for all Jochwacht errors."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class ConfigError(JochwachtError):
    """Error loading or validating configuration."""


class ConfigFileNotFoundError(ConfigError):
    """Configuration file does not exist."""


class ConfigValidationError(ConfigError):
    """Configuration file failed Pydantic validation."""


class GitError(JochwachtError):
    """Error extracting git metadata."""


class GitNotARepositoryError(GitError):
    """Directory is not a git repository."""


class MetaError(JochwachtError):
    """Error reading or writing meta.yaml / bigMeta.yaml."""


class StorageError(JochwachtError):
    """Error accessing storage backend."""


class SBOMError(JochwachtError):
    """Base exception for SBOM operations (import, generation, scanning)."""


class SBOMGenerationError(SBOMError):
    """Error generating SBOM."""


class SecretScanError(SBOMError):
    """Error during secrets detection scan."""


class ArtifactNotFoundError(JochwachtError):
    """Requested artifact does not exist."""


class ArtifactVerificationError(JochwachtError):
    """Artifact integrity check failed."""


class UpdateError(JochwachtError):
    """Error creating or verifying update files."""


class MakeselfNotFoundError(UpdateError):
    """makeself.sh could not be located."""


class MakeselfExecutionError(UpdateError):
    """makeself.sh failed during .run generation."""


class SigningError(UpdateError):
    """Error during cryptographic signing."""


class SignatureVerificationError(UpdateError):
    """Signature verification failed."""


class EncryptionError(UpdateError):
    """Error during file encryption."""


class DecryptionError(UpdateError):
    """Error during file decryption."""


class DeltaError(UpdateError):
    """Error creating or applying a binary delta."""


class ArchiveError(JochwachtError):
    """Error creating or verifying a compliance archive bundle."""


class BuildError(JochwachtError):
    """Error in build system integration."""


class BuildConfigError(BuildError):
    """Invalid or missing build configuration."""


class PresetGenerationError(BuildError):
    """Error generating CMake presets."""


class ProfileGenerationError(BuildError):
    """Error generating Conan profiles."""


class HookGenerationError(BuildError):
    """Error generating post-build hook script."""


class ImageError(JochwachtError):
    """Error creating or flashing images."""


class ImageGenerationError(ImageError):
    """Error during SD-Card image generation."""


class LoopDeviceError(ImageError):
    """Error setting up or tearing down a loop device."""


class PartitionError(ImageError):
    """Error creating or formatting partitions."""


class BoardConfigError(ImageError):
    """Invalid or missing board configuration."""


class FlashError(ImageError):
    """Error flashing an image to a device."""


class BootBinError(ImageError):
    """Error generating a Xilinx BOOT.bin file."""


class ReleaseError(JochwachtError):
    """Error creating or verifying releases."""


class ChangelogError(ReleaseError):
    """Error generating changelog from git history."""


class ReportError(ReleaseError):
    """Error generating traceability report."""


class ComplianceError(JochwachtError):
    """Error in compliance audit or reporting."""


class AuditError(ComplianceError):
    """Error running CRA compliance audit."""


class PDFExportError(ComplianceError):
    """Error exporting a compliance audit report to PDF."""


class ENISAError(ComplianceError):
    """Error generating ENISA incident report."""


class BSIComplianceError(ComplianceError):
    """Error generating or validating a BSI TR-03183-2 compliant SBOM."""


class DocumentationError(ComplianceError):
    """Error generating technical documentation."""


class LicenseError(JochwachtError):
    """Error with license validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=1)


class LicenseExpiredError(LicenseError):
    """License or trial has expired."""


class AnalyzerError(JochwachtError):
    """Error in AI project analyzer."""


class ModelError(AnalyzerError):
    """Error loading or running the inference model."""


class ReconciliationError(AnalyzerError):
    """Error during dependency reconciliation."""


class CacheError(JochwachtError):
    """Error in the project-local SQLite cache."""


class CacheWriteError(CacheError):
    """Failed to write data to the SQLite cache."""


class CacheReadError(CacheError):
    """Failed to read data from the SQLite cache."""


class CheckError(JochwachtError):
    """Error in the jochwacht-sbom collector."""


class CheckCollectionError(CheckError):
    """Failed to collect dependency metadata from the project."""


class CheckUploadError(CheckError):
    """Failed to upload the check payload to the submit endpoint."""
