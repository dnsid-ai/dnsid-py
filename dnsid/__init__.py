"""DNSid Python SDK.

Implements the DNSid Protocol for identity management and verification.

Protocol layer (spec-defined):
    IdentityManager            — primary entry point; all protocol operations flow through it
    IdentityManagerDependencies — optional dependency bundle for IdentityManager
    DnsidConfig                — core configuration: identity, verification, transport
    IdentityConfig             — local identity publication settings
    VerificationConfig         — verification policy and counterparty acceptance
    TrustedEntity              — one counterparty allowlist entry (gi + optional key pins)
    TransportConfig            — optional deployment/runtime DNS and TLS controls
    RegistryConfig             — optional registry control-plane configuration
    DnsIdTxtRecord             — _dnsid TXT record parsing, validation, serialization
    JWKS / JWK                 — key set wrapper and individual key type
    check_ek_ku_distinctness  — RFC 7638 thumbprint distinctness check (ek vs ku key sets)
    AgentStatus                — status endpoint response
    VerifiedDomain             — result of a successful verify_domain call
    DomainLog                  — verified event history for a domain
    DomainSnapshot             — materialized domain state at a point in time
    LogRegistry                — factory registry for log method implementations
    RegistryClient             — operator-side registry workflows

Application profiles (not part of the DNSid protocol):
    JoseProfile / JoseConfig   — JWT and JWS helpers (dnsid.jose)
    HttpSignatureProfile / HttpMessageSignatureConfig
                               — RFC 9421 HTTP Message Signatures (dnsid.http_signatures)
    OIDCProfile / OIDCConfig   — OIDC token minting and verification (dnsid.oidc)

Key management:
    LocalKeyProvider           — file-backed EdDSA/ES256 KeyProvider with key rotation lifecycle
    AwsKmsKeyProvider          — AWS KMS-backed KeyProvider (optional dep: boto3)
    AwsKmsConfig               — configuration for AwsKmsKeyProvider
    AwsKmsKeyState             — mutable lifecycle state for AwsKmsKeyProvider
    BotoKmsFacade              — boto3 adapter for AwsKmsKeyProvider
    AwsKmsFacade               — abstract facade for testing without AWS

CLI config helpers:
    identity_manager_from_cli_directory — one-call init from DNSid CLI identity files (~/.dnsid)
    config_from_cli_directory           — build config objects from DNSid CLI identity files
    CliConfigResult                     — return type of config_from_cli_directory

Environment helpers:
    identity_manager_from_environment — one-call init from DNSID_* variables and local keys
    config_from_environment    — build config objects from DNSID_* environment variables
    registry_client_from_environment — RegistryClient from DNSID_REGISTRY_URL / DNSID_API_KEY
    EnvironmentConfigResult    — return type of config_from_environment

Interfaces (implement to integrate your own backends):
    IdentityResolver  — minimal protocol satisfied by IdentityManager; accepted by profiles
    KeyProvider       — key management (local files, KMS, HSM)
    Log               — log write interface
    LogReader         — log read/verify interface
    IdentityCache     — verified domain cache
    DNSResolver       — DNS resolver

Errors:
    ParseError        — structurally malformed TXT record
    ValidationError   — semantic constraint violation
    VerificationError — live verification failure (carries VerificationCode)
    ArgumentError     — invalid caller-supplied argument

Enumerations:
    DNSSECState, DNSSECMode, VerificationCode, AgentState, RevocationReason,
    RegistryRevocationReason, EventType
"""

from ._verification_budget import remaining_seconds, verification_budget
from .agent_status import active_status_document
from .aws_kms_key_provider import (
    AwsKmsConfig as AwsKmsConfig,
)
from .aws_kms_key_provider import (
    AwsKmsFacade as AwsKmsFacade,
)
from .aws_kms_key_provider import (
    AwsKmsKeyProvider as AwsKmsKeyProvider,
)
from .aws_kms_key_provider import (
    AwsKmsKeyState as AwsKmsKeyState,
)
from .aws_kms_key_provider import (
    BotoKmsFacade as BotoKmsFacade,
)
from .cli_config import (
    CliConfigResult,
    config_from_cli_directory,
    identity_manager_from_cli_directory,
)
from .conformance import SDK_CONFORMANCE, SDKConformance
from .enums import (
    AgentState,
    DNSSECMode,
    DNSSECState,
    EventType,
    LifecycleErrorCategory,
    LogSignerRole,
    RegistryRevocationReason,
    RevocationReason,
    VerificationCode,
)
from .environment import (
    EnvironmentConfigResult,
    EnvironmentFieldName,
    config_from_environment,
    dnsid_environment_variables,
    identity_manager_from_environment,
    key_store_path_from_environment,
    registry_client_from_environment,
)
from .exceptions import (
    ArgumentError,
    DNSidError,
    LifecycleVerificationError,
    ManagedKeyRotationActivationError,
    ManagedKeyRotationSubmissionError,
    ParseError,
    RegistryRequestError,
    ValidationError,
    VerificationError,
)
from .http_signatures import HttpMessageSignatureConfig, HttpSignatureProfile
from .interfaces import (
    AbstractRegistryClient,
    DNSResolver,
    HTTPSFetcher,
    IdentityCache,
    IdentityResolver,
    KeyProvider,
    Log,
    LogReader,
    NoopLogReader,
)
from .jose import JoseConfig, JoseProfile
from .local_key_provider import LocalKeyProvider, LocalKeyProviderEnvironmentOptions
from .manager import (
    ApplicationSigningPauseHook,
    IdentityManager,
    IdentityManagerDependencies,
    KeyRotationPersistenceHook,
    sign_event_with_provider,
)
from .models import (
    DEFAULT_REGISTRY_URL,
    IDENTITY_RECORD_VERSION,
    JWK,
    JWKS,
    AgentRegistration,
    AgentRegistrationInput,
    AgentStatus,
    AnyLogEvent,
    CanonicalRecordContentResponse,
    DelegationEvent,
    DnsidConfig,
    DnsIdTxtRecord,
    DomainLog,
    DomainSnapshot,
    HttpRequest,
    HttpSigningOptions,
    HttpVerificationOptions,
    IdentityConfig,
    IssuanceEvent,
    JWTOptions,
    KeyRotationEvent,
    KeyRotationPreparationRequest,
    KeyRotationResult,
    LifecycleResult,
    LiveAgentRegistrationInput,
    LiveChallengeTranscript,
    LiveProofReissueRequest,
    LiveProofReissueResponse,
    LiveProofRequest,
    LiveProofResponse,
    LiveProvisioningResponse,
    LogEvent,
    LoggedStateEvidence,
    LogRef,
    MigrationEvent,
    PreparedRegistryEvent,
    PublicationConfig,
    PublishedRecord,
    RegistryAgentStatus,
    RegistryConfig,
    RetirementEvent,
    RevocationEvent,
    SignatureParams,
    SubmissionResult,
    TLSCertificate,
    TransportConfig,
    TrustedEntity,
    TXTRecord,
    VerificationConfig,
    VerifiedCutoffHistory,
    VerifiedDomain,
    check_ek_ku_distinctness,
    publish_allowed_version,
)
from .oidc import (
    NetworkError,
    OAuthError,
    OIDCAssertionOptions,
    OIDCConfig,
    OIDCDiscoveryDocument,
    OIDCProfile,
    OIDCTokenExchangeOptions,
    OIDCTokenResponse,
    VerifiedOIDCSubject,
    VerifyOIDCTokenOptions,
)
from .registry import LogRegistry
from .registry_client import RegistryClient, required, required_int
from .retry import async_retry_transient, retry_transient
from .wba_signer import (
    WBADirectoryResponse,
    WBAHttpSigner,
    WBAVariant,
    WebBotAuthConfig,
    WebBotAuthSigningOptions,
    serve_http_message_signatures_directory,
)
from .web_bot_auth import (
    BotAuthConfig,
    BotIdentity,
    VerifiedBotRequest,
    WebBotAuthProfile,
)

PROTOCOL_VERSION: str = IDENTITY_RECORD_VERSION
"""Wire version string for the DNSid protocol implemented by this SDK.

Alias of IDENTITY_RECORD_VERSION — the current numbered publish profile.
"""

__all__ = [
    # Core
    "IdentityManager",
    "IdentityManagerDependencies",
    # Config
    "DnsidConfig",
    "IdentityConfig",
    "VerificationConfig",
    "TrustedEntity",
    "TransportConfig",
    "RegistryConfig",
    # DNS record
    "DnsIdTxtRecord",
    "TXTRecord",
    # Keys
    "JWK",
    "JWKS",
    "check_ek_ku_distinctness",
    # Status / TLS
    "AgentStatus",
    "TLSCertificate",
    # Verification result
    "VerifiedDomain",
    # Log
    "DomainLog",
    "DomainSnapshot",
    "LoggedStateEvidence",
    "VerifiedCutoffHistory",
    "LogRef",
    "LogEvent",
    "AnyLogEvent",
    "IssuanceEvent",
    "KeyRotationEvent",
    "RevocationEvent",
    "RetirementEvent",
    "MigrationEvent",
    "DelegationEvent",
    "LifecycleErrorCategory",
    "LifecycleVerificationError",
    "ManagedKeyRotationActivationError",
    "ManagedKeyRotationSubmissionError",
    "LogSignerRole",
    "sign_event_with_provider",
    # Registry
    "LogRegistry",
    "RegistryClient",
    "required",
    "required_int",
    "AgentRegistrationInput",
    "AgentRegistration",
    "LifecycleResult",
    "LiveAgentRegistrationInput",
    "LiveChallengeTranscript",
    "LiveProvisioningResponse",
    "LiveProofRequest",
    "LiveProofResponse",
    "LiveProofReissueRequest",
    "LiveProofReissueResponse",
    "RegistryAgentStatus",
    "CanonicalRecordContentResponse",
    "PublishedRecord",
    "PreparedRegistryEvent",
    "KeyRotationPreparationRequest",
    "KeyRotationResult",
    "KeyRotationPersistenceHook",
    "ApplicationSigningPauseHook",
    "SubmissionResult",
    # Application-layer option types
    "JWTOptions",
    "HttpRequest",
    "HttpSigningOptions",
    "HttpVerificationOptions",
    "SignatureParams",
    # JOSE / HTTP signatures profiles
    "JoseProfile",
    "JoseConfig",
    "HttpSignatureProfile",
    "HttpMessageSignatureConfig",
    # OIDC profile
    "OIDCProfile",
    "OIDCConfig",
    "OIDCAssertionOptions",
    "OIDCTokenExchangeOptions",
    "OIDCTokenResponse",
    "OIDCDiscoveryDocument",
    "VerifyOIDCTokenOptions",
    "VerifiedOIDCSubject",
    # Key management
    "LocalKeyProvider",
    "LocalKeyProviderEnvironmentOptions",
    # CLI config helpers
    "config_from_cli_directory",
    "identity_manager_from_cli_directory",
    "CliConfigResult",
    # Environment helpers
    "config_from_environment",
    "identity_manager_from_environment",
    "EnvironmentConfigResult",
    "EnvironmentFieldName",
    "dnsid_environment_variables",
    "key_store_path_from_environment",
    "registry_client_from_environment",
    # Agent status helpers
    "active_status_document",
    # Interfaces
    "AbstractRegistryClient",
    "IdentityResolver",
    "KeyProvider",
    "Log",
    "LogReader",
    "NoopLogReader",
    "IdentityCache",
    "DNSResolver",
    "HTTPSFetcher",
    # Retry helpers
    "retry_transient",
    "async_retry_transient",
    # Conformance
    "SDKConformance",
    "SDK_CONFORMANCE",
    "verification_budget",
    "remaining_seconds",
    "PROTOCOL_VERSION",
    "PublicationConfig",
    "DEFAULT_REGISTRY_URL",
    "IDENTITY_RECORD_VERSION",
    "publish_allowed_version",
    # Web Bot Auth profile
    "WBAHttpSigner",
    "WBAVariant",
    "WBADirectoryResponse",
    "WebBotAuthConfig",
    "WebBotAuthSigningOptions",
    "serve_http_message_signatures_directory",
    "WebBotAuthProfile",
    "BotAuthConfig",
    "BotIdentity",
    "VerifiedBotRequest",
    # Errors
    "DNSidError",
    "ParseError",
    "ValidationError",
    "RegistryRequestError",
    "VerificationError",
    "ArgumentError",
    "NetworkError",
    "OAuthError",
    # Enumerations
    "DNSSECState",
    "DNSSECMode",
    "VerificationCode",
    "AgentState",
    "RevocationReason",
    "RegistryRevocationReason",
    "EventType",
]
