export type CamouflageDomainErrorCode =
    | 'BUSY'
    | 'CERTIFICATE_INVALID'
    | 'CERTIFICATE_SAN_MISMATCH'
    | 'DNS_BOGON'
    | 'DNS_LIMIT_EXCEEDED'
    | 'DNS_RESOLUTION_FAILED'
    | 'HTTP_2_REQUIRED'
    | 'HTTP_REQUEST_FAILED'
    | 'TLS_1_3_REQUIRED'
    | 'TLS_NEGOTIATION_FAILED'
    | 'TLS_TRUST_FAILED'
    | 'VALIDATION_TIMEOUT'
    | 'X25519_UNVERIFIED';

export class CamouflageDomainError extends Error {
    constructor(
        public readonly code: CamouflageDomainErrorCode,
        message: string,
        public readonly httpStatus: number,
    ) {
        super(message);
        this.name = 'CamouflageDomainError';
    }
}
