import { domainToASCII } from 'node:url';
import { z } from 'zod';

export const CAMOUFLAGE_DOMAIN_REGIONS = {
    LOS_ANGELES: 'LOS_ANGELES',
    SAN_JOSE: 'SAN_JOSE',
    TOKYO: 'TOKYO',
    SINGAPORE: 'SINGAPORE',
    FRANKFURT: 'FRANKFURT',
    LONDON: 'LONDON',
    AMSTERDAM: 'AMSTERDAM',
} as const;

export const CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS = {
    ASN: 'ASN',
    IP_RANGE: 'IP_RANGE',
    CNAME: 'CNAME',
    HTTP_HEADER: 'HTTP_HEADER',
} as const;

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export const CamouflageDomainSchema = z
    .string()
    .transform((value) => domainToASCII(value.trim().toLowerCase().replace(/\.$/, '')))
    .pipe(
        z
            .string()
            .min(4)
            .max(253)
            .refine(
                (value) =>
                    value.includes('.') &&
                    value.split('.').every((label) => HOST_LABEL.test(label)) &&
                    !/^\d+(?:\.\d+){3}$/.test(value),
                'A fully qualified domain name is required',
            ),
    );

const AsnSchema = z.string().regex(/^AS[1-9]\d*$/);
const DateTimeSchema = z.iso.datetime();

export const CamouflageDomainAgentValidationRequestSchema = z
    .object({
        domain: CamouflageDomainSchema,
        expectedRegion: z.enum(CAMOUFLAGE_DOMAIN_REGIONS),
        requirements: z
            .object({
                tlsVersion: z.literal('TLSv1.3'),
                httpProtocol: z.literal('h2'),
                keyExchangeGroup: z.literal('X25519'),
                minimumCertificateValidityDays: z.literal(14),
                maximumRedirects: z.literal(0),
                minimumDistinctMainlandProbeAsns: z.literal(2),
                maximumMainlandEvidenceAgeHours: z.literal(24),
                rejectCloudflare: z.literal(true),
                requireCertificateSanMatch: z.literal(true),
            })
            .strict(),
    })
    .strict();

export const CamouflageDomainAgentValidationReportSchema = z
    .object({
        domain: CamouflageDomainSchema,
        expectedRegion: z.enum(CAMOUFLAGE_DOMAIN_REGIONS),
        checkedAt: DateTimeSchema,
        dns: z
            .object({
                addresses: z.array(z.union([z.ipv4(), z.ipv6()])).max(32),
                cnameChain: z.array(CamouflageDomainSchema).max(16),
                fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
                containsBogon: z.boolean(),
            })
            .strict(),
        edge: z
            .object({
                provider: z.string().min(1).max(128).nullable(),
                asn: AsnSchema.nullable(),
                observedRegion: z.enum(CAMOUFLAGE_DOMAIN_REGIONS).nullable(),
            })
            .strict(),
        cloudflare: z
            .object({
                detected: z.boolean(),
                signals: z
                    .array(z.enum(CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS))
                    .max(Object.keys(CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS).length),
            })
            .strict(),
        tls: z
            .object({
                version: z.string().min(1).max(32),
                cipherSuite: z.string().min(1).max(128),
                keyExchangeGroup: z.string().min(1).max(64),
                certificate: z
                    .object({
                        sans: z.array(z.string().min(1).max(253)).min(1).max(256),
                        sanMatches: z.boolean(),
                        notBefore: DateTimeSchema,
                        notAfter: DateTimeSchema,
                    })
                    .strict(),
            })
            .strict(),
        http: z
            .object({
                negotiatedProtocol: z.string().min(1).max(32),
                statusCode: z.int().min(100).max(599),
                redirectCount: z.int().min(0).max(20),
                serverHeader: z.string().max(512).nullable(),
                locationHeader: z.string().max(2_048).nullable(),
            })
            .strict(),
        mainlandProbes: z
            .array(
                z
                    .object({
                        probeId: z.string().min(1).max(128),
                        countryCode: z.literal('CN'),
                        asn: AsnSchema,
                        reachable: z.boolean(),
                        checkedAt: DateTimeSchema,
                    })
                    .strict(),
            )
            .max(32),
    })
    .strict();

export const CamouflageDomainAgentValidationResponseSchema = z
    .object({ response: CamouflageDomainAgentValidationReportSchema })
    .strict();

export type TCamouflageDomainAgentValidationRequest = z.infer<
    typeof CamouflageDomainAgentValidationRequestSchema
>;
export type TCamouflageDomainAgentValidationReport = z.infer<
    typeof CamouflageDomainAgentValidationReportSchema
>;
