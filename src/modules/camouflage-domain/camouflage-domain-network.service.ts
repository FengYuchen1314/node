import {
    ClientHttp2Session,
    ClientHttp2Stream,
    connect as connectHttp2,
    constants as http2Constants,
} from 'node:http2';
import { isIP } from 'node:net';
import { ConnectionOptions, TLSSocket, connect as connectTls, checkServerIdentity } from 'node:tls';

import { HttpStatus, Injectable } from '@nestjs/common';

import { CamouflageDomainError } from './camouflage-domain.error';

const CONNECT_TIMEOUT_MS = 5_000;
const HTTP_RESPONSE_BODY_LIMIT = 64 * 1024;
const HTTP_HEADER_PAIRS_LIMIT = 64;

export interface CamouflageDomainTlsObservation {
    certificate: {
        notAfter: string;
        notBefore: string;
        sanMatches: boolean;
        sans: string[];
    };
    cipherSuite: string;
    keyExchangeGroup: string;
    version: string;
}

export interface CamouflageDomainHttpObservation {
    locationHeader: string | null;
    negotiatedProtocol: string;
    redirectCount: number;
    serverHeader: string | null;
    statusCode: number;
}

export interface CamouflageDomainNetworkObservation {
    http: CamouflageDomainHttpObservation;
    tls: CamouflageDomainTlsObservation;
}

interface ObservedHttp2Headers {
    ':status'?: number;
    location?: string | string[];
    server?: string | string[];
}

export type TlsConnectFunction = (
    options: ConnectionOptions & { family: 4 | 6; host: string; port: number },
    secureConnectListener?: () => void,
) => TLSSocket;

@Injectable()
export class CamouflageDomainNetworkService {
    public async probe(
        domain: string,
        address: string,
        signal: AbortSignal,
    ): Promise<CamouflageDomainNetworkObservation> {
        const socket = await openBoundTlsSocket(domain, address, signal);
        try {
            const tls = readTlsObservation(socket, domain);
            const http = await requestHttp2Head(socket, domain, signal);
            return { tls, http };
        } finally {
            socket.destroy();
        }
    }
}

export function openBoundTlsSocket(
    domain: string,
    address: string,
    signal: AbortSignal,
    connect: TlsConnectFunction = connectTls,
): Promise<TLSSocket> {
    return new Promise<TLSSocket>((resolve, reject) => {
        let socket: TLSSocket;
        let settled = false;
        const cleanup = () => {
            signal.removeEventListener('abort', abort);
            socket?.removeListener('error', fail);
            socket?.removeListener('timeout', timedOut);
            socket?.setTimeout(0);
        };
        const rejectOnce = (error: CamouflageDomainError) => {
            if (settled) return;
            settled = true;
            cleanup();
            socket?.destroy();
            reject(error);
        };
        const abort = () =>
            rejectOnce(
                new CamouflageDomainError(
                    'VALIDATION_TIMEOUT',
                    'Camouflage-domain validation timed out.',
                    HttpStatus.GATEWAY_TIMEOUT,
                ),
            );
        const timedOut = () =>
            rejectOnce(
                new CamouflageDomainError(
                    'TLS_NEGOTIATION_FAILED',
                    'The TLS connection timed out.',
                    HttpStatus.BAD_GATEWAY,
                ),
            );
        const fail = (error: Error) => rejectOnce(classifyTlsError(error));

        if (signal.aborted) {
            abort();
            return;
        }
        try {
            socket = connect(
                {
                    host: address,
                    port: 443,
                    family: isIP(address) as 4 | 6,
                    servername: domain,
                    ALPNProtocols: ['h2'],
                    minVersion: 'TLSv1.3',
                    maxVersion: 'TLSv1.3',
                    ecdhCurve: 'X25519',
                    rejectUnauthorized: true,
                    checkServerIdentity,
                },
                () => {
                    if (settled) return;
                    settled = true;
                    cleanup();
                    resolve(socket);
                },
            );
        } catch (error: unknown) {
            rejectOnce(classifyTlsError(error));
            return;
        }
        socket.once('error', fail);
        socket.once('timeout', timedOut);
        socket.setTimeout(CONNECT_TIMEOUT_MS);
        signal.addEventListener('abort', abort, { once: true });
    });
}

export function readTlsObservation(
    socket: TLSSocket,
    domain: string,
): CamouflageDomainTlsObservation {
    if (!socket.authorized) {
        throw new CamouflageDomainError(
            'TLS_TRUST_FAILED',
            'The certificate chain is not trusted by the Node system store.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    const version = socket.getProtocol();
    if (version !== 'TLSv1.3') {
        throw new CamouflageDomainError(
            'TLS_1_3_REQUIRED',
            'The endpoint did not negotiate TLS 1.3.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    if (socket.alpnProtocol !== 'h2') {
        throw new CamouflageDomainError(
            'HTTP_2_REQUIRED',
            'The endpoint did not negotiate HTTP/2 via ALPN.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    const keyExchangeGroup = getEphemeralKeyName(socket);
    if (keyExchangeGroup?.toUpperCase() !== 'X25519') {
        throw new CamouflageDomainError(
            'X25519_UNVERIFIED',
            'The Node runtime could not verify an X25519 negotiated group.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    const cipher = socket.getCipher();
    const certificate = socket.getPeerX509Certificate();
    if (!certificate) {
        throw new CamouflageDomainError(
            'CERTIFICATE_INVALID',
            'The endpoint did not provide a verifiable certificate.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    const sans = parseDnsSans(certificate.subjectAltName);
    const sanMatches = Boolean(
        certificate.checkHost(domain, {
            subject: 'never',
            wildcards: true,
            partialWildcards: false,
            multiLabelWildcards: false,
            singleLabelSubdomains: false,
        }),
    );
    if (!sanMatches || sans.length === 0) {
        throw new CamouflageDomainError(
            'CERTIFICATE_SAN_MISMATCH',
            'The certificate SAN does not match the requested domain.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    const notBefore = parseCertificateDate(certificate.validFrom);
    const notAfter = parseCertificateDate(certificate.validTo);
    return {
        version,
        cipherSuite: cipher.standardName ?? cipher.name,
        keyExchangeGroup,
        certificate: { sans, sanMatches, notBefore, notAfter },
    };
}

export async function requestHttp2Head(
    socket: TLSSocket,
    domain: string,
    signal: AbortSignal,
): Promise<CamouflageDomainHttpObservation> {
    const session = connectHttp2(`https://${domain}`, {
        createConnection: () => socket,
        maxHeaderListPairs: HTTP_HEADER_PAIRS_LIMIT,
        maxSessionMemory: 1,
        settings: { enablePush: false },
    });
    session.on('stream', (stream) => stream.close(http2Constants.NGHTTP2_CANCEL));
    try {
        const headers = await makeHeadRequest(session, domain, signal);
        return buildHttpObservation(socket.alpnProtocol === 'h2' ? 'h2' : '', headers);
    } finally {
        session.destroy();
    }
}

export function buildHttpObservation(
    negotiatedProtocol: string,
    headers: ObservedHttp2Headers,
): CamouflageDomainHttpObservation {
    const rawStatus = headers[':status'];
    if (typeof rawStatus !== 'number' || rawStatus < 100 || rawStatus > 599) {
        throw new CamouflageDomainError(
            'HTTP_REQUEST_FAILED',
            'The HTTP/2 response did not contain a valid status.',
            HttpStatus.BAD_GATEWAY,
        );
    }
    const serverHeader = normalizeHeader(headers.server, 512);
    const locationHeader = normalizeHeader(headers.location, 2_048);
    return {
        negotiatedProtocol,
        statusCode: rawStatus,
        redirectCount: (rawStatus >= 300 && rawStatus <= 399) || locationHeader !== null ? 1 : 0,
        serverHeader,
        locationHeader,
    };
}

function makeHeadRequest(
    session: ClientHttp2Session,
    domain: string,
    signal: AbortSignal,
): Promise<ObservedHttp2Headers> {
    return new Promise((resolve, reject) => {
        let stream: ClientHttp2Stream;
        let responseHeaders: ObservedHttp2Headers | undefined;
        let responseBytes = 0;
        let settled = false;
        const cleanup = () => {
            signal.removeEventListener('abort', abort);
            session.removeListener('error', fail);
            stream?.removeListener('error', fail);
        };
        const rejectOnce = (error: CamouflageDomainError) => {
            if (settled) return;
            settled = true;
            cleanup();
            stream?.close(http2Constants.NGHTTP2_CANCEL);
            reject(error);
        };
        const fail = () =>
            rejectOnce(
                new CamouflageDomainError(
                    'HTTP_REQUEST_FAILED',
                    'The HTTP/2 request failed.',
                    HttpStatus.BAD_GATEWAY,
                ),
            );
        const abort = () =>
            rejectOnce(
                new CamouflageDomainError(
                    'VALIDATION_TIMEOUT',
                    'Camouflage-domain validation timed out.',
                    HttpStatus.GATEWAY_TIMEOUT,
                ),
            );

        if (signal.aborted) {
            abort();
            return;
        }
        stream = session.request({
            ':method': 'HEAD',
            ':scheme': 'https',
            ':authority': domain,
            ':path': '/',
            accept: '*/*',
            'user-agent': 'Remnawave-Node-Camouflage-Validator/1',
        });
        stream.once('response', (headers) => {
            responseHeaders = {
                ':status': headers[':status'],
                location: headers.location,
                server: headers.server,
            };
        });
        stream.on('data', (chunk: Buffer) => {
            responseBytes += chunk.byteLength;
            if (responseBytes > HTTP_RESPONSE_BODY_LIMIT) {
                rejectOnce(
                    new CamouflageDomainError(
                        'HTTP_REQUEST_FAILED',
                        'The HTTP/2 response body exceeded the validation limit.',
                        HttpStatus.BAD_GATEWAY,
                    ),
                );
            }
        });
        stream.once('end', () => {
            if (settled) return;
            if (!responseHeaders) {
                fail();
                return;
            }
            settled = true;
            cleanup();
            resolve(responseHeaders);
        });
        stream.once('error', fail);
        session.once('error', fail);
        signal.addEventListener('abort', abort, { once: true });
        stream.end();
    });
}

function parseDnsSans(subjectAltName: string | undefined): string[] {
    if (!subjectAltName) return [];
    const values = subjectAltName
        .split(/,\s*/)
        .filter((entry) => entry.startsWith('DNS:'))
        .map((entry) => entry.slice(4).toLowerCase())
        .filter((entry) => entry.length >= 1 && entry.length <= 253);
    return [...new Set(values)].slice(0, 256);
}

function getEphemeralKeyName(socket: TLSSocket): string | null {
    const info = socket.getEphemeralKeyInfo();
    if (!info || !('name' in info) || typeof info.name !== 'string') return null;
    return info.name;
}

function parseCertificateDate(value: string): string {
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp)) {
        throw new CamouflageDomainError(
            'CERTIFICATE_INVALID',
            'The certificate validity period is invalid.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    return new Date(timestamp).toISOString();
}

function normalizeHeader(value: string | string[] | undefined, maxLength: number): string | null {
    if (value === undefined) return null;
    const normalized = (Array.isArray(value) ? value.join(', ') : value).trim();
    if (normalized.length === 0) return null;
    if (normalized.length > maxLength) {
        throw new CamouflageDomainError(
            'HTTP_REQUEST_FAILED',
            'The HTTP/2 response header exceeded the validation limit.',
            HttpStatus.BAD_GATEWAY,
        );
    }
    return normalized;
}

function classifyTlsError(error: unknown): CamouflageDomainError {
    if (error instanceof CamouflageDomainError) return error;
    const code = getErrorCode(error);
    if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
        return new CamouflageDomainError(
            'CERTIFICATE_SAN_MISMATCH',
            'The certificate SAN does not match the requested domain.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    if (code?.includes('CERT') || code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
        return new CamouflageDomainError(
            'TLS_TRUST_FAILED',
            'The certificate chain is not trusted by the Node system store.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    if (
        code === 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' ||
        code === 'ERR_SSL_WRONG_VERSION_NUMBER'
    ) {
        return new CamouflageDomainError(
            'TLS_1_3_REQUIRED',
            'The endpoint could not negotiate TLS 1.3.',
            HttpStatus.UNPROCESSABLE_ENTITY,
        );
    }
    return new CamouflageDomainError(
        'TLS_NEGOTIATION_FAILED',
        'The TLS handshake failed.',
        HttpStatus.BAD_GATEWAY,
    );
}

function getErrorCode(error: unknown): string | undefined {
    if (!error || typeof error !== 'object' || !('code' in error)) return undefined;
    const code = (error as NodeJS.ErrnoException).code;
    return typeof code === 'string' ? code : undefined;
}
