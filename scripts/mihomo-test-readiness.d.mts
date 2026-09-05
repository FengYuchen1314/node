export function createMihomoTestReadiness(): Promise<{
    targetPort: number;
    rule: string;
    wait(socksPort: number, isAlive: () => boolean, timeoutMs?: number): Promise<void>;
    close(): Promise<void>;
}>;
