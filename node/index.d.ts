/**
 * Synchronously call sluice. Sends fds 0/1/2 of this Node process via
 * SCM_RIGHTS; the broker dups them onto the spawned child, so stdio is
 * end-to-end kernel passthrough.
 *
 * @param socketPath  Path to the sluice unix socket (e.g. "/run/sluice.sock").
 * @param argv        Command + arguments. argv[0] is the executable.
 * @returns Reply status:
 *   - 0..=255 → spawned child's exit code
 *   - <0      → sluice rejection (see proto.rs ERR_* constants)
 * @throws  When the broker is unreachable or the protocol fails.
 */
export function call(socketPath: string, argv: string[]): number;
