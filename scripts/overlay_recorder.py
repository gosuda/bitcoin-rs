"""Bounded loopback recorder for SOCKS5 and SAM 3.3. One concern only."""
import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import sys
from collections.abc import Awaitable, Callable, Coroutine
from typing import Literal, TypedDict


class SocksRecord(TypedDict, total=False):
    direction: str
    auth_method: int
    auth_sanitized: bool
    atyp: int
    domain_length: int
    target_domain: str
    target_port: int
    reply_code: int
    ip_literal: bool
    error: str


class SamRecord(TypedDict, total=False):
    hello: str
    negotiated_version: str
    session_create: str
    naming_lookup: str
    stream_connect: str
    stream_accept: str
    error: str


type SamCommand = Literal["hello", "session_create", "naming_lookup", "stream_connect", "stream_accept"]
type SamPhase = Literal["root", "stream"]
type Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[None, None, None]]

# One handshake step (connect, a command, a reply, a drain) waits at most IO_TIMEOUT. The reply to
# SESSION CREATE is the one exception: the node's whole root budget. HANDSHAKE_TIMEOUT bounds a
# whole negotiation. Established root and relayed streams stay open across any idle period; only
# their writes and the final close are bounded.
IO_TIMEOUT = 30.0
SESSION_CREATE_TIMEOUT = 135.0
HANDSHAKE_TIMEOUT = SESSION_CREATE_TIMEOUT
CLOSE_TIMEOUT = 5.0
MAX_CONNECTIONS = 128
MAX_LINE = 65536
CHUNK = 16384
MAX_OBSERVED = 512

SAM_COMMANDS: dict[tuple[str, str], SamCommand] = {
    ("HELLO", "VERSION"): "hello",
    ("SESSION", "CREATE"): "session_create",
    ("NAMING", "LOOKUP"): "naming_lookup",
    ("STREAM", "CONNECT"): "stream_connect",
    ("STREAM", "ACCEPT"): "stream_accept",
}
SECRET_KEYS = ("DESTINATION", "PASSWORD")
SAM_VERSION = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}")
SOCKS_ADDRESS_SIZE = {1: 4, 4: 16}
# Failures that are connection evidence. Their messages never carry peer data.
EXPECTED = (OSError, RuntimeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError)
# Fresh-root readiness ordinal: incremented once per validated SESSION CREATE OK
# (SESSION STATUS RESULT=OK, exact token match) and flushed as one stable log
# line. Each recorder process holds its own counter starting at 0, so the A-side
# log proves a fresh post-restart Node A root while the B-side log stays
# independent. The line carries no DESTINATION, PASSWORD, VALUE, or key.
_SESSION_CREATE_OK_ORDINAL = 0


def describe(err: BaseException) -> str:
    name = type(err).__name__
    return f"{name}: {err}" if isinstance(err, EXPECTED) and str(err) else name


def leaves(err: BaseException) -> list[BaseException]:
    if isinstance(err, BaseExceptionGroup):
        return [leaf for inner in err.exceptions for leaf in leaves(inner)]
    return [err]


def note_sam_error(sam: SamRecord, message: str) -> None:
    sam.setdefault("error", message)


def sam_tokens(text: str) -> list[str]:
    """Split a SAM line on whitespace outside double quotes (a backslash escapes inside quotes)."""
    tokens: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    for char in text.strip():
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char in " \t" and not quoted:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def redact_sam_tokens(tokens: list[str]) -> str:
    kept: list[str] = []
    for token in tokens:
        head = token.split("=", 1)[0]
        kept.append(f"{head}=[REDACTED]" if head.upper() in SECRET_KEYS else token)
    return " ".join(kept)


def observe_command(sam: SamRecord, command: bytes) -> SamCommand | None:
    """Record the redacted line of a command the launcher requires; return its kind."""
    tokens = sam_tokens(command.decode("utf-8", "replace"))
    kind = SAM_COMMANDS.get((tokens[0].upper(), tokens[1].upper())) if len(tokens) > 1 else None
    if kind is not None:
        sam[kind] = redact_sam_tokens(tokens)[:MAX_OBSERVED]
    return kind


def reply_fields(reply: bytes, verb: str) -> dict[str, str]:
    """Fields of a strict `<VERB> <SUBVERB> KEY=VALUE ...` reply; anything else fails unechoed."""
    try:
        tokens = sam_tokens(reply.decode("utf-8"))
    except UnicodeDecodeError:
        raise RuntimeError(f"malformed sam {verb} reply") from None
    if tokens[:2] != verb.split():
        raise RuntimeError(f"malformed sam {verb} reply")
    fields: dict[str, str] = {}
    for token in tokens[2:]:
        key, separator, value = token.partition("=")
        if not separator or not key or key in fields:
            raise RuntimeError(f"malformed sam {verb} reply")
        fields[key] = value.strip('"')
    return fields


def record_negotiated_version(sam: SamRecord, reply: bytes) -> None:
    fields = reply_fields(reply, "HELLO REPLY")
    version = fields.get("VERSION", "")
    if fields.get("RESULT") == "OK" and SAM_VERSION.fullmatch(version):
        sam["negotiated_version"] = version


async def bounded[T](awaitable: Awaitable[T], timeout: float, what: str) -> T:
    try:
        async with asyncio.timeout(timeout):
            return await awaitable
    except TimeoutError as err:
        raise RuntimeError(f"{what} timeout after {timeout}s") from err


async def read_exact(reader: asyncio.StreamReader, count: int, what: str) -> bytes:
    return await bounded(reader.readexactly(count), IO_TIMEOUT, what)


async def read_line(reader: asyncio.StreamReader, timeout: float | None, what: str) -> bytes | None:
    """One newline-terminated line; None for a clean EOF between lines. No deadline when idle."""
    line = reader.readuntil(b"\n")
    try:
        return await (line if timeout is None else bounded(line, timeout, what))
    except asyncio.IncompleteReadError as err:
        if err.partial:
            raise
        return None


async def send(writer: asyncio.StreamWriter, data: bytes, what: str) -> None:
    writer.write(data)
    await bounded(writer.drain(), IO_TIMEOUT, what)


async def close_all(*writers: asyncio.StreamWriter | None) -> str | None:
    """Close every socket and wait for its transport, bounded. Returns the first non-reset failure."""
    live = [writer for writer in writers if writer is not None]
    for writer in live:
        writer.close()
    try:
        async with asyncio.timeout(CLOSE_TIMEOUT):
            results = await asyncio.gather(*(writer.wait_closed() for writer in live), return_exceptions=True)
    except TimeoutError:
        for writer in live:
            writer.transport.abort()
        return f"close timeout after {CLOSE_TIMEOUT}s"
    for result in results:
        if isinstance(result, Exception) and not isinstance(result, ConnectionError):
            return describe(result)
    return None


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy bytes one way until EOF. Idle reads are unbounded; every write is bounded."""
    while chunk := await reader.read(CHUNK):
        await send(writer, chunk, "relay write")


async def first_to_end(*coros: Coroutine[None, None, None]) -> None:
    """Run until the first coroutine ends, then cancel the rest. A failure aborts the group."""
    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(coro) for coro in coros]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            task.cancel()


async def read_socks_message(reader: asyncio.StreamReader, what: str) -> bytes:
    """One whole SOCKS5 request or reply: VER, CMD/REP, RSV, ATYP, address, port."""
    head = await read_exact(reader, 4, what)
    if head[0] != 5:
        raise RuntimeError(f"{what} is not socks5")
    if head[3] == 3:
        length = await read_exact(reader, 1, what)
        return head + length + await read_exact(reader, length[0] + 2, what)
    size = SOCKS_ADDRESS_SIZE.get(head[3])
    if size is None:
        raise RuntimeError(f"{what} has unknown address type {head[3]}")
    return head + await read_exact(reader, size + 2, what)


def socks_target(request: bytes) -> SocksRecord:
    atyp = request[3]
    record: SocksRecord = {
        "atyp": atyp,
        "target_port": int.from_bytes(request[-2:], "big"),
        "ip_literal": atyp != 3,
        "domain_length": 0,
        "target_domain": "",
    }
    if atyp == 3:
        record["domain_length"] = request[4]
        record["target_domain"] = request[5 : 5 + request[4]].decode("utf-8", "replace")
    return record


async def forward_socks_auth(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    """RFC 1929 sub-negotiation, forwarded without keeping the credentials."""
    head = await read_exact(client_reader, 2, "socks auth")
    user = await read_exact(client_reader, head[1], "socks auth")
    password_length = await read_exact(client_reader, 1, "socks auth")
    password = await read_exact(client_reader, password_length[0], "socks auth")
    await send(upstream_writer, head + user + password_length + password, "socks auth write")
    status = await read_exact(reader, 2, "socks auth status")
    await send(client_writer, status, "socks auth status write")
    if status[1] != 0:
        raise RuntimeError("socks proxy refused the credentials")


async def socks_handshake(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> SocksRecord | None:
    """Forward greeting, auth, request and full reply; None for a close before any byte."""
    try:
        greeting = await read_exact(client_reader, 2, "socks greeting")
    except asyncio.IncompleteReadError as err:
        if err.partial:
            raise
        return None
    if greeting[0] != 5:
        raise RuntimeError("client did not send a socks5 greeting")
    methods = await read_exact(client_reader, greeting[1], "socks methods")
    await send(upstream_writer, greeting + methods, "socks greeting write")
    choice = await read_exact(reader, 2, "socks method choice")
    await send(client_writer, choice, "socks method choice write")
    if choice[1] == 2:
        await forward_socks_auth(client_reader, client_writer, reader, upstream_writer)
    elif choice[1] != 0:
        raise RuntimeError(f"unsupported socks auth method {choice[1]}")
    request = await read_socks_message(client_reader, "socks request")
    await send(upstream_writer, request, "socks request write")
    reply = await read_socks_message(reader, "socks reply")
    await send(client_writer, reply, "socks reply write")
    record = socks_target(request)
    record["direction"] = "outbound"
    record["auth_method"] = choice[1]
    record["auth_sanitized"] = True
    record["reply_code"] = reply[1]
    return record


async def handle_socks(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    records: list[SocksRecord],
) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    try:
        reader, upstream_writer = await bounded(
            asyncio.open_connection(target_host, target_port), IO_TIMEOUT, "socks proxy connect"
        )
        record = await bounded(
            socks_handshake(client_reader, client_writer, reader, upstream_writer),
            HANDSHAKE_TIMEOUT,
            "socks handshake",
        )
        if record is not None:
            records.append(record)
            if record.get("reply_code") == 0:
                await first_to_end(pump(client_reader, upstream_writer), pump(reader, client_writer))
    except* EXPECTED as group:
        records.extend({"error": describe(err)} for err in leaves(group))
    finally:
        failure = await close_all(client_writer, upstream_writer)
        if failure is not None:
            records.append({"error": f"close: {failure}"})


async def negotiate_sam(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    sam: SamRecord,
) -> SamPhase | None:
    """Lock-step commands and replies until a root or a stream is up; None when the exchange ends."""
    global _SESSION_CREATE_OK_ORDINAL
    while True:
        command = await read_line(client_reader, IO_TIMEOUT, "sam command")
        if command is None:
            return None
        kind = observe_command(sam, command)
        await send(upstream_writer, command, "sam command write")
        reply = await read_line(
            reader, SESSION_CREATE_TIMEOUT if kind == "session_create" else IO_TIMEOUT, "sam reply"
        )
        if reply is None:
            raise RuntimeError("sam bridge closed before replying")
        await send(client_writer, reply, "sam reply write")
        if kind == "hello":
            record_negotiated_version(sam, reply)
        elif kind == "session_create" and reply_fields(reply, "SESSION STATUS").get("RESULT") == "OK":
            _SESSION_CREATE_OK_ORDINAL += 1
            print(f"sam_session_create_ok ordinal={_SESSION_CREATE_OK_ORDINAL}", file=sys.stderr, flush=True)
            return "root"
        elif kind in ("stream_connect", "stream_accept"):
            ok = reply_fields(reply, "STREAM STATUS").get("RESULT") == "OK"
            return "stream" if ok else None


async def observe_commands(
    client_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter, sam: SamRecord
) -> None:
    """Session root: record and forward each later command; the wait for the next has no deadline."""
    while (command := await read_line(client_reader, None, "sam command")) is not None:
        observe_command(sam, command)
        await send(upstream_writer, command, "sam command write")


async def handle_sam(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    sam: SamRecord,
) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    try:
        reader, upstream_writer = await bounded(
            asyncio.open_connection(target_host, target_port, limit=MAX_LINE), IO_TIMEOUT, "sam bridge connect"
        )
        phase = await bounded(
            negotiate_sam(client_reader, client_writer, reader, upstream_writer, sam),
            HANDSHAKE_TIMEOUT,
            "sam handshake",
        )
        if phase == "stream":
            await first_to_end(pump(client_reader, upstream_writer), pump(reader, client_writer))
        elif phase == "root":
            await first_to_end(observe_commands(client_reader, upstream_writer, sam), pump(reader, client_writer))
    except* EXPECTED as group:
        for err in leaves(group):
            note_sam_error(sam, describe(err))
    finally:
        failure = await close_all(client_writer, upstream_writer)
        if failure is not None:
            note_sam_error(sam, f"close: {failure}")


def acceptor(
    group: asyncio.TaskGroup,
    handlers: set[asyncio.Task[None]],
    stop: asyncio.Event,
    handle: Handler,
    refuse: Callable[[str], None],
) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]:
    """Own each accepted connection as a task of `group`; shed it above MAX_CONNECTIONS."""

    def accepted(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if stop.is_set():
            writer.transport.abort()
        elif len(handlers) >= MAX_CONNECTIONS:
            refuse(f"connection cap {MAX_CONNECTIONS} exceeded")
            writer.transport.abort()
        else:
            coro = handle(reader, writer)
            try:
                task = group.create_task(coro)
            except RuntimeError:
                # The group is aborting or finished: the failure that closed it is already propagating.
                coro.close()
                writer.transport.abort()
            else:
                handlers.add(task)
                task.add_done_callback(handlers.discard)

    return accepted


async def amain(args: argparse.Namespace) -> int:
    socks_records: list[SocksRecord] = []
    sam_record: SamRecord = {}
    handlers: set[asyncio.Task[None]] = set()
    servers: list[asyncio.Server] = []
    stop = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    async with asyncio.TaskGroup() as group:
        try:
            servers.append(
                await asyncio.start_server(
                    acceptor(
                        group,
                        handlers,
                        stop,
                        lambda r, w: handle_socks(
                            r, w, str(args.socks_target_host), int(args.socks_target_port), socks_records
                        ),
                        lambda message: socks_records.append({"error": message}),
                    ),
                    "127.0.0.1",
                    int(args.socks_listen),
                    limit=MAX_LINE,
                )
            )
            servers.append(
                await asyncio.start_server(
                    acceptor(
                        group,
                        handlers,
                        stop,
                        lambda r, w: handle_sam(
                            r, w, str(args.sam_target_host), int(args.sam_target_port), sam_record
                        ),
                        lambda message: note_sam_error(sam_record, message),
                    ),
                    "127.0.0.1",
                    int(args.sam_listen),
                    limit=MAX_LINE,
                )
            )
            await stop.wait()
        finally:
            for server in servers:
                server.close()
            for task in handlers:
                task.cancel()
    for server in servers:
        await bounded(server.wait_closed(), CLOSE_TIMEOUT, "listener close")
    if not all(task.done() for task in handlers):
        raise RuntimeError("handlers still running at finalization")
    write_snapshot(str(args.output), str(args.done), socks_records, sam_record)
    return 0


def write_snapshot(output: str, done: str, socks_records: list[SocksRecord], sam_record: SamRecord) -> None:
    snapshot = {"socks": socks_records, "sam": sam_record}
    raw = json.dumps(snapshot, indent=2).encode("utf-8")
    tmp_output = f"{output}.tmp"
    with open(tmp_output, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_output, output)
    marker = {
        "schema": "bitcoin-rs-overlay-observations-v1",
        "complete": True,
        "observations_bytes": len(raw),
        "observations_sha256": hashlib.sha256(raw).hexdigest(),
    }
    marker_raw = json.dumps(marker, indent=2).encode("utf-8")
    tmp_done = f"{done}.tmp"
    with open(tmp_done, "wb") as handle:
        handle.write(marker_raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_done, done)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socks-listen", type=int, required=True)
    parser.add_argument("--socks-target-host", default="127.0.0.1")
    parser.add_argument("--socks-target-port", type=int, required=True)
    parser.add_argument("--sam-listen", type=int, required=True)
    parser.add_argument("--sam-target-host", default="127.0.0.1")
    parser.add_argument("--sam-target-port", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--done", required=True)
    args = parser.parse_args()
    try:
        return asyncio.run(amain(args))
    except BaseExceptionGroup as group:
        for leaf in leaves(group):
            sys.stderr.write(f"recorder failed: {describe(leaf)}\n")
        return 1
    except (OSError, RuntimeError) as err:
        sys.stderr.write(f"recorder failed: {describe(err)}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
