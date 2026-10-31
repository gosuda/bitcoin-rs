# Python startup hook for the core-functional lane. Activated by run.sh via
# PYTHONPATH=<this directory>; sitecustomize is imported automatically by the
# interpreter before any test code runs.
#
# Patches are applied from outside; no Bitcoin Core code is copied or
# modified. Every patch is an explicitly recorded deviation of bitcoin-rs
# from Core behavior and is listed in tools/core-functional/README.md:
#
# 1. test_framework.wallet.MiniWallet.generate mines via the implemented
#    `generatetoaddress` RPC instead of the unimplemented
#    `generatetodescriptor`. v31.1's generate() is:
#        blocks = self._test_node.generatetodescriptor(num_blocks, self.get_descriptor(), **kwargs)
#        self.rescan_utxos()
#        return blocks
#    The replacement keeps the post-conditions (rescan_utxos after generate,
#    same return shape, **kwargs forwarding) and only diverges in
#    ADDRESS_OP_TRUE mode, whose fixed bech32m P2TR address get_address()
#    already exposes. Other modes fall through to the upstream implementation
#    and fail loudly on the missing RPC - honest failure beats a silent wrong
#    mine.
#
# 2. test_framework.authproxy.AuthServiceProxy.get_request: the framework's
#    client serializes zero-argument calls as "params": {} (an empty JSON
#    object; get_request's `params = args or argsn` falls back to an empty
#    dict). Core's JSON-RPC layer treats an empty params object as "no named
#    parameters" and accepts it. bitcoin-rs rejects it with
#    {"code": -32602, "message": "invalid params: params must be an array"},
#    which kills every test at the very first framework probe
#    (wait_for_rpc_connection's getblockcount). The patch rewrites exactly the
#    empty-object case to [] on the CLIENT side so the rest of each test can
#    be measured; the node-side deviation itself is recorded as a node gap in
#    the README and must be fixed in the node, after which this patch becomes
#    a no-op that should be deleted. Set BITCOIN_RS_NO_PARAMS_SHIM=1 to
#    disable it and reproduce the raw failure. The same patch also rewrites
#    generatetoaddress's named-object params (nblocks=/address=/maxtries=,
#    how the framework's mining plumbing always calls it) into the
#    positional array [nblocks, address, maxtries] - bitcoin-rs's handler
#    parses positionally only and rejects the object form with -32602, while
#    Core accepts both. The rewrite is deliberately limited to this one
#    method because its parameter order is identical on both sides, so no
#    argument can be silently reordered; every other method fails honestly
#    on named-object params.
#
# 3. test_framework.authproxy.AuthServiceProxy.__call__: two RPCs that the
#    framework's own plumbing calls unconditionally - syncwithvalidation-
#    interfacequeue (sync_mempools after pools match, so via sync_all in the
#    default setup_network of every test) and setmocktime (_initialize_chain's
#    cache build pins the cache node's clock to its tip time) - are missing
#    from bitcoin-rs's RPC surface and would gate every candidate at setup,
#    before any test body runs. bitcoin-rs returns
#    {"code": -32601, "message": "method not found: ..."} for both. The patch
#    no-ops exactly these two methods CLIENT-side (Core's replies are null and
#    the framework ignores them). Verified against v31.1: no candidate test
#    file calls setmocktime itself, and set_node_times/bump_mocktime (the
#    other setmocktime callers) are used by no candidate, so no observable
#    test behavior is being faked. Both remain node gaps for the next phase;
#    once the node implements them, delete this patch. Set
#    BITCOIN_RS_NO_RPC_PLUMBING_SHIM=1 to disable it and reproduce the raw
#    method-not-found failures.
#
# 4. test_framework.authproxy.AuthServiceProxy.__call__: Core's stop takes a
#    hidden numeric wait argument; bitcoin-rs's stop takes none and refuses
#    any with the local parameter-shape error (a documented deviation in
#    crates/rpc/src/registry.rs). The framework's stop_node() teardown sends
#    stop(wait=0) unconditionally, so exactly that default form (wait 0 or
#    absent) is stripped client-side - it is semantically identical to a bare
#    stop. Non-zero waits (feature_shutdown.py, wait=1000) are forwarded
#    untouched and fail honestly. Set BITCOIN_RS_NO_STOP_WAIT_SHIM=1 to
#    disable it.

import importlib.abc
import importlib.util
import os
import sys
import warnings


def _patch_wallet(wallet):
    if getattr(wallet, "__bitcoin_rs_patched__", False):
        return
    original_generate = wallet.MiniWallet.generate
    address_op_true = wallet.MiniWalletMode.ADDRESS_OP_TRUE

    def generate_with_generatetoaddress(self, num_blocks, **kwargs):
        if getattr(self, "_mode", None) is not address_op_true:
            return original_generate(self, num_blocks, **kwargs)
        blocks = self._test_node.generatetoaddress(
            num_blocks, self.get_address(), **kwargs)
        self.rescan_utxos()
        return blocks

    wallet.MiniWallet.generate = generate_with_generatetoaddress
    wallet.__bitcoin_rs_patched__ = True


# Framework-plumbing RPCs bitcoin-rs does not implement. See header note 3.
NOOP_RPC_METHODS = frozenset({"syncwithvalidationinterfacequeue", "setmocktime"})


def _normalize_empty_params(proxy_cls):
    original_get_request = proxy_cls.get_request

    def get_request_with_empty_params_normalized(self, *args, **argsn):
        request = original_get_request(self, *args, **argsn)
        params = request.get("params")
        if isinstance(params, dict) and not params:
            request["params"] = []
            return request
        # generatetoaddress only: the framework's own mining plumbing calls it
        # with named args (test_framework._initialize_chain passes nblocks=
        # and address=; TestNode.generate passes nblocks=/address=/maxtries=),
        # which serializes as a params OBJECT. bitcoin-rs's handler parses
        # params positionally only and answers -32602. Core accepts the named
        # form. Translation is deliberately limited to this one method, whose
        # Core-documented parameter order (nblocks, address, maxtries) is
        # identical to the node handler's positional reads, so no silent
        # reordering of arguments is possible. Other methods keep failing
        # honestly on named-object params.
        if (self._service_name == "generatetoaddress"
                and isinstance(params, dict) and "args" not in params):
            positional = [params.get(name) for name in ("nblocks", "address", "maxtries")
                          if name in params]
            request["params"] = positional
        return request

    proxy_cls.get_request = get_request_with_empty_params_normalized


def _strip_default_stop_wait(proxy_cls):
    # Core's stop takes a hidden numeric "wait" (milliseconds); bitcoin-rs's
    # stop takes no arguments and refuses any (documented deviation in
    # crates/rpc/src/registry.rs). The framework's stop_node() always sends
    # stop(wait=0), which is semantically identical to a bare stop, so that
    # exact form is stripped client-side. A non-zero wait (only
    # feature_shutdown.py, wait=1000) is forwarded untouched and fails
    # honestly against the deviation.
    original_call = proxy_cls.__call__

    def call_with_default_stop_wait_stripped(self, *args, **argsn):
        if self._service_name == "stop":
            values = args if args else (argsn.get("wait", 0),)
            if len(values) == 1 and values[0] in (0, None):
                return original_call(self)
        return original_call(self, *args, **argsn)

    proxy_cls.__call__ = call_with_default_stop_wait_stripped


def _noop_plumbing_methods(proxy_cls):
    original_call = proxy_cls.__call__

    def call_with_plumbing_noops(self, *args, **argsn):
        if self._service_name in NOOP_RPC_METHODS:
            return None
        return original_call(self, *args, **argsn)

    proxy_cls.__call__ = call_with_plumbing_noops


def _patch_authproxy(authproxy):
    proxy_cls = authproxy.AuthServiceProxy
    if getattr(authproxy, "__bitcoin_rs_params_patched__", False):
        return
    if not os.environ.get("BITCOIN_RS_NO_PARAMS_SHIM"):
        _normalize_empty_params(proxy_cls)
    if not os.environ.get("BITCOIN_RS_NO_RPC_PLUMBING_SHIM"):
        _noop_plumbing_methods(proxy_cls)
    if not os.environ.get("BITCOIN_RS_NO_STOP_WAIT_SHIM"):
        _strip_default_stop_wait(proxy_cls)
    authproxy.__bitcoin_rs_params_patched__ = True


PATCHES = {
    "test_framework.wallet": _patch_wallet,
    "test_framework.authproxy": _patch_authproxy,
}


class _LoaderProxy(importlib.abc.Loader):
    """Wrap the real loader; apply the lane's patch once the module executes."""

    def __init__(self, loader, module_name):
        self._loader = loader
        self._module_name = module_name

    def create_module(self, spec):
        return self._loader.create_module(spec)

    def exec_module(self, module):
        self._loader.exec_module(module)
        module = sys.modules.get(self._module_name)
        if module is not None:
            PATCHES[self._module_name](module)


class _Finder(importlib.abc.MetaPathFinder):
    """Intercept the patched imports; everything else falls through untouched."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in PATCHES:
            return None
        sys.meta_path.remove(self)
        try:
            spec = importlib.util.find_spec(fullname)
        finally:
            sys.meta_path.insert(0, self)
        if spec is None or spec.loader is None:
            return None
        spec.loader = _LoaderProxy(spec.loader, fullname)
        return spec


_still_needed = [name for name in PATCHES if name not in sys.modules]
if _still_needed:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # abc deprecation noise on some 3.x
        sys.meta_path.insert(0, _Finder())
