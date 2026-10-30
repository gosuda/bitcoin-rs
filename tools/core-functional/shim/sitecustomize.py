# Python startup hook for the core-functional lane. Activated by run.sh via
# PYTHONPATH=<this directory>; sitecustomize is imported automatically by the
# interpreter before any test code runs.
#
# Patch (from outside; no Bitcoin Core code is copied or modified):
# test_framework.wallet.MiniWallet.generate mines via the implemented
# `generatetoaddress` RPC instead of the unimplemented `generatetodescriptor`.
# v31.1's generate() is:
#     blocks = self._test_node.generatetodescriptor(num_blocks, self.get_descriptor(), **kwargs)
#     self.rescan_utxos()
#     return blocks
# The replacement keeps the post-conditions (rescan_utxos after generate, same
# return shape, **kwargs forwarding) and only diverges in ADDRESS_OP_TRUE mode,
# whose fixed bech32m P2TR address (address.create_deterministic_address_
# bcrt1_p2tr_op_true) get_address() already exposes. Other modes fall through
# to the upstream implementation and fail loudly on the missing RPC - honest
# failure beats a silent wrong mine.

import importlib.abc
import importlib.util
import sys
import warnings

_TARGET_MODULE = "test_framework.wallet"


class _LoaderProxy(importlib.abc.Loader):
    """Wrap the real loader; patch MiniWallet once its module is executed."""

    def __init__(self, loader):
        self._loader = loader

    def create_module(self, spec):
        return self._loader.create_module(spec)

    def exec_module(self, module):
        self._loader.exec_module(module)
        wallet = sys.modules.get(_TARGET_MODULE)
        if wallet is None or getattr(wallet, "__bitcoin_rs_patched__", False):
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


class _Finder(importlib.abc.MetaPathFinder):
    """Intercept the one import; everything else falls through untouched."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname != _TARGET_MODULE:
            return None
        sys.meta_path.remove(self)
        try:
            spec = importlib.util.find_spec(fullname)
        finally:
            sys.meta_path.insert(0, self)
        if spec is None or spec.loader is None:
            return None
        spec.loader = _LoaderProxy(spec.loader)
        return spec


if _TARGET_MODULE not in sys.modules:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # abc deprecation noise on some 3.x
        sys.meta_path.insert(0, _Finder())
